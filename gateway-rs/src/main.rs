use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, atomic::Ordering},
    thread,
    time::Duration,
};

use doorman_gateway::{
    AppState, Config, build_router,
    demo_seed::{SeedOptions, run_seed},
    hot_reload::HotReloadConfig,
    observability::analytics_aggregator::global_analytics,
    routes::platform::backfill_grpc_descriptors,
    state::{GatewayRuntime, MemoryAutosaveConfig},
    storage::{runtime::SharedStorage, security_settings, snapshot},
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    doorman_gateway::observability::init();

    match env::args().nth(1).as_deref() {
        Some("start") => return start_process(),
        Some("stop") => return stop_process(),
        Some("restart") => {
            stop_process()?;
            thread::sleep(Duration::from_secs(1));
            return start_process();
        }
        Some("seed") => return seed_command(env::args().skip(2)).await,
        Some("run") | None => {}
        Some(command) => return Err(format!("unknown command: {command}").into()),
    }

    restore_metrics();

    let config = Config::from_env()?;
    let bind_addr = config.bind_addr();
    let state = AppState::from_config(config).await?;
    let storage = state.storage.clone();
    let runtime = state.runtime.clone();
    let mut autosave_task = None;
    let mut signal_dump_task = None;
    spawn_metrics_autosave(state.runtime.clone());

    if let Some(storage) = storage.as_ref().filter(|storage| !storage.is_memory()) {
        let backfill = backfill_grpc_descriptors(storage).await;
        if backfill.missing() > 0 {
            warn!(
                scanned = backfill.scanned,
                updated = backfill.updated,
                skipped = backfill.skipped,
                missing = backfill.missing(),
                "gRPC descriptor backfill completed with failures; readiness will remain degraded for affected APIs"
            );
        } else {
            info!(
                scanned = backfill.scanned,
                updated = backfill.updated,
                skipped = backfill.skipped,
                "gRPC descriptor backfill completed"
            );
        }
    }

    if let Some(storage) = storage.as_ref().filter(|storage| storage.is_memory()) {
        let dump_path = security_settings::startup_dump_path(&state.config);
        match snapshot::restore_latest(storage, dump_path.as_deref()).await {
            Ok((version, created_at)) => info!(version, created_at, "restored memory snapshot"),
            Err(snapshot::SnapshotError::Io(error_value))
                if error_value.kind() == std::io::ErrorKind::NotFound =>
            {
                info!("no existing memory snapshot found")
            }
            Err(snapshot::SnapshotError::MissingKey) => {
                warn!("MEM_ENCRYPTION_KEY is not configured; restore and autosave are disabled")
            }
            Err(error_value) => {
                error!(error = %error_value, "memory snapshot restore failed; refusing to start with empty state");
                return Err(error_value.into());
            }
        }
    }

    // Settings restored from a dump or MongoDB take precedence over the file.
    // Load before the listener and the first autosave so policy and persistence
    // use the same settings on the first request.
    if let Some(storage) = &storage {
        let settings = security_settings::load(storage, &state.config).await?;
        state
            .runtime
            .update_memory_autosave_config(MemoryAutosaveConfig::from_settings(Some(&settings)));
        if storage.is_memory() {
            autosave_task = Some(snapshot::spawn_autosave(storage.clone(), runtime.clone()));
            signal_dump_task = spawn_sigusr1_dump(storage.clone(), runtime.clone());
        }
    }

    // Memory snapshots are restored above, so the first purge sees the same
    // records that will serve traffic. External storage has no restore phase.
    if let Some(storage) = &storage {
        run_revocation_purge(storage, &state.runtime).await;
        spawn_revocation_purger(storage.clone(), state.runtime.clone());
    }

    spawn_sighup_reload(state.hot_reload.clone());
    let app = build_router(state);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!(address = %bind_addr, "Doorman Rust gateway listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Axum has now drained active requests. Stop writers before the final dump
    // so an older autosave cannot replace the state committed during draining.
    for task in [autosave_task, signal_dump_task].into_iter().flatten() {
        task.abort();
        let _ = task.await;
    }
    if let Some(storage) = storage.filter(|storage| storage.is_memory()) {
        let dump_path = runtime.memory_autosave_config().borrow().dump_path.clone();
        match snapshot::dump(&storage, dump_path.as_deref()).await {
            Ok(path) => {
                runtime
                    .memory_snapshot_healthy
                    .store(true, Ordering::Relaxed);
                info!(path = %path.display(), "shutdown memory dump completed");
            }
            Err(snapshot::SnapshotError::MissingKey) => {}
            Err(error_value) => {
                runtime
                    .memory_snapshot_healthy
                    .store(false, Ordering::Relaxed);
                error!(error = %error_value, "shutdown memory dump failed");
            }
        }
    }
    persist_metrics();
    Ok(())
}

async fn seed_command(
    arguments: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments.collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        print_seed_help();
        return Ok(());
    }
    let options = parse_seed_options(arguments.into_iter())?;
    println!("Starting demo seed with:");
    println!("  Users: {}", options.users);
    println!("  APIs: {}", options.apis);
    println!("  Endpoints per API: {}", options.endpoints);
    println!("  Groups: {}", options.groups);
    println!("  Protos: {}", options.protos);
    println!("  Logs: {}", options.logs);
    if let Some(seed) = options.seed {
        println!("  Random Seed: {seed}");
    }
    println!();

    let config = Config::from_env()?;
    let storage = SharedStorage::connect(&config.shared_storage).await?;
    storage.initialize_core().await?;
    let result = run_seed(&storage, &options).await?;
    println!("\n✓ Seeding completed successfully!");
    println!("Result: {result}");
    Ok(())
}

fn parse_seed_options(
    arguments: impl Iterator<Item = String>,
) -> Result<SeedOptions, Box<dyn std::error::Error>> {
    let mut options = SeedOptions::default();
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value.to_owned()))
            });
        let value = inline_value
            .or_else(|| arguments.next())
            .ok_or_else(|| format!("{name} requires an integer value"))?;
        match name {
            "--users" => options.users = value.parse()?,
            "--apis" => options.apis = value.parse()?,
            "--endpoints" => options.endpoints = value.parse()?,
            "--groups" => options.groups = value.parse()?,
            "--protos" => options.protos = value.parse()?,
            "--logs" => options.logs = value.parse()?,
            "--seed" => options.seed = Some(value.parse()?),
            _ => return Err(format!("unknown seed option: {name}").into()),
        }
    }
    Ok(options)
}

fn print_seed_help() {
    println!(
        "Seed the database with demo data\n\n  --users N       Number of users (default: 60)\n  --apis N        Number of APIs (default: 20)\n  --endpoints N   Endpoints per API (default: 6)\n  --groups N      Number of groups (default: 10)\n  --protos N      Number of proto files (default: 6)\n  --logs N        Number of log entries (default: 2000)\n  --seed N        Random seed for reproducibility"
    );
}

fn pid_file_path() -> PathBuf {
    env::var_os("PID_FILE")
        .or_else(|| env::var_os("DOORMAN_PID_FILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("doorman.pid"))
}

fn start_process() -> Result<(), Box<dyn std::error::Error>> {
    let pid_file = pid_file_path();
    if pid_file.exists() {
        info!(path = %pid_file.display(), "doorman is already running");
        return Ok(());
    }

    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let child = command.spawn()?;
    fs::write(&pid_file, child.id().to_string())?;
    info!(pid = child.id(), "starting doorman");
    Ok(())
}

fn stop_process() -> Result<(), Box<dyn std::error::Error>> {
    let pid_file = pid_file_path();
    if !pid_file.exists() {
        info!("no running instance found");
        return Ok(());
    }
    let pid = read_pid(&pid_file)?;

    #[cfg(unix)]
    stop_unix_process_group(pid);
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status();
    }

    if pid_file.exists() {
        fs::remove_file(&pid_file)?;
    }
    info!(pid, "stopping doorman");
    Ok(())
}

fn read_pid(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let pid = fs::read_to_string(path)?.trim().parse::<u32>()?;
    if pid == 0 {
        return Err("PID file must contain a positive process ID".into());
    }
    Ok(pid)
}

#[cfg(unix)]
fn stop_unix_process_group(pid: u32) {
    let group = format!("-{pid}");
    let status = Command::new("kill").args(["-TERM", "--", &group]).status();
    if !status.is_ok_and(|status| status.success()) {
        return;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let running = Command::new("kill")
            .args(["-0", "--", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !running {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(unix)]
fn spawn_sighup_reload(config: Arc<HotReloadConfig>) {
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(error_value) => {
                warn!(error = %error_value, "failed to register SIGHUP configuration reload handler");
                return;
            }
        };
        while signal.recv().await.is_some() {
            match config.reload() {
                Ok(()) => info!("configuration reloaded from SIGHUP"),
                Err(error_value) => {
                    error!(error = %error_value, "SIGHUP configuration reload failed; retaining prior configuration")
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload(_config: Arc<HotReloadConfig>) {}

async fn run_revocation_purge(storage: &SharedStorage, runtime: &GatewayRuntime) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    match storage.purge_expired_revocations(now).await {
        Ok(removed) => {
            runtime
                .revocation_purge_healthy
                .store(true, Ordering::Relaxed);
            if removed > 0 {
                info!(removed, "purged expired token revocations");
            }
        }
        Err(error_value) => {
            runtime
                .revocation_purge_healthy
                .store(false, Ordering::Relaxed);
            error!(error = %error_value, "expired token revocation purge failed");
        }
    }
}

fn spawn_revocation_purger(storage: Arc<SharedStorage>, runtime: Arc<GatewayRuntime>) {
    let seconds = env::var("REVOCATION_PURGE_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(300)
        .max(1);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(seconds));
        interval.tick().await;
        loop {
            interval.tick().await;
            run_revocation_purge(&storage, &runtime).await;
        }
    });
}

#[cfg(unix)]
fn spawn_sigusr1_dump(
    storage: Arc<SharedStorage>,
    runtime: Arc<GatewayRuntime>,
) -> Option<tokio::task::JoinHandle<()>> {
    // Register before opening the listener, so the first accepted request can
    // safely be followed by an on-demand signal.
    let mut signal =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
            Ok(signal) => signal,
            Err(error_value) => {
                warn!(error = %error_value, "failed to register SIGUSR1 memory dump handler");
                return None;
            }
        };
    Some(tokio::spawn(async move {
        while signal.recv().await.is_some() {
            let dump_path = runtime.memory_autosave_config().borrow().dump_path.clone();
            match snapshot::dump(&storage, dump_path.as_deref()).await {
                Ok(path) => {
                    runtime
                        .memory_snapshot_healthy
                        .store(true, Ordering::Relaxed);
                    info!(path = %path.display(), "SIGUSR1 memory dump completed");
                }
                Err(error_value) => {
                    runtime
                        .memory_snapshot_healthy
                        .store(false, Ordering::Relaxed);
                    error!(error = %error_value, "SIGUSR1 memory dump failed");
                }
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_sigusr1_dump(
    _storage: Arc<SharedStorage>,
    _runtime: Arc<GatewayRuntime>,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown requested; draining active requests");
}

fn metrics_paths() -> [PathBuf; 2] {
    let directory = env::var_os("LOGS_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            let path = PathBuf::from("/app/logs");
            path.is_dir().then_some(path)
        })
        .unwrap_or_else(|| PathBuf::from("platform-logs"));
    [
        directory.join("enhanced_metrics.json"),
        directory.join("metrics.json"),
    ]
}

fn restore_metrics() {
    for path in metrics_paths() {
        if !path.exists() {
            continue;
        }
        match global_analytics().load_from_file(&path) {
            Ok(()) => {
                info!(path = %path.display(), "restored gateway metrics");
                return;
            }
            Err(error_value) => {
                warn!(path = %path.display(), error = %error_value, "gateway metrics restore skipped");
            }
        }
    }
}

fn persist_metrics() -> bool {
    let mut persisted = true;
    for path in metrics_paths() {
        if let Err(error_value) = global_analytics().save_to_file(&path) {
            persisted = false;
            warn!(path = %path.display(), error = %error_value, "gateway metrics persistence failed");
        }
    }
    persisted
}

fn spawn_metrics_autosave(runtime: Arc<GatewayRuntime>) {
    let seconds = env::var("METRICS_SAVE_INTERVAL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60)
        .max(1);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(seconds));
        interval.tick().await;
        loop {
            interval.tick().await;
            runtime
                .metrics_persistence_healthy
                .store(persist_metrics(), Ordering::Relaxed);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_files_require_a_positive_integer() {
        let directory = env::temp_dir().join(format!("doorman-pid-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("doorman.pid");

        fs::write(&path, "1234\n").unwrap();
        assert_eq!(read_pid(&path).unwrap(), 1234);
        fs::write(&path, "0").unwrap();
        assert!(read_pid(&path).is_err());
        fs::write(&path, "invalid").unwrap();
        assert!(read_pid(&path).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn seed_options_match_python_cli_names_and_defaults() {
        assert_eq!(
            parse_seed_options(std::iter::empty()).unwrap(),
            SeedOptions::default()
        );
        assert_eq!(
            parse_seed_options(
                [
                    "--users=2",
                    "--apis",
                    "3",
                    "--endpoints",
                    "4",
                    "--groups",
                    "5",
                    "--protos",
                    "6",
                    "--logs",
                    "7",
                    "--seed",
                    "8",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .unwrap(),
            SeedOptions {
                users: 2,
                apis: 3,
                endpoints: 4,
                groups: 5,
                protos: 6,
                logs: 7,
                seed: Some(8),
            }
        );
    }
}
