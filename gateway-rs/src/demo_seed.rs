use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{Rng, SeedableRng, prelude::SliceRandom, rngs::StdRng};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    observability::analytics_aggregator::global_analytics,
    storage::{field_encryption::encrypt_value, runtime::SharedStorage},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedOptions {
    pub users: usize,
    pub apis: usize,
    pub endpoints: usize,
    pub groups: usize,
    pub protos: usize,
    pub logs: usize,
    pub seed: Option<u64>,
}

impl Default for SeedOptions {
    fn default() -> Self {
        Self {
            users: 60,
            apis: 20,
            endpoints: 6,
            groups: 10,
            protos: 6,
            logs: 2_000,
            seed: None,
        }
    }
}

pub async fn run_seed(
    storage: &SharedStorage,
    options: &SeedOptions,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut rng = options
        .seed
        .map(StdRng::seed_from_u64)
        .unwrap_or_else(StdRng::from_os_rng);
    let roles = ensure_roles(storage).await?;
    let apis = seed_apis(storage, options.apis, &roles, &mut rng).await?;
    let api_keys = apis
        .iter()
        .map(|(name, version)| format!("{name}/{version}"))
        .collect::<Vec<_>>();
    let groups = seed_groups(storage, options.groups, &api_keys, &mut rng).await?;
    let users = seed_users(storage, options.users, &roles, &groups, &mut rng).await?;
    seed_endpoints(storage, &apis, options.endpoints, &mut rng).await?;
    let credit_groups = seed_credits(storage, &mut rng).await?;
    seed_user_credits(storage, &users, &credit_groups, &mut rng).await?;
    seed_subscriptions(storage, &users, &api_keys, &mut rng).await?;
    seed_logs(options.logs, &users, &apis, &mut rng)?;
    seed_protos(options.protos, &apis, &mut rng)?;
    seed_metrics(&users, &apis, &mut rng);

    let mut result = serde_json::Map::new();
    for (name, collection) in [
        ("users", "users"),
        ("apis", "apis"),
        ("endpoints", "endpoints"),
        ("groups", "groups"),
        ("roles", "roles"),
        ("subscriptions", "subscriptions"),
        ("credit_defs", "credit_defs"),
        ("user_credits", "user_credits"),
    ] {
        result.insert(
            name.to_owned(),
            json!(storage.find_many(collection, &json!({})).await?.len()),
        );
    }
    Ok(Value::Object(result))
}

async fn ensure_roles(storage: &SharedStorage) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let roles = [
        (
            "developer",
            json!({"manage_apis": true, "manage_endpoints": true, "manage_subscriptions": true, "manage_credits": true, "view_logs": true}),
        ),
        ("analyst", json!({"view_logs": true, "export_logs": true})),
        ("viewer", json!({"view_logs": true})),
        (
            "ops",
            json!({"manage_gateway": true, "view_logs": true, "export_logs": true, "manage_security": true}),
        ),
    ];
    for (name, extra) in roles {
        if storage
            .find_one("roles", &json!({"role_name": name}))
            .await?
            .is_none()
        {
            let mut value = json!({"role_name": name, "role_description": format!("{name} role")});
            if let (Some(target), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
                target.extend(extra.clone());
            }
            storage.insert_one("roles", value).await?;
        }
    }
    Ok(["admin", "developer", "analyst", "viewer", "ops"]
        .into_iter()
        .map(str::to_owned)
        .collect())
}

async fn seed_apis(
    storage: &SharedStorage,
    count: usize,
    roles: &[String],
    rng: &mut StdRng,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let bases = [
        "customers",
        "orders",
        "billing",
        "weather",
        "news",
        "crypto",
        "search",
        "inventory",
        "shipping",
        "payments",
        "alerts",
        "metrics",
        "recommendations",
    ];
    let versions = ["v1", "v2", "v3"];
    let mut result = Vec::new();
    for _ in 0..count {
        let name = format!("{}-{}", choose(&bases, rng), random_word(3, 6, rng));
        let version = choose(&versions, rng).to_string();
        if storage
            .find_one("apis", &json!({"api_name": name, "api_version": version}))
            .await?
            .is_none()
        {
            storage
                .insert_one(
                    "apis",
                    json!({
                        "api_name": name, "api_version": version,
                        "api_description": format!("Auto API {name}/{version}"),
                        "api_allowed_roles": sample(roles, rng.random_range(1..=roles.len().min(3)), rng),
                        "api_allowed_groups": ["ALL", "admin"],
                        "api_servers": [format!("http://localhost:{}", 8_000 + rng.random_range(0..1_000))],
                        "api_type": "REST", "api_allowed_retry_count": rng.random_range(0..=3),
                        "api_id": Uuid::new_v4().to_string(), "api_path": format!("/{name}/{version}")
                    }),
                )
                .await?;
        }
        result.push((name, version));
    }
    Ok(result)
}

async fn seed_groups(
    storage: &SharedStorage,
    count: usize,
    api_keys: &[String],
    rng: &mut StdRng,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    for index in 0..count {
        let name = format!("team-{}-{index}", random_word(3, 6, rng));
        if storage
            .find_one("groups", &json!({"group_name": name}))
            .await?
            .is_none()
        {
            let access = if api_keys.is_empty() {
                Vec::new()
            } else {
                let maximum = (api_keys.len() / 3).max(1);
                sample(api_keys, rng.random_range(1..=maximum), rng)
            };
            storage.insert_one("groups", json!({"group_name": name, "group_description": format!("Auto group {name}"), "api_access": access})).await?;
        }
        result.push(name);
    }
    for name in ["ALL", "admin"] {
        if storage
            .find_one("groups", &json!({"group_name": name}))
            .await?
            .is_none()
        {
            storage.insert_one("groups", json!({"group_name": name, "group_description": format!("{name} group"), "api_access": []})).await?;
        }
        if !result.iter().any(|item| item == name) {
            result.push(name.to_owned());
        }
    }
    Ok(result)
}

async fn seed_users(
    storage: &SharedStorage,
    count: usize,
    roles: &[String],
    groups: &[String],
    rng: &mut StdRng,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let firsts = [
        "alex", "casey", "morgan", "sam", "taylor", "riley", "jamie", "jordan", "drew", "quinn",
        "kyle", "parker", "blake", "devon",
    ];
    let lasts = [
        "lee", "kim", "patel", "garcia", "nguyen", "williams", "brown", "davis", "miller",
        "wilson", "moore", "taylor", "thomas",
    ];
    let domains = ["example.com", "acme.io", "contoso.net", "demo.dev"];
    let mut result = Vec::new();
    for index in 0..count {
        let username = format!("{}.{}_{}", choose(&firsts, rng), choose(&lasts, rng), index);
        if storage
            .find_one("users", &json!({"username": username}))
            .await?
            .is_none()
        {
            let password = bcrypt::hash(random_password(rng), bcrypt::DEFAULT_COST)?;
            let group_count = rng.random_range(1..=groups.len().min(3));
            storage.insert_one("users", json!({
                "username": username, "email": format!("{}@{}", username.replace('.', "_"), choose(&domains, rng)),
                "password": password, "role": choose(roles, rng), "groups": sample(groups, group_count, rng),
                "rate_limit_duration": rng.random_range(100..=10_000), "rate_limit_duration_type": choose(&["minute", "hour", "day"], rng),
                "throttle_duration": rng.random_range(1_000..=100_000), "throttle_duration_type": choose(&["second", "minute"], rng),
                "throttle_wait_duration": rng.random_range(100..=10_000), "throttle_wait_duration_type": choose(&["seconds", "minutes"], rng),
                "custom_attributes": {"dept": choose(&["sales", "eng", "support", "ops"], rng)}, "active": true,
                "ui_access": rng.random_bool(0.5)
            })).await?;
        }
        result.push(username);
    }
    Ok(result)
}

async fn seed_endpoints(
    storage: &SharedStorage,
    apis: &[(String, String)],
    per_api: usize,
    rng: &mut StdRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    let uris = [
        "/status",
        "/health",
        "/items",
        "/items/{id}",
        "/search",
        "/reports",
        "/export",
        "/metrics",
        "/list",
        "/detail/{id}",
    ];
    for (name, version) in apis {
        let api = storage
            .find_one("apis", &json!({"api_name": name, "api_version": version}))
            .await?;
        let api_id = api
            .as_ref()
            .and_then(|value| value.get("api_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut created = BTreeSet::new();
        for _ in 0..per_api {
            let method = choose(&methods, rng);
            let uri = choose(&uris, rng);
            if !created.insert((method, uri)) || storage.find_one("endpoints", &json!({"api_name": name, "api_version": version, "endpoint_method": method, "endpoint_uri": uri})).await?.is_some() { continue; }
            storage.insert_one("endpoints", json!({"api_name": name, "api_version": version, "endpoint_method": method, "endpoint_uri": uri, "endpoint_description": format!("{method} {uri} for {name}"), "api_id": api_id, "endpoint_id": Uuid::new_v4().to_string()})).await?;
        }
    }
    Ok(())
}

async fn seed_credits(
    storage: &SharedStorage,
    rng: &mut StdRng,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let groups = [
        "ai-basic",
        "ai-pro",
        "maps-basic",
        "maps-pro",
        "news-tier",
        "weather-tier",
    ];
    let catalog = [
        json!({"tier_name":"basic","credits":100,"input_limit":100,"output_limit":100,"reset_frequency":"monthly"}),
        json!({"tier_name":"pro","credits":1000,"input_limit":500,"output_limit":500,"reset_frequency":"monthly"}),
        json!({"tier_name":"enterprise","credits":10000,"input_limit":2000,"output_limit":2000,"reset_frequency":"monthly"}),
    ];
    for group in groups {
        if storage
            .find_one("credit_defs", &json!({"api_credit_group": group}))
            .await?
            .is_none()
        {
            let tiers = sample(&catalog, rng.random_range(1..=3), rng);
            storage.insert_one("credit_defs", json!({"api_credit_group": group, "api_key": encrypt_value(Some(&Uuid::new_v4().simple().to_string())), "api_key_header": choose(&["x-api-key", "authorization", "x-token"], rng), "credit_tiers": tiers})).await?;
        }
    }
    Ok(groups.into_iter().map(str::to_owned).collect())
}

async fn seed_user_credits(
    storage: &SharedStorage,
    users: &[String],
    groups: &[String],
    rng: &mut StdRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let selected = sample(users, (users.len() / 2).max(1).min(users.len()), rng);
    for username in selected {
        let mut credits = serde_json::Map::new();
        for group in sample(groups, rng.random_range(1..=groups.len().min(3)), rng) {
            let days = rng.random_range(1..=30);
            credits.insert(group, json!({"tier_name": choose(&["basic", "pro", "enterprise"], rng), "available_credits": rng.random_range(10..=10_000), "reset_date": date_after(days), "user_api_key": encrypt_value(Some(&Uuid::new_v4().simple().to_string()))}));
        }
        let value = json!({"users_credits": credits});
        if storage
            .find_one("user_credits", &json!({"username": username}))
            .await?
            .is_some()
        {
            storage
                .update_one("user_credits", &json!({"username": username}), &value)
                .await?;
        } else {
            storage
                .insert_one(
                    "user_credits",
                    json!({"username": username, "users_credits": credits}),
                )
                .await?;
        }
    }
    Ok(())
}

async fn seed_subscriptions(
    storage: &SharedStorage,
    users: &[String],
    api_keys: &[String],
    rng: &mut StdRng,
) -> Result<(), Box<dyn std::error::Error>> {
    for username in users {
        let subscriptions = if api_keys.is_empty() {
            Vec::new()
        } else {
            sample(api_keys, rng.random_range(1..=api_keys.len().min(5)), rng)
        };
        if storage
            .find_one("subscriptions", &json!({"username": username}))
            .await?
            .is_some()
        {
            storage
                .update_one(
                    "subscriptions",
                    &json!({"username": username}),
                    &json!({"apis": subscriptions}),
                )
                .await?;
        } else {
            storage
                .insert_one(
                    "subscriptions",
                    json!({"username": username, "apis": subscriptions}),
                )
                .await?;
        }
    }
    Ok(())
}

fn seed_logs(
    count: usize,
    users: &[String],
    apis: &[(String, String)],
    rng: &mut StdRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::var_os("LOGS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "logs".into());
    fs::create_dir_all(&directory)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("doorman.log"))?;
    for _ in 0..count {
        let (api, version) = apis
            .get(rng.random_range(0..apis.len().max(1)))
            .cloned()
            .unwrap_or_else(|| ("demo".to_owned(), "v1".to_owned()));
        let user = users
            .get(rng.random_range(0..users.len().max(1)))
            .map(String::as_str)
            .unwrap_or("admin");
        writeln!(
            file,
            "{} - doorman.gateway - INFO - {} | Username: {user} | From: 127.0.0.1:{} | Endpoint: {} /{api}/{version}{} | Total time: {}ms",
            timestamp(),
            Uuid::new_v4(),
            rng.random_range(10_000..=65_000),
            choose(&["GET", "POST", "PUT", "DELETE", "PATCH"], rng),
            choose(
                &[
                    "/status",
                    "/list",
                    "/items",
                    "/items/123",
                    "/search?q=test",
                    "/export",
                    "/metrics"
                ],
                rng
            ),
            rng.random_range(5..=500)
        )?;
    }
    Ok(())
}

fn seed_protos(
    count: usize,
    apis: &[(String, String)],
    rng: &mut StdRng,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("proto")?;
    fs::create_dir_all("generated")?;
    for (name, version) in sample(apis, count.min(apis.len()), rng) {
        let key = format!("{name}_{version}").replace('-', "_");
        let service = name.split('-').map(capitalize).collect::<String>();
        let content = format!(
            "syntax = \"proto3\";\n\npackage {key};\n\nservice {service}Service {{\n  rpc GetStatus (StatusRequest) returns (StatusReply) {{}}\n}}\n\nmessage StatusRequest {{\n  string id = 1;\n}}\n\nmessage StatusReply {{\n  string status = 1;\n  string message = 2;\n}}\n"
        );
        fs::write(Path::new("proto").join(format!("{key}.proto")), content)?;
    }
    Ok(())
}

fn seed_metrics(users: &[String], apis: &[(String, String)], rng: &mut StdRng) {
    for _ in 0..400 {
        for _ in 0..rng.random_range(0..=50) {
            let status = *choose(&[200_u16, 200, 200, 201, 204, 400, 401, 403, 404, 500], rng);
            let api = apis
                .get(rng.random_range(0..apis.len().max(1)))
                .map(|item| format!("rest:{}", item.0));
            let user = users
                .get(rng.random_range(0..users.len().max(1)))
                .map(String::as_str);
            global_analytics().record_request(
                api.as_deref(),
                user,
                None,
                status,
                rng.random_range(10.0..400.0),
                0,
                0,
            );
        }
    }
}

fn choose<'a, T>(values: &'a [T], rng: &mut StdRng) -> &'a T {
    &values[rng.random_range(0..values.len())]
}

fn sample<T: Clone>(values: &[T], count: usize, rng: &mut StdRng) -> Vec<T> {
    let mut values = values.to_vec();
    values.shuffle(rng);
    values.truncate(count.min(values.len()));
    values
}

fn random_word(minimum: usize, maximum: usize, rng: &mut StdRng) -> String {
    (0..rng.random_range(minimum..=maximum))
        .map(|_| char::from(rng.random_range(b'a'..=b'z')))
        .collect()
}

fn random_password(rng: &mut StdRng) -> String {
    let mut bytes = Vec::new();
    bytes.push(*choose(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", rng));
    bytes.extend((0..8).map(|_| *choose(b"abcdefghijklmnopqrstuvwxyz", rng)));
    bytes.extend((0..4).map(|_| *choose(b"0123456789", rng)));
    bytes.push(*choose(b"!@#$%^&*()-_=+[]{};:,.<>?/", rng));
    bytes.extend((0..6).map(|_| {
        *choose(
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            rng,
        )
    }));
    bytes.shuffle(rng);
    String::from_utf8(bytes).expect("ASCII password")
}

fn date_after(days: i64) -> String {
    let date = (OffsetDateTime::now_utc() + Duration::days(days)).date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        date.month() as u8,
        date.day()
    )
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_string()
}

fn capitalize(value: &str) -> String {
    let mut characters = value.chars();
    characters
        .next()
        .map(char::to_uppercase)
        .into_iter()
        .flatten()
        .chain(characters)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_python_seed_command() {
        assert_eq!(
            SeedOptions::default(),
            SeedOptions {
                users: 60,
                apis: 20,
                endpoints: 6,
                groups: 10,
                protos: 6,
                logs: 2_000,
                seed: None
            }
        );
    }

    #[test]
    fn seeded_generators_are_reproducible() {
        let mut first = StdRng::seed_from_u64(17);
        let mut second = StdRng::seed_from_u64(17);
        assert_eq!(
            random_word(4, 10, &mut first),
            random_word(4, 10, &mut second)
        );
        assert_eq!(random_password(&mut first), random_password(&mut second));
    }
}
