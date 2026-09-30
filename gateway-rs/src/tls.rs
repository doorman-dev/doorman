use std::{
    fs, io,
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor, TlsStream,
    rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        server::WebPkiClientVerifier,
    },
};
use x509_parser::parse_x509_certificate;

pub mod policy;
pub mod profiles;
pub mod secrets;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 256;

#[derive(Clone, Debug)]
pub struct TlsConnectionInfo {
    pub peer: SocketAddr,
    pub peer_certificates: Vec<Vec<u8>>,
}

impl Connected<IncomingStream<'_, TlsListener>> for TlsConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

pub fn server_config(cert_file: &Path, key_file: &Path) -> io::Result<ServerConfig> {
    server_config_from_pem(&fs::read(cert_file)?, &fs::read(key_file)?)
}

pub fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<ServerConfig> {
    server_config_from_pem_with_roots(cert_pem, key_pem, None)
}

pub fn server_config_from_pem_with_roots(
    cert_pem: &[u8],
    key_pem: &[u8],
    roots: Option<RootCertStore>,
) -> io::Result<ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_pem)?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate file is empty",
        ));
    }
    let (_, leaf) = parse_x509_certificate(certs[0].as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TLS certificate is not X.509"))?;
    if !leaf.validity().is_valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate is not currently valid",
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(invalid_pem)?;
    let verifier = match roots {
        Some(roots) if !roots.is_empty() => WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(invalid_pem)?,
        _ => WebPkiClientVerifier::no_client_auth(),
    };
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

pub fn certificate_expiry_timestamp(pem: &[u8]) -> io::Result<i64> {
    let mut min_expiry = None;
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(invalid_pem)?;
        let (_, parsed) = parse_x509_certificate(cert.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "certificate is not X.509"))?;
        let expiry = parsed.validity().not_after.timestamp();
        min_expiry = Some(min_expiry.map_or(expiry, |prior: i64| prior.min(expiry)));
    }
    min_expiry
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PEM contains no certificate"))
}

fn invalid_pem(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

type PendingHandshake = BoxFuture<'static, io::Result<(TlsStream<TcpStream>, TlsConnectionInfo)>>;

pub struct TlsListener {
    listener: TcpListener,
    config: Arc<RwLock<Arc<ServerConfig>>>,
    pending: FuturesUnordered<PendingHandshake>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: ServerConfig) -> Self {
        Self {
            listener,
            config: Arc::new(RwLock::new(Arc::new(config))),
            pending: FuturesUnordered::new(),
        }
    }

    pub fn reload_handle(&self) -> TlsReloadHandle {
        TlsReloadHandle(self.config.clone())
    }
}

#[derive(Clone)]
pub struct TlsReloadHandle(Arc<RwLock<Arc<ServerConfig>>>);

impl TlsReloadHandle {
    pub fn publish(&self, config: ServerConfig) {
        *self.0.write().expect("TLS configuration lock poisoned") = Arc::new(config);
    }
}

pub fn spawn_file_reload(
    cert_file: std::path::PathBuf,
    key_file: std::path::PathBuf,
    handle: TlsReloadHandle,
    roots: Option<RootCertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        let mut active_hash = None;
        loop {
            interval.tick().await;
            let materials =
                tokio::try_join!(tokio::fs::read(&cert_file), tokio::fs::read(&key_file));
            let (cert_pem, key_pem) = match materials {
                Ok(materials) => materials,
                Err(error) => {
                    tracing::warn!(%error, "TLS certificate reload could not read mounted files");
                    continue;
                }
            };
            let mut hasher = Sha256::new();
            hasher.update(&cert_pem);
            hasher.update(&key_pem);
            let hash: [u8; 32] = hasher.finalize().into();
            if active_hash == Some(hash) {
                continue;
            }
            match server_config_from_pem_with_roots(&cert_pem, &key_pem, roots.clone()) {
                Ok(config) => {
                    handle.publish(config);
                    active_hash = Some(hash);
                    tracing::info!("TLS listener certificate reloaded");
                }
                Err(error) => {
                    tracing::warn!(%error, "TLS certificate reload rejected; retaining active certificate")
                }
            }
        }
    })
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = TlsConnectionInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                accepted = self.listener.accept(), if self.pending.len() < MAX_PENDING_HANDSHAKES => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let config = self.config.read().expect("TLS configuration lock poisoned").clone();
                            let acceptor = TlsAcceptor::from(config);
                            self.pending.push(Box::pin(async move {
                                let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                                    .await
                                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
                                let certificates = stream.get_ref().1.peer_certificates()
                                    .map(|chain| chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
                                    .unwrap_or_default();
                                Ok((TlsStream::Server(stream), TlsConnectionInfo { peer, peer_certificates: certificates }))
                            }));
                        }
                        Err(error) => {
                            tracing::warn!(%error, "TLS listener accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                completed = self.pending.next(), if !self.pending.is_empty() => {
                    match completed {
                        Some(Ok(connected)) => return connected,
                        Some(Err(error)) => tracing::debug!(%error, "TLS handshake rejected"),
                        None => {}
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(TlsConnectionInfo {
            peer: self.listener.local_addr()?,
            peer_certificates: Vec::new(),
        })
    }
}
