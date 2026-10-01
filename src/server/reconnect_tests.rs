use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::{
    keys::ssh_key::{Algorithm, LineEnding},
    server::Server,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
};

use super::*;
use crate::client::{ClientCommand, ConnectionOptions};

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    options: ConnectionOptions,
    server: JoinHandle<()>,
    proxy: JoinHandle<()>,
    control: Arc<ProxyControl>,
}

struct ProxyControl {
    fault: AtomicU64,
    connections: AtomicUsize,
    forwarded: AtomicU64,
    paused: AtomicBool,
    resumes: Semaphore,
}

impl Fixture {
    async fn new(drop_upload: bool) -> Self {
        let directory =
            std::env::temp_dir().join(format!("jftp-reconnect-test-{}", uuid::Uuid::new_v4()));
        let root = directory.join("root");
        fs::create_dir_all(root.join("subdir")).await.unwrap();
        let root = fs::canonicalize(root).await.unwrap();
        let identity = keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let host_key = keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let identity_file = directory.join("identity");
        fs::write(
            &identity_file,
            identity.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .await
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let account = UserAccount {
            name: "test".into(),
            home_directory: root.clone(),
            authorized_keys: vec![identity.public_key().clone()],
            can_read: true,
            can_write: true,
            can_delete: true,
        };
        let context = Arc::new(ServerContext {
            root_directory: root.clone(),
            users: HashMap::from([("test".into(), account)]),
            uploads: Default::default(),
        });
        let config = Arc::new(server::Config {
            keys: vec![host_key.clone()],
            ..Default::default()
        });
        let server = tokio::spawn(async move {
            JftpServer { context }
                .run_on_socket(config, &listener)
                .await
                .unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let known_hosts_file = directory.join("known_hosts");
        fs::write(
            &known_hosts_file,
            format!(
                "[127.0.0.1]:{port} {}\n",
                host_key.public_key().to_openssh().unwrap()
            ),
        )
        .await
        .unwrap();
        let control = Arc::new(ProxyControl {
            fault: AtomicU64::new(0),
            connections: AtomicUsize::new(0),
            forwarded: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            resumes: Semaphore::new(1),
        });
        let proxy = tokio::spawn(proxy(
            listener,
            server_address,
            drop_upload,
            control.clone(),
        ));
        Self {
            directory,
            root,
            options: ConnectionOptions {
                host: "127.0.0.1".into(),
                port,
                username: "test".into(),
                identity_file,
                known_hosts_file,
            },
            server,
            proxy,
            control,
        }
    }

    async fn connect(&self) -> crate::client::ClientSession {
        crate::client::connect(&self.options, ("127.0.0.1", self.options.port))
            .await
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        self.proxy.abort();
        // Cleanup may need to wait for Windows file handles to close.
        let directory = self.directory.clone();
        tokio::spawn(async move {
            for _ in 0..20 {
                if fs::remove_dir_all(&directory).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
    }
}

async fn proxy(
    listener: TcpListener,
    server: SocketAddr,
    drop_upload: bool,
    control: Arc<ProxyControl>,
) {
    loop {
        let (mut client, _) = listener.accept().await.unwrap();
        if control.connections.load(Ordering::SeqCst) > 0 {
            let permit = control.resumes.acquire().await.unwrap();
            drop(permit);
        }
        let mut upstream = TcpStream::connect(server).await.unwrap();
        control.connections.fetch_add(1, Ordering::SeqCst);
        let control = control.clone();
        tokio::spawn(async move {
            let (client_read, client_write) = client.split();
            let (server_read, server_write) = upstream.split();
            tokio::select! {
                _ = relay(client_read, server_write, drop_upload, &control) => {},
                _ = relay(server_read, client_write, !drop_upload, &control) => {},
            }
        });
    }
}

async fn relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    monitored: bool,
    control: &ProxyControl,
) {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let Ok(read) = reader.read(&mut buffer).await else {
            return;
        };
        if read == 0 {
            return;
        }
        if monitored {
            let remaining = control.fault.load(Ordering::SeqCst);
            if remaining > 0 {
                if remaining <= read as u64 {
                    control.fault.store(0, Ordering::SeqCst);
                    return; // Drop both TCP directions, once per armed fault.
                }
                control.fault.fetch_sub(read as u64, Ordering::SeqCst);
            }
            control.forwarded.fetch_add(read as u64, Ordering::SeqCst);
        }
        while control.paused.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if writer.write_all(&buffer[..read]).await.is_err() {
            return;
        }
        if monitored {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

fn contents() -> Vec<u8> {
    (0..4 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect()
}

async fn wait_until(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn changed_download_source_is_rejected_after_reconnecting() {
    let fixture = Fixture::new(false).await;
    let mut session = fixture.connect().await;
    let mut content = contents();
    let source = fixture.root.join("source.bin");
    fs::write(&source, &content).await.unwrap();
    let destination = fixture.directory.join("download.bin");
    let gate = fixture.control.resumes.acquire().await.unwrap();
    fixture.control.fault.store(1024 * 1024, Ordering::SeqCst);
    let local = destination.clone();
    let transfer = tokio::spawn(async move {
        let result = session
            .run_command(ClientCommand::Download {
                remote: "/source.bin".into(),
                local,
            })
            .await;
        (session, result)
    });
    wait_until(|| fixture.control.fault.load(Ordering::SeqCst) == 0).await;
    content[0] ^= 1; // Same length, different contents.
    fs::write(source, &content).await.unwrap();
    drop(gate);
    let (mut session, result) = tokio::time::timeout(Duration::from_secs(15), transfer)
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("source changed"));
    assert!(!fs::try_exists(destination).await.unwrap());
    // The error stream is drained and a new command still works.
    session.run_command(ClientCommand::Pwd).await.unwrap();
}

#[tokio::test]
async fn short_traffic_pause_continues_without_reconnecting() {
    let fixture = Fixture::new(false).await;
    let mut session = fixture.connect().await;
    let content = contents();
    fs::write(fixture.root.join("source.bin"), &content)
        .await
        .unwrap();
    let destination = fixture.directory.join("download.bin");
    let local = destination.clone();
    let before = fixture.control.forwarded.load(Ordering::SeqCst);
    let transfer = tokio::spawn(async move {
        session
            .run_command(ClientCommand::Download {
                remote: "/source.bin".into(),
                local,
            })
            .await
            .unwrap();
        session
    });
    wait_until(|| fixture.control.forwarded.load(Ordering::SeqCst) > before + 256 * 1024).await;
    fixture.control.paused.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await;
    fixture.control.paused.store(false, Ordering::SeqCst);
    let _session = tokio::time::timeout(Duration::from_secs(15), transfer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.control.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(destination).await.unwrap(), content);
}

#[tokio::test]
async fn read_command_reconnects_and_restores_directory() {
    let fixture = Fixture::new(true).await;
    let mut session = fixture.connect().await;
    session
        .run_command(ClientCommand::Cd {
            path: "/subdir".into(),
        })
        .await
        .unwrap();
    fixture.control.fault.store(1, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(15),
        session.run_command(ClientCommand::Pwd),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fixture.control.connections.load(Ordering::SeqCst), 2);
    session
        .run_command(ClientCommand::List {
            path: Some(".".into()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn changed_host_key_stops_automatic_reconnection() {
    let fixture = Fixture::new(true).await;
    let mut session = fixture.connect().await;
    let different_key = keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    fs::write(
        &fixture.options.known_hosts_file,
        format!(
            "[127.0.0.1]:{} {}\n",
            fixture.options.port,
            different_key.public_key().to_openssh().unwrap()
        ),
    )
    .await
    .unwrap();
    fixture.control.fault.store(1, Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        session.run_command(ClientCommand::Pwd),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(fixture.control.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn upload_resumes_after_tcp_drop_and_restores_directory() {
    let fixture = Fixture::new(true).await;
    let mut session = fixture.connect().await;
    session
        .run_command(ClientCommand::Cd {
            path: "/subdir".into(),
        })
        .await
        .unwrap();
    let source = fixture.directory.join("source.bin");
    let content = contents();
    fs::write(&source, &content).await.unwrap();
    let before = fixture.control.forwarded.load(Ordering::SeqCst);
    fixture.control.fault.store(1024 * 1024, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(30),
        session.run_command(ClientCommand::Upload {
            local: source,
            remote: "uploaded.bin".into(),
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        fs::read(fixture.root.join("subdir/uploaded.bin"))
            .await
            .unwrap(),
        content
    );
    assert!(fixture.control.connections.load(Ordering::SeqCst) >= 2);
    assert!(
        fixture.control.forwarded.load(Ordering::SeqCst) - before
            < content.len() as u64 + 512 * 1024,
        "the upload restarted instead of resuming"
    );
    session.run_command(ClientCommand::Pwd).await.unwrap();
}

#[tokio::test]
async fn download_resumes_after_tcp_drop_and_checks_bytes() {
    let fixture = Fixture::new(false).await;
    let mut session = fixture.connect().await;
    session
        .run_command(ClientCommand::Cd {
            path: "/subdir".into(),
        })
        .await
        .unwrap();
    let content = contents();
    fs::write(fixture.root.join("subdir/source.bin"), &content)
        .await
        .unwrap();
    let destination = fixture.directory.join("downloaded.bin");
    let before = fixture.control.forwarded.load(Ordering::SeqCst);
    fixture.control.fault.store(1024 * 1024, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(30),
        session.run_command(ClientCommand::Download {
            remote: "source.bin".into(),
            local: destination.clone(),
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fs::read(destination).await.unwrap(), content);
    assert!(fixture.control.connections.load(Ordering::SeqCst) >= 2);
    assert!(
        fixture.control.forwarded.load(Ordering::SeqCst) - before
            < content.len() as u64 + 512 * 1024,
        "the download restarted instead of resuming"
    );
    session.run_command(ClientCommand::Pwd).await.unwrap();
}
