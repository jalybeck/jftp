mod handler;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use russh::{
    keys::{
        self,
        ssh_key::{Algorithm, LineEnding, PublicKey},
    },
    server::{self, Server as _},
};
use serde::Deserialize;

pub use handler::JftpHandler;

#[derive(Debug, Clone)]
pub struct UserAccount {
    pub name: String,
    pub home_directory: PathBuf,
    pub authorized_keys: Vec<PublicKey>,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
}

#[derive(Debug)]
pub struct ServerContext {
    pub root_directory: PathBuf,
    pub users: HashMap<String, UserAccount>,
}

#[derive(Deserialize)]
struct UsersFile {
    users: Vec<UserConfig>,
}

#[derive(Deserialize)]
struct UserConfig {
    name: String,
    #[serde(default = "default_home")]
    home: PathBuf,
    #[serde(default)]
    authorized_keys: Vec<String>,
    #[serde(default)]
    authorized_keys_file: Option<PathBuf>,
    #[serde(default)]
    permissions: Permissions,
}

fn default_home() -> PathBuf {
    PathBuf::from(".")
}

#[derive(Deserialize)]
struct Permissions {
    #[serde(default = "default_true")]
    read: bool,
    #[serde(default)]
    write: bool,
    #[serde(default)]
    delete: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
        }
    }
}

fn default_true() -> bool {
    true
}

pub async fn default_config_directory() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|path| PathBuf::from(path).join("AppData").join("Roaming"))
        })
        .context("APPDATA or USERPROFILE must be set")?;

    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|path| PathBuf::from(path).join(".config")))
        .context("HOME or XDG_CONFIG_HOME must be set")?;

    Ok(base.join("jftp"))
}

pub async fn run(
    root_arg: PathBuf,
    port: u16,
    users_arg: Option<PathBuf>,
    host_key_arg: Option<PathBuf>,
) -> anyhow::Result<()> {
    let root_directory = tokio::fs::canonicalize(&root_arg)
        .await
        .with_context(|| format!("cannot resolve served directory {}", root_arg.display()))?;
    if !tokio::fs::metadata(&root_directory).await?.is_dir() {
        bail!("--path must point to a directory");
    }

    let config_directory = default_config_directory().await?;
    tokio::fs::create_dir_all(&config_directory)
        .await
        .with_context(|| {
            format!(
                "cannot create config directory {}",
                config_directory.display()
            )
        })?;
    let users_path = users_arg.unwrap_or_else(|| config_directory.join("users.toml"));
    let host_key_path =
        host_key_arg.unwrap_or_else(|| config_directory.join("ssh_host_ed25519_key"));

    let users_path = tokio::fs::canonicalize(&users_path)
        .await
        .with_context(|| {
            format!(
                "cannot find users file {} (see users.example.toml)",
                users_path.display()
            )
        })?;
    ensure_not_served(&users_path, &root_directory, "users file")?;
    let users_text = tokio::fs::read_to_string(&users_path)
        .await
        .with_context(|| format!("cannot read users file {}", users_path.display()))?;
    let parsed: UsersFile = toml::from_str(&users_text)
        .with_context(|| format!("invalid users file {}", users_path.display()))?;
    if parsed.users.is_empty() {
        bail!("users file must declare at least one user");
    }

    let mut users = HashMap::new();
    for config in parsed.users {
        if config.name.trim().is_empty() {
            bail!("user names must not be empty");
        }
        if config.home.is_absolute()
            || config
                .home
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            bail!(
                "home for user {:?} must be a relative directory inside --path",
                config.name
            );
        }
        let home_directory = tokio::fs::canonicalize(root_directory.join(&config.home))
            .await
            .with_context(|| format!("cannot resolve home directory for user {:?}", config.name))?;
        if !home_directory.starts_with(&root_directory)
            || !tokio::fs::metadata(&home_directory).await?.is_dir()
        {
            bail!(
                "home for user {:?} must be a directory inside --path",
                config.name
            );
        }
        let mut authorized_keys = Vec::new();
        for source in config.authorized_keys {
            add_authorized_key(&mut authorized_keys, source.trim(), &config.name)?;
        }
        if let Some(key_file) = config.authorized_keys_file {
            let key_file = if key_file.is_absolute() {
                key_file
            } else {
                users_path
                    .parent()
                    .context("users file has no parent directory")?
                    .join(key_file)
            };
            let key_file = tokio::fs::canonicalize(&key_file).await.with_context(|| {
                format!(
                    "cannot resolve authorized keys file for user {:?}: {}",
                    config.name,
                    key_file.display()
                )
            })?;
            ensure_not_served(&key_file, &root_directory, "authorized keys file")?;
            let contents = tokio::fs::read_to_string(&key_file)
                .await
                .with_context(|| {
                    format!(
                        "cannot read authorized keys file for user {:?}: {}",
                        config.name,
                        key_file.display()
                    )
                })?;
            for (line_index, line) in contents.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                add_authorized_key(&mut authorized_keys, line, &config.name).with_context(
                    || {
                        format!(
                            "invalid key on line {} of {}",
                            line_index + 1,
                            key_file.display()
                        )
                    },
                )?;
            }
        }
        if authorized_keys.is_empty() {
            bail!(
                "user {:?} must specify at least one Ed25519 key using authorized_keys or authorized_keys_file",
                config.name
            );
        }
        let account = UserAccount {
            name: config.name.clone(),
            home_directory,
            authorized_keys,
            can_read: config.permissions.read,
            can_write: config.permissions.write,
            can_delete: config.permissions.delete,
        };
        if users.insert(config.name.clone(), account).is_some() {
            bail!("duplicate user name {:?}", config.name);
        }
    }

    let host_key = load_or_create_host_key(&host_key_path, &root_directory).await?;
    let public_line = host_key.public_key().to_openssh()?;
    eprintln!(
        "jftp SSH host key: {}",
        host_key
            .public_key()
            .fingerprint(keys::ssh_key::HashAlg::Sha256)
    );
    eprintln!("jftp host public key: {public_line}");
    eprintln!(
        "Listening on 0.0.0.0:{port}; served root: {}",
        root_directory.display()
    );

    let context = Arc::new(ServerContext {
        root_directory,
        users,
    });
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        inactivity_timeout: Some(Duration::from_secs(900)),
        keepalive_interval: Some(Duration::from_secs(60)),
        keepalive_max: 3,
        ..Default::default()
    });

    let mut server = JftpServer { context };
    server.run_on_address(config, ("0.0.0.0", port)).await?;
    Ok(())
}

fn add_authorized_key(
    authorized_keys: &mut Vec<PublicKey>,
    source: &str,
    username: &str,
) -> anyhow::Result<()> {
    let key = keys::parse_public_key_base64(source)
        .with_context(|| format!("invalid authorized key for user {username:?}"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("user {username:?} has a non-Ed25519 authorized key");
    }
    if !authorized_keys.contains(&key) {
        authorized_keys.push(key);
    }
    Ok(())
}

fn ensure_not_served(file: &Path, root: &Path, what: &str) -> anyhow::Result<()> {
    if file.starts_with(root) {
        bail!("{what} must be outside the served root to prevent it being downloaded");
    }
    Ok(())
}

async fn load_or_create_host_key(path: &Path, root: &Path) -> anyhow::Result<keys::PrivateKey> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.as_os_str().is_empty() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("cannot create host key directory {}", parent.display()))?;
        let canonical_parent = tokio::fs::canonicalize(parent).await?;
        ensure_not_served(&canonical_parent, root, "SSH host key")?;
    }

    if tokio::fs::try_exists(path).await? {
        let canonical_key = tokio::fs::canonicalize(path)
            .await
            .with_context(|| format!("cannot resolve SSH host key {}", path.display()))?;
        ensure_not_served(&canonical_key, root, "SSH host key")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = tokio::fs::metadata(&canonical_key).await?.permissions();
            permissions.set_mode(0o600);
            tokio::fs::set_permissions(&canonical_key, permissions).await?;
        }
        let key_text = tokio::fs::read_to_string(&canonical_key)
            .await
            .with_context(|| format!("cannot read SSH host key {}", canonical_key.display()))?;
        let key = keys::decode_secret_key(&key_text, None)
            .with_context(|| format!("cannot read SSH host key {}", canonical_key.display()))?;
        if key.algorithm() != Algorithm::Ed25519 {
            bail!("SSH host key must use Ed25519: {}", canonical_key.display());
        }
        return Ok(key);
    }

    let mut rng = rand::rng();
    let key = keys::PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .context("could not generate an Ed25519 SSH host key")?;
    let encoded = key.to_openssh(LineEnding::LF)?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("cannot create SSH host key {}", path.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(encoded.as_bytes()).await?;
    file.flush().await?;
    Ok(key)
}

#[derive(Clone)]
struct JftpServer {
    context: Arc<ServerContext>,
}

impl server::Server for JftpServer {
    type Handler = JftpHandler;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Self::Handler {
        JftpHandler::new(self.context.clone())
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        eprintln!("SSH session ended: {error:#}");
    }
}
