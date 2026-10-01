use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use russh::keys::ssh_key::{Algorithm, PublicKey};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value, value};
use uuid::Uuid;

const AUTHORIZED_KEYS_DIRECTORY: &str = ".jftp-authorized-keys";

#[derive(Debug, Parser)]
#[command(
    name = "jftp-server-admin",
    about = "Manage local jftp server accounts"
)]
pub struct AdminArgs {
    /// Users TOML file. Defaults to the per-user jftp config directory.
    #[arg(long, global = true, value_name = "FILE")]
    users: Option<PathBuf>,

    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Print configured users, permissions, homes, and public-key fingerprints.
    ListUsers,
    /// Add a user using a local OpenSSH public-key file.
    AddUser(AddUserArgs),
    /// Update one user's home, authorized keys, or permissions.
    UpdateUser(UpdateUserArgs),
}

#[derive(Debug, Args)]
struct AddUserArgs {
    /// Account name used by the jftp client.
    username: String,

    /// Client Ed25519 public key file (for example id_ssh.pub).
    #[arg(long, required = true, value_name = "FILE")]
    public_key: PathBuf,

    /// User home relative to the server's --path. Defaults to the served root.
    #[arg(long, default_value = ".", value_name = "DIR")]
    home: PathBuf,

    /// Served root. Required when --home is not "."; creates the home directory if needed.
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Grant permission to upload files and create directories.
    #[arg(long)]
    write: bool,

    /// Grant permission to delete files and directories.
    #[arg(long)]
    delete: bool,

    /// Disable read access. Read access is enabled by default.
    #[arg(long)]
    no_read: bool,
}

#[derive(Debug, Args)]
struct UpdateUserArgs {
    /// Existing account name to update.
    username: String,

    /// Replace the account's authorized key set with keys from this file.
    #[arg(long, value_name = "FILE")]
    public_key: Option<PathBuf>,

    /// New home relative to the server's --path. Requires --root.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Served root. Required when changing --home; creates the new home if needed.
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Enable read access.
    #[arg(long, conflicts_with = "no_read")]
    read: bool,

    /// Disable read access.
    #[arg(long, conflicts_with = "read")]
    no_read: bool,

    /// Enable uploads and directory creation.
    #[arg(long, conflicts_with = "no_write")]
    write: bool,

    /// Disable uploads and directory creation.
    #[arg(long, conflicts_with = "write")]
    no_write: bool,

    /// Enable deletions.
    #[arg(long, conflicts_with = "no_delete")]
    delete: bool,

    /// Disable deletions.
    #[arg(long, conflicts_with = "delete")]
    no_delete: bool,
}

pub async fn run(args: AdminArgs) -> anyhow::Result<()> {
    let AdminArgs { users, command } = args;
    match command {
        AdminCommand::ListUsers => list_users(users).await,
        AdminCommand::AddUser(args) => add_user(args, users).await,
        AdminCommand::UpdateUser(args) => update_user(args, users).await,
    }
}

async fn add_user(args: AddUserArgs, users_override: Option<PathBuf>) -> anyhow::Result<()> {
    let username = args.username.trim();
    if username.is_empty() || username.chars().any(char::is_control) {
        bail!("username must be non-empty and contain no control characters");
    }

    let home_components = validate_home(&args.home)?;
    if !home_components.is_empty() && args.root.is_none() {
        bail!("--root is required when --home is not the served root (.)");
    }
    let root = match args.root.as_deref() {
        Some(path) => {
            let canonical = fs::canonicalize(path)
                .await
                .with_context(|| format!("cannot resolve served root {}", path.display()))?;
            if !fs::metadata(&canonical).await?.is_dir() {
                bail!("--root must point to a directory");
            }
            Some(canonical)
        }
        None => None,
    };

    let users_path = resolve_users_path(users_override, root.as_deref()).await?;
    if let Some(root) = root.as_deref() {
        ensure_outside_root(&users_path, root, "users file")?;
    }

    let public_keys = read_public_keys(&args.public_key).await?;
    let mut document = load_users_document(&users_path).await?;
    ensure_users_array(&mut document)?;
    if document["users"]
        .as_array_of_tables()
        .context("the `users` setting must be an array of tables")?
        .iter()
        .any(|user| user.get("name").and_then(Item::as_str) == Some(username))
    {
        bail!("user {username:?} already exists");
    }

    if let Some(root) = root.as_deref() {
        ensure_user_home(root, &home_components).await?;
    }

    let users_directory = users_path
        .parent()
        .context("users file has no parent directory")?;
    let keys_directory = users_directory.join(AUTHORIZED_KEYS_DIRECTORY);
    let keys_directory = prepare_keys_directory(&keys_directory, root.as_deref()).await?;
    let key_filename = format!("{}.pub", Uuid::new_v4());
    let key_path = keys_directory.join(&key_filename);
    let key_reference = Path::new(AUTHORIZED_KEYS_DIRECTORY)
        .join(&key_filename)
        .to_string_lossy()
        .replace('\\', "/");
    let key_contents = public_keys.join("\n") + "\n";

    append_user(
        &mut document,
        username,
        &args.home,
        &key_reference,
        !args.no_read,
        args.write,
        args.delete,
    )?;

    atomic_write(&key_path, key_contents.as_bytes()).await?;
    let users_contents = document.to_string();
    if let Err(error) = atomic_write(&users_path, users_contents.as_bytes()).await {
        let _ = fs::remove_file(&key_path).await;
        return Err(error).context("could not update users file; removed the new public-key file");
    }

    println!("Added jftp user {username:?}.");
    println!("Users file: {}", users_path.display());
    println!("Authorized key file: {}", key_path.display());
    if let Some(root) = root {
        println!("Served root: {}", root.display());
    }
    Ok(())
}

async fn list_users(users_override: Option<PathBuf>) -> anyhow::Result<()> {
    let users_path = resolve_users_path(users_override, None).await?;
    if !fs::try_exists(&users_path).await? {
        println!("No users file found at {}.", users_path.display());
        return Ok(());
    }
    let document = load_users_document(&users_path).await?;
    let Some(users) = document.get("users").and_then(Item::as_array_of_tables) else {
        println!("No users are configured in {}.", users_path.display());
        return Ok(());
    };
    if users.is_empty() {
        println!("No users are configured in {}.", users_path.display());
        return Ok(());
    }

    println!("Users file: {}", users_path.display());
    for user in users.iter() {
        let username = user
            .get("name")
            .and_then(Item::as_str)
            .unwrap_or("<unnamed>");
        let home = user.get("home").and_then(Item::as_str).unwrap_or(".");
        println!("\n{username}");
        println!("  home: {home}");
        println!(
            "  permissions: read={}, write={}, delete={}",
            permission_value(user, "read", true),
            permission_value(user, "write", false),
            permission_value(user, "delete", false)
        );

        let keys = load_configured_keys(user, &users_path).await?;
        if keys.is_empty() {
            println!("  keys: none");
        } else {
            println!("  Ed25519 key fingerprints:");
            for key in keys {
                println!(
                    "    {}",
                    key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                );
            }
        }
    }
    Ok(())
}

async fn update_user(args: UpdateUserArgs, users_override: Option<PathBuf>) -> anyhow::Result<()> {
    let username = args.username.trim();
    if username.is_empty() || username.chars().any(char::is_control) {
        bail!("username must be non-empty and contain no control characters");
    }
    let permissions_changed =
        args.read || args.no_read || args.write || args.no_write || args.delete || args.no_delete;
    if args.public_key.is_none() && args.home.is_none() && !permissions_changed {
        bail!("provide at least one field to update");
    }
    if args.home.is_some() && args.root.is_none() {
        bail!("--root is required when changing --home");
    }

    let root = match args.root.as_deref() {
        Some(path) => {
            let canonical = fs::canonicalize(path)
                .await
                .with_context(|| format!("cannot resolve served root {}", path.display()))?;
            if !fs::metadata(&canonical).await?.is_dir() {
                bail!("--root must point to a directory");
            }
            Some(canonical)
        }
        None => None,
    };
    let users_path = resolve_users_path(users_override, root.as_deref()).await?;
    if let Some(root) = root.as_deref() {
        ensure_outside_root(&users_path, root, "users file")?;
    }
    let mut document = load_users_document(&users_path).await?;
    ensure_users_array(&mut document)?;
    let user_index = document["users"]
        .as_array_of_tables()
        .context("the `users` setting must be an array of tables")?
        .iter()
        .position(|user| user.get("name").and_then(Item::as_str) == Some(username))
        .with_context(|| format!("user {username:?} does not exist"))?;

    let home_components = args.home.as_deref().map(validate_home).transpose()?;
    if let (Some(root), Some(home_components)) = (root.as_deref(), home_components.as_deref()) {
        ensure_user_home(root, home_components).await?;
    }

    let mut new_key_path = None;
    let mut new_key_contents = None;
    if let Some(public_key_path) = args.public_key.as_deref() {
        let public_keys = read_public_keys(public_key_path).await?;
        let users_directory = users_path
            .parent()
            .context("users file has no parent directory")?;
        let keys_directory = users_directory.join(AUTHORIZED_KEYS_DIRECTORY);
        let keys_directory = prepare_keys_directory(&keys_directory, root.as_deref()).await?;
        let key_filename = format!("{}.pub", Uuid::new_v4());
        let key_path = keys_directory.join(&key_filename);
        let key_reference = Path::new(AUTHORIZED_KEYS_DIRECTORY)
            .join(&key_filename)
            .to_string_lossy()
            .replace('\\', "/");
        let key_contents = public_keys.join("\n") + "\n";

        let user = document["users"]
            .as_array_of_tables_mut()
            .and_then(|users| users.get_mut(user_index))
            .context("could not locate user entry")?;
        user.remove("authorized_keys");
        user["authorized_keys_file"] = value(key_reference);
        new_key_path = Some(key_path);
        new_key_contents = Some(key_contents);
    }

    let user = document["users"]
        .as_array_of_tables_mut()
        .and_then(|users| users.get_mut(user_index))
        .context("could not locate user entry")?;
    if let Some(home) = args.home.as_deref() {
        user["home"] = value(home.to_string_lossy().as_ref());
    }
    if let Some(value) = requested_boolean(args.read, args.no_read) {
        set_permission(user, "read", value)?;
    }
    if let Some(value) = requested_boolean(args.write, args.no_write) {
        set_permission(user, "write", value)?;
    }
    if let Some(value) = requested_boolean(args.delete, args.no_delete) {
        set_permission(user, "delete", value)?;
    }

    let users_contents = document.to_string();
    if let (Some(key_path), Some(contents)) = (new_key_path.as_deref(), new_key_contents.as_deref())
    {
        atomic_write(key_path, contents.as_bytes()).await?;
    }
    if let Err(error) = atomic_write(&users_path, users_contents.as_bytes()).await {
        if let Some(key_path) = new_key_path {
            let _ = fs::remove_file(key_path).await;
        }
        return Err(error).context("could not update users file");
    }

    println!("Updated jftp user {username:?}.");
    println!("Users file: {}", users_path.display());
    if let Some(key_path) = new_key_path {
        println!("New authorized key file: {}", key_path.display());
    }
    if let Some(root) = root {
        println!("Served root: {}", root.display());
    }
    Ok(())
}

fn requested_boolean(enable: bool, disable: bool) -> Option<bool> {
    if enable {
        Some(true)
    } else if disable {
        Some(false)
    } else {
        None
    }
}

fn set_permission(user: &mut Table, name: &str, permission: bool) -> anyhow::Result<()> {
    match user.get_mut("permissions") {
        Some(Item::Table(table)) => {
            table[name] = value(permission);
        }
        Some(Item::Value(Value::InlineTable(table))) => {
            table.insert(name, Value::from(permission));
        }
        Some(_) => bail!("user permissions must be a TOML table"),
        None => {
            let mut table = Table::new();
            table[name] = value(permission);
            user["permissions"] = Item::Table(table);
        }
    }
    Ok(())
}

fn permission_value(user: &Table, name: &str, default: bool) -> bool {
    match user.get("permissions") {
        Some(Item::Table(table)) => table.get(name).and_then(Item::as_bool).unwrap_or(default),
        Some(Item::Value(Value::InlineTable(table))) => {
            table.get(name).and_then(Value::as_bool).unwrap_or(default)
        }
        _ => default,
    }
}

async fn load_configured_keys(user: &Table, users_path: &Path) -> anyhow::Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    if let Some(item) = user.get("authorized_keys") {
        let key_values = item
            .as_value()
            .and_then(Value::as_array)
            .context("authorized_keys must be an array of public key lines")?;
        for (index, source) in key_values.iter().enumerate() {
            let source = source
                .as_str()
                .context("authorized_keys entries must be strings")?;
            append_parsed_keys(&mut keys, source, "inline authorized_keys", index + 1)?;
        }
    }

    if let Some(item) = user.get("authorized_keys_file") {
        let key_file = item
            .as_str()
            .context("authorized_keys_file must be a path string")?;
        let key_file = resolve_key_reference(users_path, Path::new(key_file));
        let contents = fs::read_to_string(&key_file)
            .await
            .with_context(|| format!("cannot read authorized keys file {}", key_file.display()))?;
        for (index, source) in contents.lines().enumerate() {
            append_parsed_keys(
                &mut keys,
                source,
                &key_file.display().to_string(),
                index + 1,
            )?;
        }
    }
    Ok(keys)
}

fn append_parsed_keys(
    keys: &mut Vec<PublicKey>,
    source: &str,
    description: &str,
    line_number: usize,
) -> anyhow::Result<()> {
    let source = source.trim();
    if source.is_empty() || source.starts_with('#') {
        return Ok(());
    }
    let key = crate::server::parse_public_key_line(source)
        .with_context(|| format!("invalid public key on line {line_number} of {description}"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        bail!("non-Ed25519 public key in {description} on line {line_number}");
    }
    if !keys.contains(&key) {
        keys.push(key);
    }
    Ok(())
}

fn resolve_key_reference(users_path: &Path, reference: &Path) -> PathBuf {
    if reference.is_absolute() {
        reference.to_path_buf()
    } else {
        users_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(reference)
    }
}

fn validate_home(home: &Path) -> anyhow::Result<Vec<std::ffi::OsString>> {
    if home.is_absolute() {
        bail!("--home must be relative to the server's --path");
    }
    let mut components = Vec::new();
    for component in home.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("--home must stay inside the server's --path")
            }
        }
    }
    Ok(components)
}

async fn resolve_users_path(
    override_path: Option<PathBuf>,
    root: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let candidate = match override_path {
        Some(path) => path,
        None => crate::server::default_config_directory()
            .await?
            .join("users.toml"),
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        std::env::current_dir()?.join(candidate)
    };
    let candidate = normalize_path(&candidate);
    if let Some(root) = root {
        ensure_outside_root(&candidate, root, "users file")?;
    }
    let file_name = candidate
        .file_name()
        .context("users file path must include a file name")?
        .to_os_string();
    let parent = candidate
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .await
        .with_context(|| format!("cannot create users directory {}", parent.display()))?;
    let canonical_parent = fs::canonicalize(parent)
        .await
        .with_context(|| format!("cannot resolve users directory {}", parent.display()))?;
    let path = canonical_parent.join(file_name);
    if fs::try_exists(&path).await? {
        let canonical = fs::canonicalize(&path)
            .await
            .with_context(|| format!("cannot resolve users file {}", path.display()))?;
        if !fs::metadata(&canonical).await?.is_file() {
            bail!(
                "users file path is not a regular file: {}",
                canonical.display()
            );
        }
        Ok(canonical)
    } else {
        Ok(path)
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

async fn load_users_document(path: &Path) -> anyhow::Result<DocumentMut> {
    if fs::try_exists(path).await? {
        let contents = fs::read_to_string(path)
            .await
            .with_context(|| format!("cannot read users file {}", path.display()))?;
        contents
            .parse::<DocumentMut>()
            .with_context(|| format!("invalid TOML in {}", path.display()))
    } else {
        Ok(DocumentMut::new())
    }
}

fn ensure_users_array(document: &mut DocumentMut) -> anyhow::Result<()> {
    if document.get("users").is_none() {
        document["users"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    if document["users"].as_array_of_tables().is_none() {
        bail!("the `users` setting must be an array of tables");
    }
    Ok(())
}

fn append_user(
    document: &mut DocumentMut,
    username: &str,
    home: &Path,
    authorized_keys_file: &str,
    read: bool,
    write: bool,
    delete: bool,
) -> anyhow::Result<()> {
    let mut user = Table::new();
    user["name"] = value(username);
    user["home"] = value(home.to_string_lossy().as_ref());
    user["authorized_keys_file"] = value(authorized_keys_file);

    let mut permissions = Table::new();
    permissions["read"] = value(read);
    permissions["write"] = value(write);
    permissions["delete"] = value(delete);
    user["permissions"] = Item::Table(permissions);

    document["users"]
        .as_array_of_tables_mut()
        .context("the `users` setting must be an array of tables")?
        .push(user);
    Ok(())
}

async fn read_public_keys(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("cannot read public-key file {}", path.display()))?;
    let mut public_keys = Vec::new();
    for (line_index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = crate::server::parse_public_key_line(line).with_context(|| {
            format!(
                "invalid OpenSSH public key on line {} of {}",
                line_index + 1,
                path.display()
            )
        })?;
        if key.algorithm() != Algorithm::Ed25519 {
            bail!(
                "only Ed25519 keys are supported (line {} of {})",
                line_index + 1,
                path.display()
            );
        }
        let canonical = key.to_openssh()?;
        if !public_keys.contains(&canonical) {
            public_keys.push(canonical);
        }
    }
    if public_keys.is_empty() {
        bail!("public-key file contains no Ed25519 public keys");
    }
    Ok(public_keys)
}

async fn prepare_keys_directory(path: &Path, root: Option<&Path>) -> anyhow::Result<PathBuf> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => bail!("authorized-key path is not a directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).await.with_context(|| {
                format!("cannot create authorized-key directory {}", path.display())
            })?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("cannot inspect authorized-key directory {}", path.display())
            });
        }
    }
    let canonical = fs::canonicalize(path)
        .await
        .with_context(|| format!("cannot resolve authorized-key directory {}", path.display()))?;
    if let Some(root) = root {
        ensure_outside_root(&canonical, root, "authorized-key directory")?;
    }
    Ok(canonical)
}

async fn ensure_user_home(root: &Path, components: &[std::ffi::OsString]) -> anyhow::Result<()> {
    let mut current = root.to_path_buf();
    for component in components {
        let candidate = current.join(component);
        match fs::canonicalize(&candidate).await {
            Ok(canonical) => {
                ensure_inside_root(&canonical, root)?;
                if !fs::metadata(&canonical).await?.is_dir() {
                    bail!(
                        "user home component is not a directory: {}",
                        canonical.display()
                    );
                }
                current = canonical;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&candidate)
                    .await
                    .with_context(|| format!("cannot create user home {}", candidate.display()))?;
                let canonical = fs::canonicalize(&candidate).await?;
                ensure_inside_root(&canonical, root)?;
                current = canonical;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot resolve user home {}", candidate.display()));
            }
        }
    }
    Ok(())
}

fn ensure_inside_root(path: &Path, root: &Path) -> anyhow::Result<()> {
    if !path.starts_with(root) {
        bail!("path escapes the served root: {}", path.display());
    }
    Ok(())
}

fn ensure_outside_root(path: &Path, root: &Path, description: &str) -> anyhow::Result<()> {
    if path.starts_with(root) {
        bail!(
            "{description} must be outside the served root: {}",
            path.display()
        );
    }
    Ok(())
}

async fn atomic_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("cannot atomically write a path with no parent directory")?;
    let file_name = path
        .file_name()
        .context("cannot atomically write a path with no file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .await
        .with_context(|| format!("cannot create temporary file {}", temporary.display()))?;
    let write_result = async {
        file.write_all(contents).await?;
        file.flush().await?;
        file.sync_all().await
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary).await;
        return Err(error).with_context(|| format!("cannot write {}", temporary.display()));
    }
    if let Err(error) = fs::rename(&temporary, path).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error).with_context(|| format!("cannot replace {}", path.display()));
    }
    Ok(())
}
