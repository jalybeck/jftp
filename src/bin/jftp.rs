use std::path::PathBuf;

use clap::{Parser, Subcommand};
use jftp::client::{self, ClientCommand, ConnectionOptions};

#[derive(Debug, Parser)]
#[command(
    name = "jftp",
    about = "Transfer files and manage a remote directory over SSH"
)]
struct Args {
    /// SSH server host name or IP address.
    host: String,

    /// SSH port.
    #[arg(long, default_value_t = 2222)]
    port: u16,

    /// Authorized server-side account name.
    #[arg(long)]
    user: String,

    /// Local Ed25519 private key. Defaults to ~/.ssh/id_ed25519.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// OpenSSH known_hosts file. Defaults to ~/.ssh/known_hosts.
    #[arg(long)]
    known_hosts: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Stream a directory listing.
    List { path: Option<String> },
    /// Delete files matched by a server-side glob. Ctrl+C requests cancellation.
    Rm { path: String },
    /// Upload a local file to a new remote path.
    Upload { local: PathBuf, remote: String },
    /// Download a remote file to a new local path.
    Download { remote: String, local: PathBuf },
    /// Search recursively by file or directory name.
    Search { query: String, path: Option<String> },
    /// Print the session's virtual working directory.
    Pwd,
    /// Change the session's virtual working directory.
    Cd { path: String },
    /// Create a directory.
    Mkdir { path: String },
}

impl From<Command> for ClientCommand {
    fn from(command: Command) -> Self {
        match command {
            Command::List { path } => Self::List { path },
            Command::Rm { path } => Self::Rm {
                path,
                recursive: true,
            },
            Command::Upload { local, remote } => Self::Upload { local, remote },
            Command::Download { remote, local } => Self::Download { remote, local },
            Command::Search { query, path } => Self::Search { query, path },
            Command::Pwd => Self::Pwd,
            Command::Cd { path } => Self::Cd { path },
            Command::Mkdir { path } => Self::Mkdir { path },
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ssh_directory = client::default_ssh_directory()?;
    let identity_file = args
        .identity
        .unwrap_or_else(|| ssh_directory.join("id_ed25519"));
    let known_hosts_file = match args.known_hosts {
        Some(path) => path,
        None => ssh_directory.join("known_hosts"),
    };
    let options = ConnectionOptions {
        host: args.host.clone(),
        port: args.port,
        username: args.user,
        identity_file,
        known_hosts_file,
    };
    let mut session = client::connect(&options, (args.host.as_str(), args.port)).await?;
    match args.command {
        Some(command) => {
            session.run_command(command.into()).await?;
        }
        None => client::run_interactive(&mut session).await?,
    }
    Ok(())
}
