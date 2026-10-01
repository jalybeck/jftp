# jftp — JSONL File Transfer Protocol

**jftp** stands for **JSONL File Transfer Protocol**. It is a stateful file transfer and remote file management protocol carried over an authenticated SSH `jftp` subsystem. Control commands, listings, search results, and progress updates use JSON Lines (one JSON object per line); file contents stream as raw bytes in bounded chunks. SSH transport, key exchange, encryption, and signature verification are handled by `russh`.

This package provides two binaries: `jftp-server`, which serves a configured directory, and `jftp`, which connects to the server for interactive or command-driven use.

## Build

```powershell
cargo build --release
```

This creates `jftp-server` and `jftp` in Cargo's release output directory.

## Configure the server

Create an Ed25519 client key if you do not already have one:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Copy `users.example.toml` to the server's jftp config directory and replace the example public key with the contents of `id_ed25519.pub`:

- Linux/macOS: `$XDG_CONFIG_HOME/jftp/users.toml`, or `~/.config/jftp/users.toml`
- Windows: `%APPDATA%\jftp\users.toml`

The server config and SSH host private key must stay outside the served `--path`. By default the host key is created once in the same config directory and reused on later starts. The initial server run prints its SHA-256 host key fingerprint and OpenSSH public key.

Start the server:

```sh
jftp-server --port 2222 --path ./shared
```

`--path` defaults to the process's current working directory. `home` in `users.toml` is a relative directory below `--path`; each account is confined to that canonical home directory. Absolute client paths are virtual paths from that home, so `/` means the account's home.

Example account:

```toml
[[users]]
name = "alice"
home = "."
authorized_keys = ["ssh-ed25519 AAAAC3... alice@client"]

[users.permissions]
read = true
write = true
delete = true
```

The `--users` and `--host-key` flags can select other paths; the server rejects those files if they are under the served root. Password authentication is disabled. Only Ed25519 user keys are accepted.

## Trust the server host key

Before connecting, add a known server host key to the client's OpenSSH `known_hosts` file. Verify the fingerprint printed by the server through a trusted channel before accepting the key. For a non-default port, a known-hosts line has this form:

```text
[server.example]:2222 ssh-ed25519 BASE64_KEY
```

The default file is `~/.ssh/known_hosts`; choose another with `--known-hosts`. Unknown or changed host keys are rejected.

## Use the client

Open an interactive session (CWD persists for this SSH connection):

```sh
jftp server.example --port 2222 --user alice
```

The client defaults to `~/.ssh/id_ed25519`; choose another Ed25519 identity with `--identity`. Encrypted keys prompt for their passphrase. Interactive commands are `list`, `search`, `cd`, `pwd`, `mkdir`, `rm`, `upload`, `download`, and `exit`. Press Ctrl+C during `rm` to request cancellation while the server streams per-item progress.

Commands can also run in a single SSH session:

```sh
jftp server.example --port 2222 --user alice list /
jftp server.example --port 2222 --user alice rm '/logs/*.tmp'
jftp server.example --port 2222 --user alice upload ./report.csv /reports/report.csv
jftp server.example --port 2222 --user alice download /reports/archive.zip ./archive.zip
```

Uploads and downloads stream in 64 KiB chunks and use the declared byte count to switch between JSONL and raw data. Uploads publish atomically after the exact byte count arrives. Both local downloads and remote uploads refuse to overwrite an existing destination.

## JSONL session protocol

Open an authenticated SSH session channel and request the subsystem `jftp`. Send one JSON object plus `\n` per command. Each response or progress update is one JSON object plus `\n`. Commands include `list`, `search`, `pwd`, `cd`, `mkdir`, `rm`, `cancel`, `upload`, and `download`.

For a file transfer, the `ready` event declares `transfer` and `size`. The sender or receiver then moves exactly that many raw bytes over the channel before JSONL resumes. For example, an upload request looks like:

```json
{"id":"request-1","command":"upload","path":"/report.csv","size":1234}
```

The server responds with `ready`, receives exactly 1234 bytes, then emits `done`. Downloads use the same handshake in the opposite direction. This avoids Base64 and keeps file memory bounded to one chunk.
