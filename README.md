# jftp — JSONL File Transfer Protocol

**jftp** stands for **JSONL File Transfer Protocol**. It is a stateful file transfer and remote file management protocol carried over an authenticated SSH `jftp` subsystem. Control commands, listings, search results, and progress updates use JSON Lines (one JSON object per line); file contents stream as raw bytes in bounded chunks. SSH transport, key exchange, encryption, and signature verification are handled by `russh`.

This package provides three binaries: `jftp-server` serves a configured directory, `jftp-server-admin` manages the server's local user configuration, and `jftp` connects for interactive or command-driven use.

## Build

```powershell
cargo build --release
```

This creates `jftp-server`, `jftp-server-admin`, and `jftp` in Cargo's release output directory.

## Create a server user

Create an Ed25519 client key if you do not already have one:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Create the directory the server will expose, then add a user from the machine where the server configuration is stored:

```sh
mkdir -p ./shared
jftp-server-admin add-user alice --public-key ~/.ssh/id_ed25519.pub --root ./shared --home alice --write --delete
```

On Windows PowerShell, use:

```powershell
New-Item -ItemType Directory -Force .\shared
jftp-server-admin add-user alice --public-key "$env:USERPROFILE\.ssh\id_ed25519.pub" --root .\shared --home alice --write --delete
```

`--public-key` points to the client `.pub` file; the admin tool validates that it contains Ed25519 public keys, then copies them into its managed key directory and updates `users.toml` (creating the file if needed). The private key stays on the client. `--root` must match the server's `--path`; when `--home` names a subdirectory, `--root` is required and the tool creates the home directory if needed. Read access is enabled by default; pass `--write` and `--delete` only when those permissions are needed. Use `--no-read` to disable read access.

By default, the admin tool and server use the same per-user config directory:

- Linux/macOS: `$XDG_CONFIG_HOME/jftp`, or `~/.config/jftp`
- Windows: `%APPDATA%\jftp`

If you use a custom users file, pass the same `--users <file>` path to both commands. Use an absolute path if you run the commands from different working directories. For example, `jftp-server-admin --users ./config/users.toml add-user ...` and `jftp-server --users ./config/users.toml ...`. The users file, managed public-key files, and SSH host private key must stay outside the served `--path`. The admin tool checks this when you pass `--root`; the server always checks it at startup.

Start the server:

```sh
jftp-server --port 2222 --path ./shared
```

`--path` defaults to the process's current working directory. `home` in `users.toml` is a relative directory below `--path`; each account is confined to that canonical home directory. Absolute client paths are virtual paths from that home, so `/` means the account's home.

The server reads `users.toml` at startup. Restart it after adding or updating a user so the changes take effect. `jftp-server-admin` is a local configuration tool; it does not add a remote user-management command to the SSH protocol.

## List and update users

List configured accounts, their home directories, permissions, and public-key fingerprints:

```powershell
.\jftp-server-admin list-users
```

Update only the fields you specify. For example, change a user's home and grant write access:

```powershell
.\jftp-server-admin update-user jari --root C:\tmp --home jftp-users\jari --write
```

Change permissions with `--read`/`--no-read`, `--write`/`--no-write`, and `--delete`/`--no-delete`. Rotate the user's accepted keys by passing `--public-key <file>`; this replaces the previous authorized key list. Changing `--home` requires `--root`, which must match the server's `--path`; the new home is created if it does not exist.

Example account when configuring `users.toml` by hand:

```toml
[[users]]
name = "alice"
home = "."
authorized_keys_file = "alice.pub"

[users.permissions]
read = true
write = true
delete = true
```

The `--users` and `--host-key` flags can select other paths; the server rejects those files if they are under the served root. Password authentication is disabled. Only Ed25519 user keys are accepted.

`authorized_keys_file` may be an absolute path or a path relative to `users.toml`. It accepts one OpenSSH public key per line; blank lines and lines beginning with `#` are ignored. The server loads the file at startup. For small setups, you can still put keys directly in `authorized_keys = ["ssh-ed25519 ..."]` instead.

## Trust the server host key

On first connection, `jftp` shows the server key fingerprint and asks whether to trust it. Verify the fingerprint through a trusted channel before answering `yes`; accepted keys are added to the client's OpenSSH `known_hosts` file. A declined prompt does not save the key. If a previously trusted host presents a different key, the client refuses the connection and requires you to verify and update `known_hosts` manually.

For a non-default port, the saved known-hosts line has this form:

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
