use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};

/// A user's virtual filesystem root. Absolute client paths are interpreted from
/// this directory, never from the host's filesystem root.
#[derive(Debug, Clone)]
pub struct PathSecurity {
    home: PathBuf,
}

impl PathSecurity {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn ensure_inside(&self, canonical: &Path) -> anyhow::Result<()> {
        if canonical.starts_with(&self.home) {
            Ok(())
        } else {
            bail!("path escapes this user's home directory")
        }
    }

    /// Build a candidate path from the session CWD. Canonicalize the final
    /// object before use so `..` and symlinks cannot cross the user's boundary.
    pub fn candidate(&self, cwd: &Path, input: &str) -> anyhow::Result<PathBuf> {
        let input_path = Path::new(input);
        let base = if input_path.has_root() {
            &self.home
        } else {
            cwd
        };

        let mut candidate = base.to_path_buf();
        for component in input_path.components() {
            match component {
                Component::Prefix(_) => {
                    bail!("drive and network prefixes are not valid virtual paths")
                }
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => candidate.push(".."),
                Component::Normal(name) => candidate.push(name),
            }
        }
        Ok(candidate)
    }

    pub async fn resolve_existing(&self, cwd: &Path, input: &str) -> anyhow::Result<PathBuf> {
        let candidate = self.candidate(cwd, input)?;
        let canonical = tokio::fs::canonicalize(&candidate)
            .await
            .with_context(|| format!("cannot resolve {}", input))?;
        self.ensure_inside(&canonical)?;
        Ok(canonical)
    }

    /// Resolve the parent of a new file and validate the leaf separately.
    /// Uploads are created with `create_new`, so existing files and symlinks
    /// cannot be overwritten accidentally.
    pub async fn resolve_new_file(
        &self,
        cwd: &Path,
        input: &str,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let (parent, destination) = self.resolve_file_destination(cwd, input).await?;
        if tokio::fs::try_exists(&destination).await? {
            bail!("destination already exists: {}", self.display(&destination));
        }
        Ok((parent, destination))
    }

    pub(crate) async fn resolve_file_destination(
        &self,
        cwd: &Path,
        input: &str,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let candidate = self.candidate(cwd, input)?;
        let leaf = candidate
            .file_name()
            .filter(|name| !name.is_empty())
            .context("a destination file name is required")?;
        if matches!(leaf.to_string_lossy().as_ref(), "." | "..") {
            bail!("a destination file name is required");
        }

        let parent = candidate
            .parent()
            .context("destination has no parent directory")?;
        let canonical_parent = tokio::fs::canonicalize(parent).await.with_context(|| {
            format!("cannot resolve destination directory {}", parent.display())
        })?;
        self.ensure_inside(&canonical_parent)?;
        let destination = canonical_parent.join(leaf);
        Ok((canonical_parent, destination))
    }

    /// Resolve the path prefix for a glob. Individual matches are still
    /// canonicalized and checked before any operation is performed.
    pub fn glob_pattern(&self, cwd: &Path, input: &str) -> anyhow::Result<String> {
        let candidate = self.candidate(cwd, input)?;
        let mut pattern = candidate.to_string_lossy().into_owned();
        if cfg!(windows) {
            pattern = pattern.replace('\\', "/");
        }
        Ok(pattern)
    }

    pub fn display(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(relative) if relative.as_os_str().is_empty() => "/".to_owned(),
            Ok(relative) => format!("/{}", relative.to_string_lossy().replace('\\', "/")),
            Err(_) => "<outside-home>".to_owned(),
        }
    }

    pub fn is_home(&self, canonical: &Path) -> bool {
        canonical == self.home
    }
}
