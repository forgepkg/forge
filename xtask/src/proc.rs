//! Thin wrappers around `std::process::Command` that stream child output to the
//! caller's stdout/stderr (inherited) and turn a non-zero exit into an `Err`.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// A command builder that remembers a human-readable label for error messages.
pub struct Cmd {
    inner: Command,
    /// What we print if the command fails (e.g. "docker compose up").
    label: String,
}

impl Cmd {
    /// Start a command. `program` is the binary (e.g. "cargo", "docker", "pnpm").
    pub fn new(program: &str) -> Self {
        Cmd {
            inner: Command::new(program),
            label: program.to_string(),
        }
    }

    /// Append a single argument (also extends the label for diagnostics).
    pub fn arg<S: AsRef<OsStr>>(mut self, a: S) -> Self {
        self.label.push(' ');
        self.label.push_str(&a.as_ref().to_string_lossy());
        self.inner.arg(a);
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for a in args {
            self.label.push(' ');
            self.label.push_str(&a.as_ref().to_string_lossy());
            self.inner.arg(a);
        }
        self
    }

    /// Set an environment variable for the child.
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(mut self, k: K, v: V) -> Self {
        self.inner.env(k, v);
        self
    }

    /// Run the child in a different working directory.
    pub fn current_dir<P: AsRef<Path>>(mut self, dir: P) -> Self {
        self.inner.current_dir(dir);
        self
    }

    /// Run, streaming output. Returns `Err` with the label on non-zero exit or
    /// if the binary could not be spawned (e.g. not installed / not on PATH).
    pub fn run(mut self) -> Result<(), String> {
        eprintln!("\x1b[36m$ {}\x1b[0m", self.label);
        let status = self.inner.status().map_err(|e| {
            format!(
                "failed to spawn `{}`: {e} (is it installed and on PATH?)",
                self.label
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "`{}` exited with {}",
                self.label,
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "a signal".to_string())
            ))
        }
    }

    /// Run and capture stdout as a trimmed `String` (used by `seed`). Streams
    /// stderr through so the user still sees progress/errors.
    pub fn output_string(mut self) -> Result<String, String> {
        let out = self
            .inner
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|e| format!("failed to spawn `{}`: {e}", self.label))?;
        if !out.status.success() {
            return Err(format!("`{}` exited unsuccessfully", self.label));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}
