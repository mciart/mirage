use std::process::Command;
use tracing::{debug, info, warn};

/// Manages lifecycle hooks (PostUp / PostDown scripts).
///
/// Executes user-defined shell commands after the tunnel interface is created
/// (PostUp) and before it is destroyed (PostDown). This follows the same
/// pattern as WireGuard's PostUp/PostDown configuration.
///
/// The `%i` placeholder in commands is replaced with the actual TUN interface
/// name (e.g. "mirage0").
pub struct LifecycleHooks {
    interface_name: String,
    post_down: Vec<String>,
}

impl LifecycleHooks {
    /// Create hooks and immediately execute PostUp commands.
    pub fn run_post_up(
        interface_name: String,
        post_up: &[String],
        post_down: Vec<String>,
    ) -> Self {
        if !post_up.is_empty() {
            info!(
                "Running {} PostUp command(s) for interface {}",
                post_up.len(),
                interface_name
            );
            for cmd in post_up {
                run_hook(&interface_name, cmd);
            }
        }

        Self {
            interface_name,
            post_down,
        }
    }
}

impl Drop for LifecycleHooks {
    fn drop(&mut self) {
        if !self.post_down.is_empty() {
            info!(
                "Running {} PostDown command(s) for interface {}",
                self.post_down.len(),
                self.interface_name
            );
            for cmd in &self.post_down {
                run_hook(&self.interface_name, cmd);
            }
        }
    }
}

/// Execute a single hook command, replacing `%i` with the interface name.
fn run_hook(interface_name: &str, cmd: &str) {
    let expanded = cmd.replace("%i", interface_name);
    debug!("Executing hook: {}", expanded);

    match Command::new("sh").args(["-c", &expanded]).output() {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    debug!("Hook output: {}", stdout.trim());
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Hook command failed: {} — {}", expanded, stderr.trim());
            }
        }
        Err(e) => {
            warn!("Failed to execute hook: {} — {}", expanded, e);
        }
    }
}
