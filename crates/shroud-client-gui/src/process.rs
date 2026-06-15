use anyhow::{Context, Result, bail};
use crossbeam_channel::Sender;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientProcessState {
    #[default]
    Stopped,
    Starting,
    Running,
    Exited {
        code: Option<i32>,
    },
    Failed {
        error: String,
    },
}

impl ClientProcessState {
    pub fn label(&self) -> String {
        match self {
            Self::Stopped => "stopped".to_string(),
            Self::Starting => "starting".to_string(),
            Self::Running => "running".to_string(),
            Self::Exited { code } => match code {
                Some(code) => format!("exited ({code})"),
                None => "exited".to_string(),
            },
            Self::Failed { error } => format!("failed: {error}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct ClientProcess {
    child: Option<Child>,
    state: ClientProcessState,
    config_path: Option<PathBuf>,
}

impl ClientProcess {
    pub fn is_running(&mut self) -> bool {
        self.refresh_state();
        matches!(
            self.state,
            ClientProcessState::Starting | ClientProcessState::Running
        )
    }

    pub fn state(&mut self) -> ClientProcessState {
        self.refresh_state();
        self.state.clone()
    }

    pub fn running_config_path(&mut self) -> Option<PathBuf> {
        self.refresh_state();
        if matches!(
            self.state,
            ClientProcessState::Starting | ClientProcessState::Running
        ) {
            self.config_path.clone()
        } else {
            None
        }
    }

    fn refresh_state(&mut self) {
        let next_state = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => Some(ClientProcessState::Exited {
                    code: status.code(),
                }),
                Ok(None) => {
                    self.state = ClientProcessState::Running;
                    None
                }
                Err(err) => Some(ClientProcessState::Failed {
                    error: format!("failed to read client process status: {err}"),
                }),
            },
            None => None,
        };

        if let Some(state) = next_state {
            self.child = None;
            self.config_path = None;
            self.state = state;
        }
    }

    pub fn start(&mut self, config_path: &Path, log_sender: Sender<String>) -> Result<()> {
        if self.is_running() {
            bail!("client process is already running");
        }

        self.state = ClientProcessState::Starting;
        self.config_path = None;
        let command = build_client_command(config_path);
        let mut child = spawn_client_command(&command).inspect_err(|err| {
            self.state = ClientProcessState::Failed {
                error: err.to_string(),
            };
            self.config_path = None;
        })?;

        let _ = log_sender.send(format!(
            "launching {} {}",
            command.program.display(),
            config_path.display()
        ));

        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(stdout, log_sender.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_reader(stderr, log_sender);
        }

        self.child = Some(child);
        self.config_path = Some(config_path.to_path_buf());
        self.state = ClientProcessState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            self.state = ClientProcessState::Stopped;
            self.config_path = None;
            return Ok(());
        };

        match child.try_wait() {
            Ok(Some(status)) => {
                self.state = ClientProcessState::Exited {
                    code: status.code(),
                };
                self.config_path = None;
                Ok(())
            }
            Ok(None) => {
                child.kill().context("failed to stop shroud-client")?;
                let _ = child.wait();
                self.state = ClientProcessState::Stopped;
                self.config_path = None;
                Ok(())
            }
            Err(err) => {
                self.state = ClientProcessState::Failed {
                    error: format!("failed to read client process status: {err}"),
                };
                self.config_path = None;
                Err(err).context("failed to read client process status")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientCommand {
    program: PathBuf,
    args: Vec<OsString>,
}

fn build_client_command(config_path: &Path) -> ClientCommand {
    ClientCommand {
        program: resolve_client_binary(),
        args: vec![
            OsString::from("--config"),
            config_path.as_os_str().to_os_string(),
            OsString::from("--log-format"),
            OsString::from("json"),
        ],
    }
}

fn spawn_client_command(command: &ClientCommand) -> Result<Child> {
    let mut process_command = Command::new(&command.program);
    process_command
        .args(&command.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let spawn_error = || {
        format!(
            "failed to start shroud-client via {}. Build shroud-client or ensure it is available in PATH",
            command.program.display()
        )
    };
    process_command.spawn().with_context(spawn_error)
}

fn resolve_client_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| sibling_client_binary(&path))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(client_binary_name()))
}

fn sibling_client_binary(current_exe: &Path) -> Option<PathBuf> {
    current_exe
        .parent()
        .map(|parent| parent.join(client_binary_name()))
}

fn client_binary_name() -> &'static str {
    if cfg!(windows) {
        "shroud-client.exe"
    } else {
        "shroud-client"
    }
}

fn spawn_log_reader<R>(reader: R, sender: Sender<String>)
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let _ = sender.send(line);
                }
                Err(err) => {
                    let _ = sender.send(format!("failed to read client log: {err}"));
                    break;
                }
            }
        }
    });
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientProcess, ClientProcessState, build_client_command, client_binary_name,
        sibling_client_binary,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn process_state_labels_are_human_readable() {
        assert_eq!(ClientProcessState::Stopped.label(), "stopped");
        assert_eq!(ClientProcessState::Starting.label(), "starting");
        assert_eq!(ClientProcessState::Running.label(), "running");
        assert_eq!(
            ClientProcessState::Exited { code: Some(2) }.label(),
            "exited (2)"
        );
        assert_eq!(ClientProcessState::Exited { code: None }.label(), "exited");
        assert_eq!(
            ClientProcessState::Failed {
                error: "boom".to_string()
            }
            .label(),
            "failed: boom"
        );
    }

    #[test]
    fn sibling_client_binary_uses_current_exe_directory() {
        let current = Path::new("/repo/target/debug/shroud-client-gui");

        assert_eq!(
            sibling_client_binary(current),
            Some(PathBuf::from("/repo/target/debug").join(client_binary_name()))
        );
    }

    #[test]
    fn build_client_command_passes_config_path_as_explicit_config_arg() {
        let command = build_client_command(Path::new("configs/client.yaml"));

        assert_eq!(
            command.args,
            vec![
                OsString::from("--config"),
                OsString::from("configs/client.yaml"),
                OsString::from("--log-format"),
                OsString::from("json")
            ]
        );
    }

    #[test]
    fn running_config_path_is_available_only_for_active_process_states() {
        let path = PathBuf::from("configs/client.yaml");
        let mut process = ClientProcess {
            child: None,
            state: ClientProcessState::Running,
            config_path: Some(path.clone()),
        };

        assert_eq!(process.running_config_path(), Some(path));

        process.state = ClientProcessState::Stopped;

        assert_eq!(process.running_config_path(), None);
    }
}
