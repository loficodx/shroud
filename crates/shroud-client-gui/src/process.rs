use anyhow::{Context, Result, bail};
use crossbeam_channel::Sender;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;

#[derive(Debug, Default)]
pub struct ClientProcess {
    child: Option<Child>,
}

impl ClientProcess {
    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) | Err(_) => {
                    self.child = None;
                    false
                }
                Ok(None) => true,
            },
            None => false,
        }
    }

    pub fn start(&mut self, config_path: &Path, log_sender: Sender<String>) -> Result<()> {
        if self.is_running() {
            bail!("client process is already running");
        }

        let mut child = Command::new("shroud-client")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| "failed to start shroud-client. Ensure it is available in PATH")?;

        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(stdout, log_sender.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_reader(stderr, log_sender);
        }

        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };

        child.kill().context("failed to stop shroud-client")?;
        let _ = child.wait();
        Ok(())
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
