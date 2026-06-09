use crossbeam_channel::{Receiver, Sender, unbounded};

#[derive(Debug)]
pub struct LogBuffer {
    sender: Sender<String>,
    receiver: Receiver<String>,
    lines: Vec<String>,
    max_lines: usize,
}

impl Default for LogBuffer {
    fn default() -> Self {
        let (sender, receiver) = unbounded();
        Self {
            sender,
            receiver,
            lines: Vec::new(),
            max_lines: 1_000,
        }
    }
}

impl LogBuffer {
    pub fn sender(&self) -> Sender<String> {
        self.sender.clone()
    }

    pub fn push(&self, line: impl Into<String>) {
        let _ = self.sender.send(line.into());
    }

    pub fn drain(&mut self) {
        while let Ok(line) = self.receiver.try_recv() {
            self.lines.push(line);
        }

        if self.lines.len() > self.max_lines {
            let overflow = self.lines.len() - self.max_lines;
            self.lines.drain(0..overflow);
        }
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}
