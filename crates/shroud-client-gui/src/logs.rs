use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::VecDeque;

const DEFAULT_MAX_LINES: usize = 5_000;

#[derive(Debug)]
pub struct LogBuffer {
    sender: Sender<String>,
    receiver: Receiver<String>,
    lines: VecDeque<String>,
    max_lines: usize,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::with_max_lines(DEFAULT_MAX_LINES)
    }
}

impl LogBuffer {
    fn with_max_lines(max_lines: usize) -> Self {
        let (sender, receiver) = unbounded();
        Self {
            sender,
            receiver,
            lines: VecDeque::new(),
            max_lines,
        }
    }

    pub fn sender(&self) -> Sender<String> {
        self.sender.clone()
    }

    pub fn push(&self, line: impl Into<String>) {
        let _ = self.sender.send(line.into());
    }

    pub fn drain(&mut self) -> usize {
        let mut drained = 0;
        while let Ok(line) = self.receiver.try_recv() {
            self.lines.push_back(line);
            drained += 1;
        }

        if self.lines.len() > self.max_lines {
            let overflow = self.lines.len() - self.max_lines;
            self.lines.drain(0..overflow);
        }

        drained
    }

    pub fn clear(&mut self) {
        while self.receiver.try_recv().is_ok() {}
        self.lines.clear();
    }

    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::LogBuffer;

    #[test]
    fn drain_moves_pending_lines_into_text() {
        let mut logs = LogBuffer::with_max_lines(10);

        logs.push("one");
        logs.push("two");

        assert_eq!(logs.drain(), 2);
        assert_eq!(logs.text(), "one\ntwo");
    }

    #[test]
    fn drain_keeps_only_newest_lines_when_capacity_is_exceeded() {
        let mut logs = LogBuffer::with_max_lines(3);

        for index in 0..5 {
            logs.push(format!("line {index}"));
        }

        assert_eq!(logs.drain(), 5);
        assert_eq!(logs.text(), "line 2\nline 3\nline 4");
    }

    #[test]
    fn clear_removes_rendered_and_pending_lines() {
        let mut logs = LogBuffer::with_max_lines(10);

        logs.push("rendered");
        logs.drain();
        logs.push("pending");

        logs.clear();

        assert_eq!(logs.drain(), 0);
        assert_eq!(logs.text(), "");
    }
}
