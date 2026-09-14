//! The refresh progress line.
//!
//! At a terminal it is one line, rewritten in place, as
//! `simple_wallet::refresh_progress_reporter_t` draws it. Anywhere else -- a
//! pipe, a log file, `--command refresh` -- a rewritten line comes out as one
//! line per update, so a line is printed every [`PIPE_INTERVAL`] instead.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use crate::fmt;

/// How often a line is printed where it cannot be rewritten.
const PIPE_INTERVAL: Duration = Duration::from_secs(10);

/// How far back the speed is measured. Blocks near the tip carry far more
/// transactions than the early chain, so an average since the start would
/// promise an ETA the rest of the chain does not keep.
const RATE_WINDOW: Duration = Duration::from_secs(30);

pub struct Progress {
    live: bool,
    /// Width of the line on screen, to blank it out; zero when there is none.
    shown: usize,
    last_line: Option<Instant>,
    samples: VecDeque<(Instant, u64)>,
}

impl Progress {
    pub fn new() -> Progress {
        Progress {
            live: std::io::stdout().is_terminal(),
            shown: 0,
            last_line: None,
            samples: VecDeque::new(),
        }
    }

    /// The wallet has scanned up to `height`, of `target`.
    pub fn update(&mut self, height: u64, target: u64) {
        let now = Instant::now();
        self.samples.push_back((now, height));
        while self.samples.len() > 2 && now.duration_since(self.samples[0].0) > RATE_WINDOW {
            self.samples.pop_front();
        }

        if !self.live
            && self
                .last_line
                .is_some_and(|t| now.duration_since(t) < PIPE_INTERVAL)
        {
            return;
        }
        let line = describe(height, target, self.rate());
        if self.live {
            let mut out = std::io::stdout().lock();
            let _ = write!(out, "\r{line:<width$}", width = self.shown);
            let _ = out.flush();
            self.shown = line.chars().count();
        } else {
            println!("  {line}");
        }
        self.last_line = Some(now);
    }

    /// Take the line off the screen so something else can be printed. The
    /// next update draws it again.
    pub fn clear(&mut self) {
        if self.shown == 0 {
            return;
        }
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "\r{:width$}\r", "", width = self.shown);
        let _ = out.flush();
        self.shown = 0;
    }

    /// Blocks per second over the last [`RATE_WINDOW`], once there is a second
    /// of it to measure.
    fn rate(&self) -> Option<f64> {
        let (t0, h0) = *self.samples.front()?;
        let (t1, h1) = *self.samples.back()?;
        let secs = t1.duration_since(t0).as_secs_f64();
        (secs >= 1.0 && h1 > h0).then(|| (h1 - h0) as f64 / secs)
    }
}

impl Drop for Progress {
    /// A refresh that fails part way must not leave half a line for the error
    /// to be printed over.
    fn drop(&mut self) {
        self.clear();
    }
}

/// `height 512001 / 873792 (58.6%), 1240 blocks/s, 4m 52s left`.
fn describe(height: u64, target: u64, rate: Option<f64>) -> String {
    let target = target.max(height);
    let percent = if target == 0 {
        100.0
    } else {
        height as f64 * 100.0 / target as f64
    };
    let mut line = format!("height {height} / {target} ({percent:.1}%)");
    if let Some(rate) = rate {
        let left = ((target - height) as f64 / rate).round() as u64;
        line.push_str(&format!(
            ", {rate:.0} blocks/s, {} left",
            fmt::duration(left)
        ));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_gains_a_speed_and_a_time_left_once_measured() {
        assert_eq!(
            describe(512_001, 873_792, None),
            "height 512001 / 873792 (58.6%)"
        );
        assert_eq!(
            describe(512_001, 873_792, Some(1_000.0)),
            "height 512001 / 873792 (58.6%), 1000 blocks/s, 6m 2s left"
        );
        // A daemon that fell behind the wallet is not shown as past 100%.
        assert_eq!(describe(10, 5, None), "height 10 / 10 (100.0%)");
    }
}
