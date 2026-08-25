//! IEEE 802.1CB-2017 Section 7.4 — Sequence Recovery Function (SRF).
//!
//! The Sequence Recovery Function is the receive-side algorithm that accepts
//! the first copy of each R-TAG–labelled frame and eliminates late/duplicate
//! copies across redundant TSN paths.  This module implements the **Vector
//! Recovery Algorithm** (VRA) per Section 7.4.3.1 with:
//!
//! * A sliding **SequenceHistory** bit-vector of width `history_length`
//!   (default 128 entries).
//! * **RecovSeqNum** tracking the next expected sequence number.
//! * Wrap-around safe 16-bit serial-number arithmetic (RFC 1982).
//! * Configurable `take_any` flag for initial learning.
//! * Per-stream statistics: accepted, out-of-order, duplicate, rogue.

/// 16-bit serial-number comparison (RFC 1982 / IEEE 802.1CB).
/// Returns `true` when `a` is "less than" `b` in circular space.
#[inline]
pub fn seq_lt(a: u16, b: u16) -> bool {
    let diff = a.wrapping_sub(b);
    diff != 0 && (diff & 0x8000) != 0
}

/// Returns the signed distance from `a` to `b` in sequence space.
#[inline]
pub fn seq_distance(a: u16, b: u16) -> i32 {
    let d = b.wrapping_sub(a);
    if d <= 0x7FFF {
        d as i32
    } else {
        d as i32 - 0x10000
    }
}

// ── Sequence History bit-vector ──────────────────────────────────────────

/// Fixed-width history recording which of the last `len` sequence numbers
/// have been seen. Index 0 corresponds to `RecovSeqNum - 1`, index 1 to
/// `RecovSeqNum - 2`, etc.
#[derive(Debug, Clone)]
pub struct SequenceHistory {
    seen: Vec<bool>,
}

impl SequenceHistory {
    pub fn new(history_length: usize) -> Self {
        SequenceHistory {
            seen: vec![false; history_length],
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if bit `idx` is set (already seen).
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        if idx < self.seen.len() {
            self.seen[idx]
        } else {
            false
        }
    }

    /// Sets bit `idx`.
    #[inline]
    pub fn set(&mut self, idx: usize) {
        if idx < self.seen.len() {
            self.seen[idx] = true;
        }
    }

    /// Shifts the entire history right by `count` positions (new lower index
    /// entries become false), which corresponds to advancing RecovSeqNum
    /// forward by `count`.
    pub fn shift_right(&mut self, count: usize) {
        let n = self.seen.len();
        if count >= n {
            self.seen.fill(false);
        } else {
            for i in (count..n).rev() {
                self.seen[i] = self.seen[i - count];
            }
            for i in 0..count {
                self.seen[i] = false;
            }
        }
    }
}

// ── SRF per-stream state ─────────────────────────────────────────────────

/// Per-stream Sequence Recovery Function statistics.
#[derive(Debug, Clone, Default)]
pub struct SrfStats {
    pub accepted: u64,
    pub out_of_order_accepted: u64,
    pub duplicates_eliminated: u64,
    pub rogue_dropped: u64,
}

/// Result of processing an incoming R-TAG sequence number through the SRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrfVerdict {
    /// Frame accepted — first copy, deliver to upper layer.
    Accept,
    /// Frame accepted but arrived out-of-order within the history window.
    AcceptOutOfOrder,
    /// Frame eliminated — duplicate of an already-accepted sequence.
    EliminateDuplicate,
    /// Frame dropped — sequence number too old (outside the history window).
    DropRogue,
}

/// IEEE 802.1CB Section 7.4 Vector Recovery Algorithm (VRA).
///
/// Each FRER compound stream should have its own `SrfInstance`.
#[derive(Debug, Clone)]
pub struct SrfInstance {
    /// The next expected sequence number (head of the window).
    pub recv_seq: u16,
    /// Bit-vector history of recently-seen sequence numbers.
    pub history: SequenceHistory,
    /// When `true`, the next frame will be unconditionally accepted and its
    /// sequence number will become the new `recv_seq`.  Resets to `false`
    /// after the first frame.
    pub take_any: bool,
    /// Counters.
    pub stats: SrfStats,
}

impl SrfInstance {
    /// Creates a new SRF instance with the given history window width.
    pub fn new(history_length: usize) -> Self {
        SrfInstance {
            recv_seq: 0,
            history: SequenceHistory::new(history_length),
            take_any: true,
            stats: SrfStats::default(),
        }
    }

    /// Processes an incoming frame's R-TAG sequence number and returns
    /// the verdict.
    pub fn process(&mut self, seq: u16) -> SrfVerdict {
        // ── TakeAny learning mode ────────────────────────────────
        if self.take_any {
            self.take_any = false;
            self.recv_seq = seq.wrapping_add(1);
            self.history = SequenceHistory::new(self.history.len());
            self.history.set(0);
            self.stats.accepted += 1;
            return SrfVerdict::Accept;
        }

        let delta = seq_distance(self.recv_seq, seq);

        if delta >= 0 {
            // ── Sequence is at or ahead of RecovSeqNum ───────────
            // Advance the window: shift history right by (delta + 1),
            // and mark the current seq as seen at bit 0.
            let advance = delta as usize + 1;
            self.history.shift_right(advance);
            self.history.set(0);
            self.recv_seq = seq.wrapping_add(1);
            self.stats.accepted += 1;
            if delta > 0 {
                self.stats.out_of_order_accepted += 1;
                SrfVerdict::AcceptOutOfOrder
            } else {
                SrfVerdict::Accept
            }
        } else {
            // ── Sequence is behind RecovSeqNum ───────────────────
            let behind = (-delta) as usize; // how many positions behind
            let idx = behind - 1; // history index (0 = recv_seq - 1)

            if idx >= self.history.len() {
                // Too old — outside the history window.
                self.stats.rogue_dropped += 1;
                return SrfVerdict::DropRogue;
            }

            if self.history.get(idx) {
                // Already seen — duplicate.
                self.stats.duplicates_eliminated += 1;
                SrfVerdict::EliminateDuplicate
            } else {
                // Not yet seen — accept out-of-order within window.
                self.history.set(idx);
                self.stats.accepted += 1;
                self.stats.out_of_order_accepted += 1;
                SrfVerdict::AcceptOutOfOrder
            }
        }
    }

    /// Resets the SRF to initial learning state.
    pub fn reset(&mut self) {
        self.take_any = true;
        self.recv_seq = 0;
        self.history = SequenceHistory::new(self.history.len());
        self.stats = SrfStats::default();
    }
}

// ── Multi-stream SRF engine ──────────────────────────────────────────────

/// Manages SRF instances for multiple compound streams keyed by `stream_handle`.
#[derive(Debug, Clone)]
pub struct FrerSrfEngine {
    pub streams: Vec<(u32, SrfInstance)>,
    pub default_history_len: usize,
}

impl FrerSrfEngine {
    pub fn new(default_history_len: usize) -> Self {
        FrerSrfEngine {
            streams: Vec::new(),
            default_history_len,
        }
    }

    /// Registers or retrieves the SRF instance for `stream_handle`.
    pub fn get_or_create(&mut self, stream_handle: u32) -> &mut SrfInstance {
        let pos = self.streams.iter().position(|(h, _)| *h == stream_handle);
        match pos {
            Some(i) => &mut self.streams[i].1,
            None => {
                self.streams
                    .push((stream_handle, SrfInstance::new(self.default_history_len)));
                let last = self.streams.len() - 1;
                &mut self.streams[last].1
            }
        }
    }

    /// Processes an incoming R-TAG frame for the given stream.
    pub fn process_frame(&mut self, stream_handle: u32, seq: u16) -> SrfVerdict {
        let srf = self.get_or_create(stream_handle);
        srf.process(seq)
    }

    /// Returns summary statistics across all streams.
    pub fn total_stats(&self) -> SrfStats {
        let mut total = SrfStats::default();
        for (_, srf) in &self.streams {
            total.accepted += srf.stats.accepted;
            total.out_of_order_accepted += srf.stats.out_of_order_accepted;
            total.duplicates_eliminated += srf.stats.duplicates_eliminated;
            total.rogue_dropped += srf.stats.rogue_dropped;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_lt_wraparound() {
        assert!(seq_lt(0xFFFF, 0x0000));
        assert!(seq_lt(0x7FFF, 0x8000));
        assert!(!seq_lt(0x8000, 0x7FFF));
        assert!(!seq_lt(5, 5));
    }

    #[test]
    fn test_srf_in_order_stream() {
        let mut srf = SrfInstance::new(128);
        assert_eq!(srf.process(100), SrfVerdict::Accept); // take_any
        assert_eq!(srf.process(101), SrfVerdict::Accept);
        assert_eq!(srf.process(102), SrfVerdict::Accept);
        assert_eq!(srf.stats.accepted, 3);
        assert_eq!(srf.stats.out_of_order_accepted, 0);
    }

    #[test]
    fn test_srf_duplicate_elimination() {
        let mut srf = SrfInstance::new(128);
        assert_eq!(srf.process(10), SrfVerdict::Accept);
        assert_eq!(srf.process(11), SrfVerdict::Accept);
        assert_eq!(srf.process(11), SrfVerdict::EliminateDuplicate);
        assert_eq!(srf.stats.duplicates_eliminated, 1);
    }

    #[test]
    fn test_srf_out_of_order_within_window() {
        let mut srf = SrfInstance::new(128);
        srf.process(100); // take_any
        srf.process(101); // in-order
        srf.process(103); // skip 102
        // Now 102 arrives late
        assert_eq!(srf.process(102), SrfVerdict::AcceptOutOfOrder);
        assert_eq!(srf.stats.out_of_order_accepted, 2); // 103 also counted
    }

    #[test]
    fn test_srf_rogue_too_old() {
        let mut srf = SrfInstance::new(8);
        srf.process(0); // take_any
        // Advance well past the window
        for i in 1u16..20 {
            srf.process(i);
        }
        // Sequence 0 is now way outside the 8-entry window
        assert_eq!(srf.process(0), SrfVerdict::DropRogue);
    }

    #[test]
    fn test_srf_wraparound() {
        let mut srf = SrfInstance::new(128);
        srf.process(0xFFFE); // take_any
        assert_eq!(srf.process(0xFFFF), SrfVerdict::Accept);
        assert_eq!(srf.process(0x0000), SrfVerdict::Accept);
        assert_eq!(srf.process(0x0001), SrfVerdict::Accept);
        assert_eq!(srf.stats.accepted, 4);
    }
}
