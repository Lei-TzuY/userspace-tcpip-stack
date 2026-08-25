from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# IEEE 802.1Qav: timestamp zero is a valid simulation instant.  The old code
# used last_update_ns == 0 as an uninitialised sentinel, so a frame that began
# transmission at t=0 lost its entire first credit-depletion interval.
replace_once(
    "src/tsn_qav_cbs.rs",
    """    /// Last simulation timestamp in nanoseconds.\n    pub last_update_ns: u64,\n    /// Number of queued frames.\n""",
    """    /// Last simulation timestamp in nanoseconds.\n    pub last_update_ns: u64,\n    /// Whether `last_update_ns` has been initialised. Timestamp zero is valid,\n    /// so it cannot double as an uninitialised sentinel.\n    time_initialized: bool,\n    /// Number of queued frames.\n""",
)
replace_once(
    "src/tsn_qav_cbs.rs",
    """            current_credit: 0,\n            last_update_ns: 0,\n            queued_frames: Vec::new(),\n""",
    """            current_credit: 0,\n            last_update_ns: 0,\n            time_initialized: false,\n            queued_frames: Vec::new(),\n""",
)
replace_once(
    "src/tsn_qav_cbs.rs",
    """    pub fn advance_time(&mut self, now_ns: u64) {\n        if self.last_update_ns == 0 {\n            self.last_update_ns = now_ns;\n            return;\n        }\n\n        let delta_ns = now_ns.saturating_sub(self.last_update_ns) as i64;\n""",
    """    pub fn advance_time(&mut self, now_ns: u64) {\n        if !self.time_initialized {\n            self.last_update_ns = now_ns;\n            self.time_initialized = true;\n            return;\n        }\n\n        let delta_ns = now_ns.saturating_sub(self.last_update_ns) as i64;\n""",
)

# IEEE 802.1Qcr: coarse simulation steps must not add artificial latency.  A
# frame that became eligible at 10us but is observed by the simulator at 100us
# actually departed at its eligibility time, not at the polling time.  Carry
# that exact departure time into the next-hop arrival calculation.
replace_once(
    "src/tsn_ats_multihop.rs",
    """                for frame in ready_frames {\n                    let next_arrival = current_time_ns + latency;\n                    self.hops[i + 1].ingest_frame(frame, next_arrival);\n                }\n""",
    """                for frame in ready_frames {\n                    let next_arrival = frame.eligibility_time_ns.saturating_add(latency);\n                    self.hops[i + 1].ingest_frame(frame, next_arrival);\n                }\n""",
)

print("TSN baseline fixes applied")
