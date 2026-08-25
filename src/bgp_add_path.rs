//! BGP ADD-PATH Capability & Multi-Path Decision Engine (RFC 7911 / RFC 8277).
//!
//! Implements BGP Multiple Paths advertisement (Capability Code 69), 4-byte Path-ID
//! prefix encoding/decoding, multi-path RIB storage, and BGP Prefix Independent
//! Convergence (BGP PIC Edge/Core) for fast link/node failover.

use crate::bgp::{AsPath, BgpOrigin, Ipv4Prefix};
use crate::bgp_caps::AfiSafi;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// BGP Capability Code for ADD-PATH (RFC 7911 Section 4).
pub const BGP_CAP_ADD_PATH: u8 = 69;

/// Send/Receive mode for ADD-PATH per address family (RFC 7911 Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddPathMode {
    /// Speaker can receive multiple paths from its peer (Value 1).
    Receive = 1,
    /// Speaker can send multiple paths to its peer (Value 2).
    Send = 2,
    /// Speaker can both send and receive multiple paths (Value 3).
    Both = 3,
}

impl AddPathMode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(AddPathMode::Receive),
            2 => Some(AddPathMode::Send),
            3 => Some(AddPathMode::Both),
            _ => None,
        }
    }

    pub fn can_send(&self) -> bool {
        matches!(self, AddPathMode::Send | AddPathMode::Both)
    }

    pub fn can_receive(&self) -> bool {
        matches!(self, AddPathMode::Receive | AddPathMode::Both)
    }
}

/// One ADD-PATH tuple in the Capability parameter: (AFI, SAFI, Send/Receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPathFamily {
    pub afi_safi: AfiSafi,
    pub mode: AddPathMode,
}

/// BGP ADD-PATH Capability container.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpAddPathCapability {
    pub families: Vec<AddPathFamily>,
}

impl BgpAddPathCapability {
    pub fn new() -> Self {
        BgpAddPathCapability {
            families: Vec::new(),
        }
    }

    pub fn with_family(mut self, afi_safi: AfiSafi, mode: AddPathMode) -> Self {
        self.families.push(AddPathFamily { afi_safi, mode });
        self
    }

    /// Serializes the Capability Value for Capability Code 69 (4 bytes per family).
    pub fn encode_value(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.families.len() * 4);
        for f in &self.families {
            buf.extend_from_slice(&f.afi_safi.afi.to_be_bytes());
            buf.push(f.afi_safi.safi);
            buf.push(f.mode as u8);
        }
        buf
    }

    /// Parses the Capability Value from raw capability bytes.
    pub fn decode_value(buf: &[u8]) -> Option<Self> {
        if buf.len() % 4 != 0 {
            return None;
        }
        let mut families = Vec::new();
        for chunk in buf.chunks_exact(4) {
            let afi = u16::from_be_bytes([chunk[0], chunk[1]]);
            let safi = chunk[2];
            let mode = AddPathMode::from_u8(chunk[3])?;
            families.push(AddPathFamily {
                afi_safi: AfiSafi::new(afi, safi),
                mode,
            });
        }
        Some(BgpAddPathCapability { families })
    }

    /// Intersects local and remote ADD-PATH capabilities to determine active transmission modes.
    ///
    /// Local SEND is enabled if local has Send/Both and peer has Receive/Both.
    /// Local RECEIVE is enabled if local has Receive/Both and peer has Send/Both.
    pub fn negotiate(&self, peer: &BgpAddPathCapability, family: AfiSafi) -> (bool, bool) {
        let local_mode = self
            .families
            .iter()
            .find(|f| f.afi_safi == family)
            .map(|f| f.mode);
        let peer_mode = peer
            .families
            .iter()
            .find(|f| f.afi_safi == family)
            .map(|f| f.mode);

        match (local_mode, peer_mode) {
            (Some(loc), Some(rem)) => {
                let local_send = loc.can_send() && rem.can_receive();
                let local_recv = loc.can_receive() && rem.can_send();
                (local_send, local_recv)
            }
            _ => (false, false),
        }
    }
}

/// An NLRI or Withdrawn route carrying a 4-octet Path Identifier (RFC 7911 Section 3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddPathNlri {
    pub path_id: u32,
    pub prefix: Ipv4Prefix,
}

impl AddPathNlri {
    pub fn new(path_id: u32, prefix: Ipv4Prefix) -> Self {
        AddPathNlri { path_id, prefix }
    }

    /// Encodes Path-ID (4 bytes) + prefix length (1 byte) + prefix octets.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 4);
        buf.extend_from_slice(&self.path_id.to_be_bytes());
        buf.push(self.prefix.length);
        let bytes_needed = ((self.prefix.length + 7) / 8) as usize;
        buf.extend_from_slice(&self.prefix.address.0[..bytes_needed]);
        buf
    }

    /// Decodes a single ADD-PATH NLRI from a slice, returning the NLRI and bytes consumed.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 5 {
            return None;
        }
        let path_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let prefix_len = buf[4];
        if prefix_len > 32 {
            return None;
        }
        let bytes_needed = ((prefix_len + 7) / 8) as usize;
        if buf.len() < 5 + bytes_needed {
            return None;
        }

        let mut addr_bytes = [0u8; 4];
        addr_bytes[..bytes_needed].copy_from_slice(&buf[5..5 + bytes_needed]);
        let prefix = Ipv4Prefix::new(Ipv4Address(addr_bytes), prefix_len);

        Some((AddPathNlri { path_id, prefix }, 5 + bytes_needed))
    }

    /// Decodes multiple ADD-PATH NLRIs from a byte slice.
    pub fn decode_all(mut buf: &[u8]) -> Result<Vec<Self>, String> {
        let mut result = Vec::new();
        while !buf.is_empty() {
            match Self::decode(buf) {
                Some((nlri, consumed)) => {
                    result.push(nlri);
                    buf = &buf[consumed..];
                }
                None => return Err("Malformed ADD-PATH NLRI sequence".to_string()),
            }
        }
        Ok(result)
    }
}

/// One path entry stored in the ADD-PATH RIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPathRibEntry {
    pub path_id: u32,
    pub peer_ip: Ipv4Address,
    pub next_hop: Ipv4Address,
    pub as_path: AsPath,
    pub origin: BgpOrigin,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub is_best: bool,
    pub is_backup: bool,
}

impl AddPathRibEntry {
    pub fn new(path_id: u32, peer_ip: Ipv4Address, next_hop: Ipv4Address, as_path: AsPath) -> Self {
        AddPathRibEntry {
            path_id,
            peer_ip,
            next_hop,
            as_path,
            origin: BgpOrigin::Igp,
            local_pref: Some(100),
            med: None,
            is_best: false,
            is_backup: false,
        }
    }
}

/// Multi-Path Routing Information Base with BGP PIC (Prefix Independent Convergence).
#[derive(Debug, Clone, Default)]
pub struct AddPathRib {
    pub routes: HashMap<Ipv4Prefix, Vec<AddPathRibEntry>>,
    pub max_paths_per_prefix: usize,
}

impl AddPathRib {
    pub fn new(max_paths_per_prefix: usize) -> Self {
        AddPathRib {
            routes: HashMap::new(),
            max_paths_per_prefix: max_paths_per_prefix.max(1),
        }
    }

    /// Inserts or updates a path for a prefix with a given `(peer_ip, path_id)`.
    pub fn insert_path(&mut self, prefix: Ipv4Prefix, entry: AddPathRibEntry) {
        let list = self.routes.entry(prefix).or_default();
        if let Some(pos) = list
            .iter()
            .position(|e| e.peer_ip == entry.peer_ip && e.path_id == entry.path_id)
        {
            list[pos] = entry;
        } else {
            list.push(entry);
        }
        self.recompute_decision(prefix);
    }

    /// Withdraws a specific path identified by `(peer_ip, path_id)`.
    pub fn withdraw_path(
        &mut self,
        prefix: &Ipv4Prefix,
        peer_ip: Ipv4Address,
        path_id: u32,
    ) -> bool {
        if let Some(list) = self.routes.get_mut(prefix) {
            let initial_len = list.len();
            list.retain(|e| !(e.peer_ip == peer_ip && e.path_id == path_id));
            if list.len() < initial_len {
                if list.is_empty() {
                    self.routes.remove(prefix);
                } else {
                    self.recompute_decision(*prefix);
                }
                return true;
            }
        }
        false
    }

    /// Recomputes primary best path and BGP PIC backup path for a prefix.
    pub fn recompute_decision(&mut self, prefix: Ipv4Prefix) {
        let list = match self.routes.get_mut(&prefix) {
            Some(l) if !l.is_empty() => l,
            _ => return,
        };

        // Reset best and backup flags
        for entry in list.iter_mut() {
            entry.is_best = false;
            entry.is_backup = false;
        }

        // Sort paths by standard BGP decision criteria:
        // 1. Highest LocalPref
        // 2. Shortest AS-Path
        // 3. Lowest Origin (IGP < EGP < Incomplete)
        // 4. Lowest MED
        // 5. Lowest Peer IP
        list.sort_by(|a, b| {
            let lp_a = a.local_pref.unwrap_or(100);
            let lp_b = b.local_pref.unwrap_or(100);
            lp_b.cmp(&lp_a)
                .then_with(|| a.as_path.length().cmp(&b.as_path.length()))
                .then_with(|| (a.origin as u8).cmp(&(b.origin as u8)))
                .then_with(|| a.med.unwrap_or(0).cmp(&b.med.unwrap_or(0)))
                .then_with(|| a.peer_ip.0.cmp(&b.peer_ip.0))
                .then_with(|| a.path_id.cmp(&b.path_id))
        });

        // Best path is first
        list[0].is_best = true;

        // Backup path for BGP PIC is the first path with a DIFFERENT next-hop
        let best_next_hop = list[0].next_hop;
        for entry in list.iter_mut().skip(1) {
            if entry.next_hop != best_next_hop {
                entry.is_backup = true;
                break;
            }
        }
    }

    /// Returns the primary active next-hop and BGP PIC fast-reroute backup next-hop.
    pub fn get_pic_forwarding(
        &self,
        prefix: &Ipv4Prefix,
    ) -> Option<(Ipv4Address, Option<Ipv4Address>)> {
        let list = self.routes.get(prefix)?;
        let best = list.iter().find(|e| e.is_best)?;
        let backup = list.iter().find(|e| e.is_backup).map(|e| e.next_hop);
        Some((best.next_hop, backup))
    }

    /// Returns up to `max_paths` best paths for ECMP/Add-Path advertisement.
    pub fn get_advertised_paths(&self, prefix: &Ipv4Prefix) -> Vec<AddPathRibEntry> {
        match self.routes.get(prefix) {
            Some(list) => list
                .iter()
                .take(self.max_paths_per_prefix)
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }
}
