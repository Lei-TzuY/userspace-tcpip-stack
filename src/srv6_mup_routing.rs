//! SRv6 Mobile User Plane (MUP) Routing & Architecture (draft-ietf-dmm-srv6-mobile-uplane).
//!
//! Provides distributed 5G Mobile User Plane routing via BGP MUP NLRIs (SAFI 85),
//! mapping UE traffic and GTP-U tunnels directly onto Segment Routing over IPv6 (SRv6)
//! without central UPF anchor bottlenecks.
//!
//! Features:
//! - MUP Route Type 1: Interwork Segment (MUP-IS) Route (TEID, QFI, Source/Dest Node, GTP-to-SRv6 SID mapping).
//! - MUP Route Type 2: Direct Segment (MUP-DS) Route (UE IP Prefix to End.DT4/End.DX4 SID mapping).
//! - MUP Route Type 3: Downlink Data Plane Prefix Route (MUP-Type3) (TEID, QFI, Endpoint Address to SRv6 SID).
//! - MUP Route Type 4: Session Notification Route (MUP-Type4) (PDU Session ID, Tracking Area Code to SRv6 SID).
//! - MUP Routing Information Base (MUP RIB) with multi-type route resolution.

use crate::evpn::RouteDistinguisher;
use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;

pub fn matches_ipv4_cidr(ip: Ipv4Address, subnet: Ipv4Address, mask_len: u8) -> bool {
    if mask_len == 0 {
        return true;
    }
    if mask_len > 32 {
        return false;
    }
    let ip_u32 = u32::from_be_bytes(ip.0);
    let sub_u32 = u32::from_be_bytes(subnet.0);
    let mask = !0u32 << (32 - mask_len);
    (ip_u32 & mask) == (sub_u32 & mask)
}

pub const BGP_SAFI_MUP: u8 = 85;

pub const MUP_ROUTE_TYPE_INTERWORK: u8 = 1;
pub const MUP_ROUTE_TYPE_DIRECT: u8 = 2;
pub const MUP_ROUTE_TYPE_DOWNLINK: u8 = 3;
pub const MUP_ROUTE_TYPE_SESSION: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupType1InterworkRoute {
    pub rd: RouteDistinguisher,
    pub prefix: Ipv4Address,
    pub prefix_len: u8,
    pub teid: u32,
    pub qfi: u8,
    pub source_node: Ipv4Address,
    pub srv6_sid: Ipv6Address,
}

impl MupType1InterworkRoute {
    pub fn new(
        rd: RouteDistinguisher,
        prefix: Ipv4Address,
        prefix_len: u8,
        teid: u32,
        qfi: u8,
        source_node: Ipv4Address,
        srv6_sid: Ipv6Address,
    ) -> Self {
        MupType1InterworkRoute {
            rd,
            prefix,
            prefix_len,
            teid,
            qfi,
            source_node,
            srv6_sid,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.push(MUP_ROUTE_TYPE_INTERWORK);
        buf.push(38); // Length of body
        buf.extend_from_slice(&self.rd.serialize());
        buf.push(self.prefix_len);
        buf.extend_from_slice(&self.prefix.0);
        buf.extend_from_slice(&self.teid.to_be_bytes());
        buf.push(self.qfi);
        buf.extend_from_slice(&self.source_node.0);
        buf.extend_from_slice(&self.srv6_sid.0);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 40 || data[0] != MUP_ROUTE_TYPE_INTERWORK {
            return Err("Invalid or truncated MUP Type 1 route");
        }

        let rd = RouteDistinguisher::parse(&data[2..10]).map_err(|_| "Invalid RD")?;
        let prefix_len = data[10];
        let prefix = Ipv4Address::new(data[11], data[12], data[13], data[14]);
        let teid = u32::from_be_bytes([data[15], data[16], data[17], data[18]]);
        let qfi = data[19];
        let source_node = Ipv4Address::new(data[20], data[21], data[22], data[23]);

        let mut sid_bytes = [0u8; 16];
        sid_bytes.copy_from_slice(&data[24..40]);
        let srv6_sid = Ipv6Address(sid_bytes);

        Ok(MupType1InterworkRoute {
            rd,
            prefix,
            prefix_len,
            teid,
            qfi,
            source_node,
            srv6_sid,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupType2DirectRoute {
    pub rd: RouteDistinguisher,
    pub ue_prefix: Ipv4Address,
    pub prefix_len: u8,
    pub target_gnodeb: Ipv4Address,
    pub srv6_sid: Ipv6Address,
}

impl MupType2DirectRoute {
    pub fn new(
        rd: RouteDistinguisher,
        ue_prefix: Ipv4Address,
        prefix_len: u8,
        target_gnodeb: Ipv4Address,
        srv6_sid: Ipv6Address,
    ) -> Self {
        MupType2DirectRoute {
            rd,
            ue_prefix,
            prefix_len,
            target_gnodeb,
            srv6_sid,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(35);
        buf.push(MUP_ROUTE_TYPE_DIRECT);
        buf.push(33); // Body length
        buf.extend_from_slice(&self.rd.serialize());
        buf.push(self.prefix_len);
        buf.extend_from_slice(&self.ue_prefix.0);
        buf.extend_from_slice(&self.target_gnodeb.0);
        buf.extend_from_slice(&self.srv6_sid.0);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 35 || data[0] != MUP_ROUTE_TYPE_DIRECT {
            return Err("Invalid or truncated MUP Type 2 route");
        }

        let rd = RouteDistinguisher::parse(&data[2..10]).map_err(|_| "Invalid RD")?;
        let prefix_len = data[10];
        let ue_prefix = Ipv4Address::new(data[11], data[12], data[13], data[14]);
        let target_gnodeb = Ipv4Address::new(data[15], data[16], data[17], data[18]);

        let mut sid_bytes = [0u8; 16];
        sid_bytes.copy_from_slice(&data[19..35]);
        let srv6_sid = Ipv6Address(sid_bytes);

        Ok(MupType2DirectRoute {
            rd,
            ue_prefix,
            prefix_len,
            target_gnodeb,
            srv6_sid,
        })
    }
}

/// MUP Type 3: Downlink Data Plane Prefix Route (draft-ietf-dmm-srv6-mobile-uplane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupType3DownlinkRoute {
    pub rd: RouteDistinguisher,
    pub endpoint_addr: Ipv4Address,
    pub teid: u32,
    pub qfi: u8,
    pub srv6_sid: Ipv6Address,
}

impl MupType3DownlinkRoute {
    pub fn new(
        rd: RouteDistinguisher,
        endpoint_addr: Ipv4Address,
        teid: u32,
        qfi: u8,
        srv6_sid: Ipv6Address,
    ) -> Self {
        MupType3DownlinkRoute {
            rd,
            endpoint_addr,
            teid,
            qfi,
            srv6_sid,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(35);
        buf.push(MUP_ROUTE_TYPE_DOWNLINK);
        buf.push(33); // Body length: 8 (RD) + 4 (Endpoint) + 4 (TEID) + 1 (QFI) + 16 (SID)
        buf.extend_from_slice(&self.rd.serialize());
        buf.extend_from_slice(&self.endpoint_addr.0);
        buf.extend_from_slice(&self.teid.to_be_bytes());
        buf.push(self.qfi);
        buf.extend_from_slice(&self.srv6_sid.0);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 35 || data[0] != MUP_ROUTE_TYPE_DOWNLINK {
            return Err("Invalid or truncated MUP Type 3 route");
        }

        let rd = RouteDistinguisher::parse(&data[2..10]).map_err(|_| "Invalid RD")?;
        let endpoint_addr = Ipv4Address::new(data[10], data[11], data[12], data[13]);
        let teid = u32::from_be_bytes([data[14], data[15], data[16], data[17]]);
        let qfi = data[18];

        let mut sid_bytes = [0u8; 16];
        sid_bytes.copy_from_slice(&data[19..35]);
        let srv6_sid = Ipv6Address(sid_bytes);

        Ok(MupType3DownlinkRoute {
            rd,
            endpoint_addr,
            teid,
            qfi,
            srv6_sid,
        })
    }
}

/// MUP Type 4: Session Notification Route (draft-ietf-dmm-srv6-mobile-uplane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupType4SessionRoute {
    pub rd: RouteDistinguisher,
    pub endpoint_addr: Ipv4Address,
    pub pdu_session_id: u32,
    pub tracking_area_code: u32,
    pub srv6_sid: Ipv6Address,
}

impl MupType4SessionRoute {
    pub fn new(
        rd: RouteDistinguisher,
        endpoint_addr: Ipv4Address,
        pdu_session_id: u32,
        tracking_area_code: u32,
        srv6_sid: Ipv6Address,
    ) -> Self {
        MupType4SessionRoute {
            rd,
            endpoint_addr,
            pdu_session_id,
            tracking_area_code,
            srv6_sid,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(38);
        buf.push(MUP_ROUTE_TYPE_SESSION);
        buf.push(36); // Body length: 8 (RD) + 4 (Endpoint) + 4 (PDU Session ID) + 4 (TAC) + 16 (SID)
        buf.extend_from_slice(&self.rd.serialize());
        buf.extend_from_slice(&self.endpoint_addr.0);
        buf.extend_from_slice(&self.pdu_session_id.to_be_bytes());
        buf.extend_from_slice(&self.tracking_area_code.to_be_bytes());
        buf.extend_from_slice(&self.srv6_sid.0);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 38 || data[0] != MUP_ROUTE_TYPE_SESSION {
            return Err("Invalid or truncated MUP Type 4 route");
        }

        let rd = RouteDistinguisher::parse(&data[2..10]).map_err(|_| "Invalid RD")?;
        let endpoint_addr = Ipv4Address::new(data[10], data[11], data[12], data[13]);
        let pdu_session_id = u32::from_be_bytes([data[14], data[15], data[16], data[17]]);
        let tracking_area_code = u32::from_be_bytes([data[18], data[19], data[20], data[21]]);

        let mut sid_bytes = [0u8; 16];
        sid_bytes.copy_from_slice(&data[22..38]);
        let srv6_sid = Ipv6Address(sid_bytes);

        Ok(MupType4SessionRoute {
            rd,
            endpoint_addr,
            pdu_session_id,
            tracking_area_code,
            srv6_sid,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct MupRib {
    pub type1_routes: Vec<MupType1InterworkRoute>,
    pub type2_routes: Vec<MupType2DirectRoute>,
    pub type3_routes: Vec<MupType3DownlinkRoute>,
    pub type4_routes: Vec<MupType4SessionRoute>,
}

impl MupRib {
    pub fn new() -> Self {
        MupRib {
            type1_routes: Vec::new(),
            type2_routes: Vec::new(),
            type3_routes: Vec::new(),
            type4_routes: Vec::new(),
        }
    }

    pub fn add_type1_route(&mut self, route: MupType1InterworkRoute) {
        if let Some(pos) = self.type1_routes.iter().position(|r| {
            r.rd == route.rd
                && r.prefix == route.prefix
                && r.prefix_len == route.prefix_len
                && r.teid == route.teid
        }) {
            self.type1_routes[pos] = route;
        } else {
            self.type1_routes.push(route);
        }
    }

    pub fn add_type2_route(&mut self, route: MupType2DirectRoute) {
        if let Some(pos) = self.type2_routes.iter().position(|r| {
            r.rd == route.rd && r.ue_prefix == route.ue_prefix && r.prefix_len == route.prefix_len
        }) {
            self.type2_routes[pos] = route;
        } else {
            self.type2_routes.push(route);
        }
    }

    pub fn add_type3_route(&mut self, route: MupType3DownlinkRoute) {
        if let Some(pos) = self.type3_routes.iter().position(|r| {
            r.rd == route.rd && r.endpoint_addr == route.endpoint_addr && r.teid == route.teid
        }) {
            self.type3_routes[pos] = route;
        } else {
            self.type3_routes.push(route);
        }
    }

    pub fn add_type4_route(&mut self, route: MupType4SessionRoute) {
        if let Some(pos) = self.type4_routes.iter().position(|r| {
            r.rd == route.rd
                && r.endpoint_addr == route.endpoint_addr
                && r.pdu_session_id == route.pdu_session_id
        }) {
            self.type4_routes[pos] = route;
        } else {
            self.type4_routes.push(route);
        }
    }

    pub fn resolve_ue_sid(
        &self,
        rd: &RouteDistinguisher,
        ue_ip: &Ipv4Address,
    ) -> Option<&Ipv6Address> {
        let mut best_match: Option<&MupType2DirectRoute> = None;
        let mut max_prefix_len = 0;

        for route in &self.type2_routes {
            if route.rd == *rd && matches_ipv4_cidr(*ue_ip, route.ue_prefix, route.prefix_len) {
                if best_match.is_none() || route.prefix_len >= max_prefix_len {
                    max_prefix_len = route.prefix_len;
                    best_match = Some(route);
                }
            }
        }

        best_match.map(|r| &r.srv6_sid)
    }

    pub fn resolve_downlink_sid(&self, rd: &RouteDistinguisher, teid: u32) -> Option<&Ipv6Address> {
        self.type3_routes
            .iter()
            .find(|r| r.rd == *rd && r.teid == teid)
            .map(|r| &r.srv6_sid)
    }

    pub fn resolve_session_sid(
        &self,
        rd: &RouteDistinguisher,
        pdu_session_id: u32,
    ) -> Option<&Ipv6Address> {
        self.type4_routes
            .iter()
            .find(|r| r.rd == *rd && r.pdu_session_id == pdu_session_id)
            .map(|r| &r.srv6_sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mup_type1_interwork_codec_roundtrip() {
        let rd = RouteDistinguisher {
            admin: 65000,
            assigned: 1,
        };
        let sid = Ipv6Address([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01]);
        let t1 = MupType1InterworkRoute::new(
            rd.clone(),
            Ipv4Address::new(10, 0, 0, 0),
            24,
            0x12345678,
            9,
            Ipv4Address::new(192, 168, 1, 1),
            sid,
        );

        let ser = t1.serialize();
        assert_eq!(ser.len(), 40);

        let parsed = MupType1InterworkRoute::parse(&ser).unwrap();
        assert_eq!(parsed.rd, rd);
        assert_eq!(parsed.teid, 0x12345678);
        assert_eq!(parsed.qfi, 9);
        assert_eq!(parsed.srv6_sid, sid);
    }

    #[test]
    fn test_mup_type3_and_type4_codecs_and_resolution() {
        let mut rib = MupRib::new();
        let rd = RouteDistinguisher {
            admin: 65000,
            assigned: 10,
        };

        let sid_dl = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x03]);
        let sid_sess = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x04]);

        let t3 = MupType3DownlinkRoute::new(
            rd.clone(),
            Ipv4Address::new(192, 168, 10, 1),
            0xDEADBEEF,
            8,
            sid_dl,
        );
        let ser3 = t3.serialize();
        assert_eq!(ser3.len(), 35);
        let parsed3 = MupType3DownlinkRoute::parse(&ser3).unwrap();
        assert_eq!(parsed3.teid, 0xDEADBEEF);
        assert_eq!(parsed3.qfi, 8);
        assert_eq!(parsed3.srv6_sid, sid_dl);

        let t4 = MupType4SessionRoute::new(
            rd.clone(),
            Ipv4Address::new(192, 168, 10, 1),
            1001,
            5001,
            sid_sess,
        );
        let ser4 = t4.serialize();
        assert_eq!(ser4.len(), 38);
        let parsed4 = MupType4SessionRoute::parse(&ser4).unwrap();
        assert_eq!(parsed4.pdu_session_id, 1001);
        assert_eq!(parsed4.tracking_area_code, 5001);
        assert_eq!(parsed4.srv6_sid, sid_sess);

        rib.add_type3_route(t3);
        rib.add_type4_route(t4);

        assert_eq!(*rib.resolve_downlink_sid(&rd, 0xDEADBEEF).unwrap(), sid_dl);
        assert_eq!(*rib.resolve_session_sid(&rd, 1001).unwrap(), sid_sess);
        assert!(rib.resolve_downlink_sid(&rd, 0x1111).is_none());
    }
}
