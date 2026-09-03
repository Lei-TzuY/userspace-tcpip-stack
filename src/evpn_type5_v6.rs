//! EVPN Route Type 5 for IPv6: IP Prefix Route with Overlay Index (RFC 9136 / RFC 7432).
//!
//! Provides inter-subnet tenant IPv6 prefix advertisements across EVPN VXLAN/MPLS overlays,
//! supporting IPv6 Gateway IP (GW-IP) and Ethernet Segment Identifier (ESI) overlay routing.

use crate::evpn::RouteDistinguisher;
use crate::flowspec_v6::matches_ipv6_cidr;
use crate::ipv6::Ipv6Address;

pub const EVPN_ROUTE_TYPE_IP_PREFIX: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnType5V6Route {
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub eth_tag: u32,
    pub ip_prefix: Ipv6Address,
    pub prefix_len: u8,
    pub gw_ip: Ipv6Address,
    pub label_or_vni: u32, // 24-bit VNI or 20-bit MPLS label
}

impl EvpnType5V6Route {
    pub fn new(
        rd: RouteDistinguisher,
        ip_prefix: Ipv6Address,
        prefix_len: u8,
        gw_ip: Ipv6Address,
        label_or_vni: u32,
    ) -> Self {
        EvpnType5V6Route {
            rd,
            esi: [0u8; 10],
            eth_tag: 0,
            ip_prefix,
            prefix_len,
            gw_ip,
            label_or_vni,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(58);
        buf.push(EVPN_ROUTE_TYPE_IP_PREFIX);
        buf.push(56); // NLRI Length for IPv6 Type 5 (8+10+4+1+16+16+3 = 58 total bytes)
        buf.extend_from_slice(&self.rd.serialize());
        buf.extend_from_slice(&self.esi);
        buf.extend_from_slice(&self.eth_tag.to_be_bytes());
        buf.push(self.prefix_len);
        buf.extend_from_slice(&self.ip_prefix.0);
        buf.extend_from_slice(&self.gw_ip.0);
        // 3-byte Label / VNI
        let label_bytes = self.label_or_vni.to_be_bytes();
        buf.extend_from_slice(&label_bytes[1..4]);
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 58 || buf[0] != EVPN_ROUTE_TYPE_IP_PREFIX {
            return None;
        }

        let rd = RouteDistinguisher::parse(&buf[2..10]).ok()?;
        let mut esi = [0u8; 10];
        esi.copy_from_slice(&buf[10..20]);
        let eth_tag = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let prefix_len = buf[24];

        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&buf[25..41]);
        let ip_prefix = Ipv6Address(ip_bytes);

        let mut gw_bytes = [0u8; 16];
        gw_bytes.copy_from_slice(&buf[41..57]);
        let gw_ip = Ipv6Address(gw_bytes);

        let label_or_vni = u32::from_be_bytes([0, buf[57], buf[58], buf[59]]);

        Some(EvpnType5V6Route {
            rd,
            esi,
            eth_tag,
            ip_prefix,
            prefix_len,
            gw_ip,
            label_or_vni,
        })
    }
}

/// EVPN Type 5 IPv6 Prefix Routing Information Base (RIB)
#[derive(Debug, Clone, Default)]
pub struct EvpnType5V6Rib {
    pub routes: Vec<EvpnType5V6Route>,
}

impl EvpnType5V6Rib {
    pub fn new() -> Self {
        EvpnType5V6Rib { routes: Vec::new() }
    }

    pub fn add_route(&mut self, route: EvpnType5V6Route) {
        if let Some(pos) = self.routes.iter().position(|r| {
            r.rd == route.rd && r.ip_prefix == route.ip_prefix && r.prefix_len == route.prefix_len
        }) {
            self.routes[pos] = route;
        } else {
            self.routes.push(route);
        }
    }

    pub fn withdraw_route(
        &mut self,
        rd: &RouteDistinguisher,
        ip_prefix: &Ipv6Address,
        prefix_len: u8,
    ) -> bool {
        let initial_len = self.routes.len();
        self.routes
            .retain(|r| !(r.rd == *rd && r.ip_prefix == *ip_prefix && r.prefix_len == prefix_len));
        self.routes.len() < initial_len
    }

    pub fn lookup(
        &self,
        rd: &RouteDistinguisher,
        target: &Ipv6Address,
    ) -> Option<&EvpnType5V6Route> {
        let mut best_match: Option<&EvpnType5V6Route> = None;
        let mut max_prefix_len: u8 = 0;

        for route in &self.routes {
            if route.rd == *rd && matches_ipv6_cidr(*target, route.ip_prefix, route.prefix_len) {
                if best_match.is_none() || route.prefix_len >= max_prefix_len {
                    max_prefix_len = route.prefix_len;
                    best_match = Some(route);
                }
            }
        }

        best_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_type5_v6_route_codec() {
        let rd = RouteDistinguisher {
            admin: 65000,
            assigned: 100,
        };
        let prefix = Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0x11, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let gw = Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let route = EvpnType5V6Route::new(rd.clone(), prefix, 64, gw, 10001);

        let raw = route.serialize();
        assert_eq!(raw.len(), 60);

        let parsed = EvpnType5V6Route::parse(&raw).unwrap();
        assert_eq!(parsed.rd, rd);
        assert_eq!(parsed.ip_prefix, prefix);
        assert_eq!(parsed.prefix_len, 64);
        assert_eq!(parsed.gw_ip, gw);
        assert_eq!(parsed.label_or_vni, 10001);
    }

    #[test]
    fn test_evpn_type5_v6_rib_lpm() {
        let mut rib = EvpnType5V6Rib::new();
        let rd = RouteDistinguisher {
            admin: 65000,
            assigned: 1,
        };

        let default_route = EvpnType5V6Route::new(
            rd.clone(),
            Ipv6Address([0; 16]),
            0,
            Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe]),
            50000,
        );
        let subnet_route = EvpnType5V6Route::new(
            rd.clone(),
            Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            64,
            Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            60000,
        );

        rib.add_route(default_route);
        rib.add_route(subnet_route);

        // Specific lookup inside 2001:db8::/64 -> matches subnet
        let target1 = Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x55,
        ]);
        let hit1 = rib.lookup(&rd, &target1).unwrap();
        assert_eq!(hit1.prefix_len, 64);
        assert_eq!(hit1.label_or_vni, 60000);

        // Outside subnet -> matches default route
        let target2 = Ipv6Address([0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let hit2 = rib.lookup(&rd, &target2).unwrap();
        assert_eq!(hit2.prefix_len, 0);
        assert_eq!(hit2.label_or_vni, 50000);
    }
}
