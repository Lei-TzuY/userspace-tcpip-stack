from pathlib import Path

p = Path("src/icmpv6.rs")
s = p.read_text()

s = s.replace(
    "pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;\n",
    "pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;\npub const NDP_OPT_ROUTE_INFORMATION: u8 = 24;\n",
    1,
)

old = '''impl RouterPreference {
    fn from_ra_flags(flags: u8) -> Self {
        match (flags >> 3) & 0x03 {
            0x01 => Self::High,
            0x03 => Self::Low,
            // RFC 4191: the reserved 10 value MUST be treated as Medium.
            _ => Self::Medium,
        }
    }

    fn ra_flags(self) -> u8 {
        match self {
            Self::High => 0x08,
            Self::Medium => 0x00,
            Self::Low => 0x18,
        }
    }
}
'''
new = '''impl RouterPreference {
    fn from_ra_flags(flags: u8) -> Self {
        match (flags >> 3) & 0x03 {
            0x01 => Self::High,
            0x03 => Self::Low,
            // RFC 4191: the reserved 10 value MUST be treated as Medium.
            _ => Self::Medium,
        }
    }

    fn from_rio_flags(flags: u8) -> Option<Self> {
        match (flags >> 3) & 0x03 {
            0x00 => Some(Self::Medium),
            0x01 => Some(Self::High),
            0x03 => Some(Self::Low),
            // RFC 4191 section 2.3: a RIO using reserved preference 10 is ignored.
            _ => None,
        }
    }

    fn ra_flags(self) -> u8 {
        match self {
            Self::High => 0x08,
            Self::Medium => 0x00,
            Self::Low => 0x18,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInformationOption {
    pub prefix_length: u8,
    pub preference: RouterPreference,
    pub route_lifetime: u32,
    pub prefix: Ipv6Address,
}

impl RouteInformationOption {
    pub fn new(
        prefix: Ipv6Address,
        prefix_length: u8,
        preference: RouterPreference,
        route_lifetime: u32,
    ) -> Self {
        let prefix_length = prefix_length.min(128);
        Self {
            prefix_length,
            preference,
            route_lifetime,
            prefix: prefix.mask(prefix_length),
        }
    }

    fn length_units(self) -> u8 {
        match self.prefix_length {
            0 => 1,
            1..=64 => 2,
            _ => 3,
        }
    }

    fn append_to(self, buf: &mut Vec<u8>) {
        let units = self.length_units();
        buf.push(NDP_OPT_ROUTE_INFORMATION);
        buf.push(units);
        buf.push(self.prefix_length);
        buf.push(self.preference.ra_flags());
        buf.extend_from_slice(&self.route_lifetime.to_be_bytes());
        let prefix_octets = (usize::from(units) - 1) * 8;
        buf.extend_from_slice(&self.prefix.0[..prefix_octets]);
    }
}
'''
if old not in s:
    raise SystemExit("RouterPreference block not found")
s = s.replace(old, new, 1)

s = s.replace(
    "    pub retrans_timer: u32,\n    pub prefixes: Vec<PrefixInformationOption>,\n",
    "    pub retrans_timer: u32,\n    pub prefixes: Vec<PrefixInformationOption>,\n    pub routes: Vec<RouteInformationOption>,\n",
    1,
)

start = s.index("    /// RFC 4191-aware Router Advertisement builder. The legacy builder above")
end = s.index("    /// Builds an NDP Neighbor Solicitation (NS - Type 135)", start)
replacement = '''    /// RFC 4191-aware Router Advertisement builder. The legacy builder above
    /// remains source-compatible and advertises the default Medium preference.
    pub fn build_router_advertisement_with_preference(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        Self::build_router_advertisement_with_routes(
            src_ip,
            dst_ip,
            current_hop_limit,
            router_lifetime,
            preference,
            prefixes,
            &[],
            source_mac,
        )
    }

    /// Builds an RFC 4191 Router Advertisement with Route Information Options.
    /// RIOs are encoded with the shortest valid option length for their prefix.
    pub fn build_router_advertisement_with_routes(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        routes: &[RouteInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        let route_bytes: usize = routes
            .iter()
            .copied()
            .map(|route| usize::from(route.length_units()) * 8)
            .sum();
        let mut buf = Vec::with_capacity(
            16 + prefixes.len() * 32 + route_bytes + usize::from(source_mac.is_some()) * 8,
        );
        buf.push(ICMPV6_TYPE_ROUTER_ADVERT);
        buf.push(0);
        buf.extend_from_slice(&[0, 0]);
        buf.push(current_hop_limit);
        buf.push(preference.ra_flags());
        buf.extend_from_slice(&router_lifetime.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());

        if let Some(mac) = source_mac {
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }

        for prefix in prefixes {
            buf.push(NDP_OPT_PREFIX_INFORMATION);
            buf.push(4);
            buf.push(prefix.prefix_length);
            let mut flags = 0u8;
            if prefix.on_link {
                flags |= 0x80;
            }
            if prefix.autonomous {
                flags |= 0x40;
            }
            buf.push(flags);
            buf.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
            buf.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&prefix.prefix.mask(prefix.prefix_length).0);
        }

        for route in routes {
            route.append_to(&mut buf);
        }

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

'''
s = s[:start] + replacement + s[end:]

s = s.replace(
    "        let mut prefixes = Vec::new();\n        let mut offset = 12usize;\n",
    "        let mut prefixes = Vec::new();\n        let mut routes = Vec::new();\n        let mut offset = 12usize;\n",
    1,
)

old_tail = '''                prefixes.push(PrefixInformationOption::new(
                    Ipv6Address(prefix_bytes),
                    prefix_length,
                    option_flags & 0x80 != 0,
                    option_flags & 0x40 != 0,
                    valid_lifetime,
                    preferred_lifetime,
                ));
            }
            offset += option_len;
'''
new_tail = '''                prefixes.push(PrefixInformationOption::new(
                    Ipv6Address(prefix_bytes),
                    prefix_length,
                    option_flags & 0x80 != 0,
                    option_flags & 0x40 != 0,
                    valid_lifetime,
                    preferred_lifetime,
                ));
            } else if option_type == NDP_OPT_ROUTE_INFORMATION {
                let option = &payload[offset..offset + option_len];
                let prefix_length = option[2];
                let length_valid = match prefix_length {
                    0 => matches!(units, 1..=3),
                    1..=64 => matches!(units, 2 | 3),
                    65..=128 => units == 3,
                    _ => false,
                };
                if length_valid
                    && let Some(preference) = RouterPreference::from_rio_flags(option[3])
                {
                    let route_lifetime = u32::from_be_bytes(option[4..8].try_into().ok()?);
                    let prefix_octets = option_len - 8;
                    let mut prefix_bytes = [0u8; 16];
                    prefix_bytes[..prefix_octets].copy_from_slice(&option[8..]);
                    routes.push(RouteInformationOption::new(
                        Ipv6Address(prefix_bytes),
                        prefix_length,
                        preference,
                        route_lifetime,
                    ));
                }
            }
            offset += option_len;
'''
if old_tail not in s:
    raise SystemExit("RA option parse block not found")
s = s.replace(old_tail, new_tail, 1)

s = s.replace(
    "            retrans_timer,\n            prefixes,\n        })\n",
    "            retrans_timer,\n            prefixes,\n            routes,\n        })\n",
    1,
)

marker = "    #[test]\n    fn test_ndp_neighbor_solicitation_and_advertisement() {"
idx = s.index(marker)
tests = '''    #[test]
    fn test_rfc4191_route_information_round_trip() {
        let src = Ipv6Address::from_str("fe80::1").unwrap();
        let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
        let routes = [
            RouteInformationOption::new(
                Ipv6Address::UNSPECIFIED,
                0,
                RouterPreference::Low,
                30,
            ),
            RouteInformationOption::new(
                Ipv6Address::from_str("2001:db8:1234::").unwrap(),
                48,
                RouterPreference::High,
                600,
            ),
            RouteInformationOption::new(
                Ipv6Address::from_str("2001:db8:abcd:1:2::").unwrap(),
                96,
                RouterPreference::Medium,
                u32::MAX,
            ),
        ];
        let raw = Icmpv6Packet::build_router_advertisement_with_routes(
            src,
            dst,
            64,
            1800,
            RouterPreference::Medium,
            &[],
            &routes,
            None,
        );
        let packet = Icmpv6Packet::parse(src, dst, &raw, true).unwrap();
        let ra = packet.validated_router_advertisement(src, 255).unwrap();
        assert_eq!(ra.routes, routes);

        let options = &packet.payload[12..];
        assert_eq!(options[1], 1);
        assert_eq!(options[9], 2);
        assert_eq!(options[25], 3);
    }

    #[test]
    fn test_rfc4191_invalid_length_and_reserved_preference_are_ignored() {
        let mut payload = vec![0u8; 12];
        payload.extend_from_slice(&[
            NDP_OPT_ROUTE_INFORMATION,
            2,
            96,
            RouterPreference::High.ra_flags(),
            0,
            0,
            0,
            30,
            0x20,
            0x01,
            0x0d,
            0xb8,
            0,
            0,
            0,
            0,
        ]);
        payload.extend_from_slice(&[
            NDP_OPT_ROUTE_INFORMATION,
            2,
            48,
            0x10,
            0,
            0,
            0,
            30,
            0x20,
            0x01,
            0x0d,
            0xb8,
            0,
            0,
            0,
            0,
        ]);
        let packet = Icmpv6Packet {
            msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
            code: 0,
            checksum: 0,
            payload: &payload,
        };
        let ra = RouterAdvertisement::parse(&packet).unwrap();
        assert!(ra.routes.is_empty());
    }

'''
s = s[:idx] + tests + s[idx:]
p.write_text(s)
