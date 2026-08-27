from pathlib import Path

p = Path("src/bgp_ls.rs")
s = p.read_text()

old = """                    if offset + tlv_len > body.len() {
                        break;
                    }
"""
count = s.count(old)
if count != 2:
    raise SystemExit(f"expected 2 outer TLV overrun guards, found {count}")
s = s.replace(
    old,
    """                    if offset + tlv_len > body.len() {
                        return None;
                    }
""",
)

old = """                            if sub_off + s_len > tlv_val.len() {
                                break;
                            }
"""
if s.count(old) != 1:
    raise SystemExit("nested descriptor overrun guard anchor mismatch")
s = s.replace(
    old,
    """                            if sub_off + s_len > tlv_val.len() {
                                return None;
                            }
""",
)

old = """                            sub_off += s_len;
                        }
                    }
                    offset += tlv_len;
                }

                Some(BgpLsNlri::Node(BgpLsNodeDescriptor {
"""
if s.count(old) != 1:
    raise SystemExit("node framing tail anchor mismatch")
s = s.replace(
    old,
    """                            sub_off += s_len;
                        }
                        if sub_off != tlv_val.len() {
                            return None;
                        }
                    }
                    offset += tlv_len;
                }
                if offset != body.len() {
                    return None;
                }

                Some(BgpLsNlri::Node(BgpLsNodeDescriptor {
""",
)

old = """                    offset += tlv_len;
                }

                Some(BgpLsNlri::Link(BgpLsLinkDescriptor {
"""
if s.count(old) != 1:
    raise SystemExit("link framing tail anchor mismatch")
s = s.replace(
    old,
    """                    offset += tlv_len;
                }
                if offset != body.len() {
                    return None;
                }

                Some(BgpLsNlri::Link(BgpLsLinkDescriptor {
""",
)

marker = """    #[test]
    fn test_bgp_ls_node_and_link_nlri_roundtrip() {
"""
if s.count(marker) != 1:
    raise SystemExit("test insertion anchor mismatch")
tests = """    #[test]
    fn test_bgp_ls_rejects_truncated_node_tlv_value() {
        let raw = [
            0x00, 0x01, 0x00, 0x08,
            0x01, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_truncated_node_descriptor_sub_tlv() {
        let raw = [
            0x00, 0x01, 0x00, 0x0c,
            0x01, 0x00, 0x00, 0x08,
            0x02, 0x02, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_trailing_partial_tlv_header() {
        let raw = [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_truncated_link_tlv_value() {
        let raw = [
            0x00, 0x02, 0x00, 0x08,
            0x01, 0x03, 0x00, 0x08,
            192, 0, 2, 1,
        ];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

"""
s = s.replace(marker, tests + marker)
p.write_text(s)
