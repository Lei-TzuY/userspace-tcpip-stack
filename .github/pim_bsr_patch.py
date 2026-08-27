from pathlib import Path

src = Path("src/pim_bsr.rs")
s = src.read_text()

replacements = [
    (
        """            if offset + 4 > data.len() {\n                break;\n            }\n""",
        """            if offset + 4 > data.len() {\n                return None;\n            }\n""",
        1,
        "group mapping header",
    ),
    (
        """                if offset + 10 > data.len() {\n                    break;\n                }\n""",
        """                if offset + 10 > data.len() {\n                    return None;\n                }\n""",
        1,
        "candidate RP record",
    ),
    (
        """            group_mappings.push(GroupRpMapping {\n                group,\n                rp_count,\n                frag_tag,\n                candidates,\n            });\n        }\n\n        Some(PimBootstrapMessage {\n""",
        """            group_mappings.push(GroupRpMapping {\n                group,\n                rp_count,\n                frag_tag,\n                candidates,\n            });\n        }\n        if offset != data.len() {\n            return None;\n        }\n\n        Some(PimBootstrapMessage {\n""",
        1,
        "bootstrap trailing bytes",
    ),
    (
        """            if offset + 8 > data.len() {\n                break;\n            }\n""",
        """            if offset + 8 > data.len() {\n                return None;\n            }\n""",
        1,
        "candidate RP prefix",
    ),
    (
        """            group_prefixes.push(g);\n            offset += consumed;\n        }\n\n        Some(PimCandidateRpAdv {\n""",
        """            group_prefixes.push(g);\n            offset += consumed;\n        }\n        if offset != data.len() {\n            return None;\n        }\n\n        Some(PimCandidateRpAdv {\n""",
        1,
        "candidate RP trailing bytes",
    ),
]

for old, new, expected, label in replacements:
    count = s.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} anchor, found {count}")
    s = s.replace(old, new)

src.write_text(s)

tests = Path("tests/test_pim_bsr.rs")
t = tests.read_text()
addition = r'''

fn bootstrap_header() -> Vec<u8> {
    vec![0x00, 0x01, 30, 128, 0x01, 0x00, 192, 0, 2, 1]
}

fn encoded_group() -> [u8; 8] {
    [0x01, 0x00, 0x00, 8, 239, 0, 0, 0]
}

#[test]
fn test_bootstrap_rejects_truncated_group_mapping_header() {
    let mut wire = bootstrap_header();
    wire.extend_from_slice(&encoded_group());
    wire.extend_from_slice(&[1, 0]);
    assert!(PimBootstrapMessage::parse(&wire).is_none());
}

#[test]
fn test_bootstrap_rejects_missing_candidate_rp_record() {
    let mut wire = bootstrap_header();
    wire.extend_from_slice(&encoded_group());
    wire.extend_from_slice(&[1, 0, 0x12, 0x34]);
    assert!(PimBootstrapMessage::parse(&wire).is_none());
}

#[test]
fn test_bootstrap_rejects_trailing_partial_group_address() {
    let mut wire = bootstrap_header();
    wire.push(0xaa);
    assert!(PimBootstrapMessage::parse(&wire).is_none());
}

#[test]
fn test_candidate_rp_adv_rejects_missing_declared_prefix() {
    let wire = [1, 5, 0, 120, 0x01, 0x00, 10, 0, 0, 1];
    assert!(PimCandidateRpAdv::parse(&wire).is_none());
}

#[test]
fn test_candidate_rp_adv_rejects_trailing_bytes_after_declared_prefixes() {
    let wire = [0, 5, 0, 120, 0x01, 0x00, 10, 0, 0, 1, 0xaa];
    assert!(PimCandidateRpAdv::parse(&wire).is_none());
}

#[test]
fn test_empty_bootstrap_and_candidate_rp_adv_remain_valid() {
    let bsm = PimBootstrapMessage::parse(&bootstrap_header()).expect("empty BSM");
    assert!(bsm.group_mappings.is_empty());

    let adv = [0, 5, 0, 120, 0x01, 0x00, 10, 0, 0, 1];
    let parsed = PimCandidateRpAdv::parse(&adv).expect("zero-prefix C-RP-Adv");
    assert!(parsed.group_prefixes.is_empty());
}
'''

if "test_bootstrap_rejects_truncated_group_mapping_header" in t:
    raise SystemExit("PIM-BSR framing tests already present")
tests.write_text(t + addition)
