use std::panic::{AssertUnwindSafe, catch_unwind};

use toy_tcpip::snmp::{
    SNMP_PDU_GET_BULK_REQUEST, SNMP_PDU_GET_REQUEST, SNMP_PDU_SET_REQUEST, SnmpMessage,
};

const MESSAGE_CORPUS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fuzz/corpus/snmp_message_parse"
);
const GET: &[u8] = include_bytes!("../fuzz/corpus/snmp_message_parse/get_sysdescr_v2c");
const GET_BULK: &[u8] = include_bytes!("../fuzz/corpus/snmp_message_parse/getbulk_sysdescr_v2c");
const SET: &[u8] = include_bytes!("../fuzz/corpus/snmp_message_parse/set_sysname_v2c");
const NONCANONICAL_LENGTH: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_message_parse/noncanonical_length");

fn assert_round_trip(seed: &[u8], expected_pdu_type: u8) {
    let message = SnmpMessage::parse(seed).expect("valid fuzz seed must remain parseable");
    assert_eq!(message.pdu.pdu_type, expected_pdu_type);

    let canonical = message
        .try_serialize()
        .expect("parsed fuzz seed must remain serializable");
    let reparsed =
        SnmpMessage::parse(&canonical).expect("canonicalized fuzz seed must remain parseable");
    assert_eq!(reparsed, message);
}

fn assert_panic_free_round_trip(seed: &[u8], label: &str) {
    let outcome = catch_unwind(AssertUnwindSafe(|| SnmpMessage::parse(seed)));
    let parsed = outcome.unwrap_or_else(|_| panic!("fuzz corpus entry panicked parser: {label}"));

    if let Ok(message) = parsed {
        let canonical = message.try_serialize().unwrap_or_else(|err| {
            panic!("parsed fuzz corpus entry failed serialization: {label}: {err:?}")
        });
        let reparsed = SnmpMessage::parse(&canonical).unwrap_or_else(|err| {
            panic!("canonicalized fuzz corpus entry failed parsing: {label}: {err:?}")
        });
        assert_eq!(
            reparsed, message,
            "round trip changed corpus entry: {label}"
        );
    }
}

#[test]
fn valid_message_seeds_remain_semantically_valid() {
    assert_round_trip(GET, SNMP_PDU_GET_REQUEST);
    assert_round_trip(GET_BULK, SNMP_PDU_GET_BULK_REQUEST);
    assert_round_trip(SET, SNMP_PDU_SET_REQUEST);
}

#[test]
fn malformed_message_seed_remains_safe_to_parse() {
    let outcome = catch_unwind(AssertUnwindSafe(|| SnmpMessage::parse(NONCANONICAL_LENGTH)));
    let parsed = outcome.expect("malformed fuzz seed must never panic the parser");

    if let Ok(message) = parsed {
        let canonical = message
            .try_serialize()
            .expect("successfully parsed malformed seed must be serializable");
        let reparsed = SnmpMessage::parse(&canonical)
            .expect("canonicalized malformed seed must remain parseable");
        assert_eq!(reparsed, message);
        assert_ne!(canonical.as_slice(), NONCANONICAL_LENGTH);
    }
}

#[test]
fn every_message_corpus_entry_is_replayed_as_a_regression() {
    let mut entries = std::fs::read_dir(MESSAGE_CORPUS_DIR)
        .expect("message fuzz corpus directory must exist")
        .map(|entry| entry.expect("message fuzz corpus directory entry must be readable"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("message fuzz corpus entry type must be readable")
                .is_file()
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    assert!(!entries.is_empty(), "message fuzz corpus must not be empty");

    for entry in entries {
        let path = entry.path();
        let seed = std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "message fuzz corpus entry must be readable: {}: {err}",
                path.display()
            )
        });
        assert_panic_free_round_trip(&seed, &path.display().to_string());
    }
}
