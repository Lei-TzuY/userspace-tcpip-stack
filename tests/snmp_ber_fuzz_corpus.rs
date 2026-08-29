use std::panic::{AssertUnwindSafe, catch_unwind};

use toy_tcpip::snmp::{
    BER_TAG_INTEGER, BER_TAG_OID, SnmpError, decode_ber_integer, decode_ber_oid, decode_ber_tlv,
    encode_ber_integer, encode_ber_oid,
};

const BER_CORPUS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fuzz/corpus/snmp_ber_primitives"
);
const NONCANONICAL_LENGTH: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/noncanonical_length");
const NONCANONICAL_INTEGER: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/noncanonical_integer");
const UNTERMINATED_OID: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/unterminated_oid");

fn assert_ber_fuzz_invariants(seed: &[u8], label: &str) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _ = decode_ber_tlv(seed);

        if let Ok(value) = decode_ber_integer(seed) {
            let encoded = encode_ber_integer(value);
            let (tag, body, consumed) =
                decode_ber_tlv(&encoded).expect("encoded BER integer must decode as a TLV");
            assert_eq!(tag, BER_TAG_INTEGER);
            assert_eq!(consumed, encoded.len());
            assert_eq!(decode_ber_integer(body), Ok(value));
        }

        if let Ok(oid) = decode_ber_oid(seed) {
            let encoded = encode_ber_oid(&oid).expect("decoded OID must be serializable");
            let (tag, body, consumed) =
                decode_ber_tlv(&encoded).expect("encoded BER OID must decode as a TLV");
            assert_eq!(tag, BER_TAG_OID);
            assert_eq!(consumed, encoded.len());
            assert_eq!(decode_ber_oid(body), Ok(oid));
        }
    }));

    if outcome.is_err() {
        panic!("BER fuzz corpus entry violated fuzz invariants: {label}");
    }
}

#[test]
fn malformed_ber_seeds_keep_their_rejection_contract() {
    assert_eq!(
        decode_ber_tlv(NONCANONICAL_LENGTH),
        Err(SnmpError::InvalidBerEncoding)
    );

    let (tag, body, consumed) =
        decode_ber_tlv(NONCANONICAL_INTEGER).expect("INTEGER seed must retain valid TLV framing");
    assert_eq!(tag, BER_TAG_INTEGER);
    assert_eq!(consumed, NONCANONICAL_INTEGER.len());
    assert_eq!(decode_ber_integer(body), Err(SnmpError::InvalidBerEncoding));

    let (tag, body, consumed) =
        decode_ber_tlv(UNTERMINATED_OID).expect("OID seed must retain valid TLV framing");
    assert_eq!(tag, BER_TAG_OID);
    assert_eq!(consumed, UNTERMINATED_OID.len());
    assert_eq!(decode_ber_oid(body), Err(SnmpError::InvalidBerEncoding));
}

#[test]
fn every_ber_corpus_entry_is_replayed_as_a_regression() {
    let mut entries = std::fs::read_dir(BER_CORPUS_DIR)
        .expect("BER fuzz corpus directory must exist")
        .map(|entry| entry.expect("BER fuzz corpus directory entry must be readable"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("BER fuzz corpus entry type must be readable")
                .is_file()
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    assert!(!entries.is_empty(), "BER fuzz corpus must not be empty");

    for entry in entries {
        let path = entry.path();
        let seed = std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "BER fuzz corpus entry must be readable: {}: {err}",
                path.display()
            )
        });
        assert_ber_fuzz_invariants(&seed, &path.display().to_string());
    }
}
