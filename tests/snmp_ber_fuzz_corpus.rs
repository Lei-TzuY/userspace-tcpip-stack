use toy_tcpip::snmp::{
    BER_TAG_INTEGER, BER_TAG_OID, SnmpError, decode_ber_integer, decode_ber_oid, decode_ber_tlv,
};

const NONCANONICAL_LENGTH: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/noncanonical_length");
const NONCANONICAL_INTEGER: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/noncanonical_integer");
const UNTERMINATED_OID: &[u8] =
    include_bytes!("../fuzz/corpus/snmp_ber_primitives/unterminated_oid");

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
