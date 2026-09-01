#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::snmp::{
    decode_ber_integer, decode_ber_oid, decode_ber_tlv, encode_ber_integer, encode_ber_oid,
    BER_TAG_INTEGER, BER_TAG_OID,
};

fuzz_target!(|data: &[u8]| {
    if let Ok((tag, body, consumed)) = decode_ber_tlv(data) {
        assert!(consumed <= data.len());
        let prefix = &data[..consumed];
        let (prefix_tag, prefix_body, prefix_consumed) =
            decode_ber_tlv(prefix).expect("consumed BER TLV prefix must decode identically");
        assert_eq!(prefix_tag, tag);
        assert_eq!(prefix_body, body);
        assert_eq!(prefix_consumed, consumed);
    }

    if let Ok(value) = decode_ber_integer(data) {
        let encoded = encode_ber_integer(value);
        let (tag, body, consumed) = decode_ber_tlv(&encoded)
            .expect("encoded BER integer must decode as a TLV");
        assert_eq!(tag, BER_TAG_INTEGER);
        assert_eq!(consumed, encoded.len());
        let reparsed = decode_ber_integer(body).expect("encoded BER integer body must decode");
        assert_eq!(reparsed, value);
        assert_eq!(encode_ber_integer(reparsed), encoded);
    }

    if let Ok(oid) = decode_ber_oid(data) {
        let encoded = encode_ber_oid(&oid).expect("decoded OID must be serializable");
        let (tag, body, consumed) = decode_ber_tlv(&encoded)
            .expect("encoded BER OID must decode as a TLV");
        assert_eq!(tag, BER_TAG_OID);
        assert_eq!(consumed, encoded.len());
        let reparsed = decode_ber_oid(body).expect("encoded BER OID body must decode");
        assert_eq!(reparsed, oid);
        assert_eq!(
            encode_ber_oid(&reparsed).expect("reparsed OID must be serializable"),
            encoded
        );
    }
});
