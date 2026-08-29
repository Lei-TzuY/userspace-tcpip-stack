#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::snmp::{
    decode_ber_integer, decode_ber_oid, decode_ber_tlv, encode_ber_integer, encode_ber_oid,
    BER_TAG_INTEGER, BER_TAG_OID,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_ber_tlv(data);

    if let Ok(value) = decode_ber_integer(data) {
        let encoded = encode_ber_integer(value);
        let (tag, body, consumed) = decode_ber_tlv(&encoded)
            .expect("encoded BER integer must decode as a TLV");
        assert_eq!(tag, BER_TAG_INTEGER);
        assert_eq!(consumed, encoded.len());
        assert_eq!(decode_ber_integer(body), Ok(value));
    }

    if let Ok(oid) = decode_ber_oid(data) {
        let encoded = encode_ber_oid(&oid).expect("decoded OID must be serializable");
        let (tag, body, consumed) = decode_ber_tlv(&encoded)
            .expect("encoded BER OID must decode as a TLV");
        assert_eq!(tag, BER_TAG_OID);
        assert_eq!(consumed, encoded.len());
        assert_eq!(decode_ber_oid(body), Ok(oid));
    }
});
