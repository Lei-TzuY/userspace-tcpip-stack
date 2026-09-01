#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::snmp::SnmpMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = SnmpMessage::parse(data) {
        let encoded = message
            .try_serialize()
            .expect("successfully parsed SNMP message must serialize");
        let reparsed = SnmpMessage::parse(&encoded)
            .expect("serialized SNMP message must parse again");
        assert_eq!(reparsed, message);

        let reencoded = reparsed
            .try_serialize()
            .expect("reparsed SNMP message must serialize again");
        assert_eq!(reencoded, encoded);

        let mut with_trailing = encoded.clone();
        with_trailing.push(0);
        assert!(SnmpMessage::parse(&with_trailing).is_err());
    }
});
