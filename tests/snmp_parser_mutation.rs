use std::panic::{AssertUnwindSafe, catch_unwind};

use toy_tcpip::snmp::{
    SNMP_PDU_RESPONSE, SNMP_VERSION_2C, SnmpMessage, SnmpPdu, SnmpValue, SnmpVarbind,
};

const OID: &str = "1.3.6.1.2.1.1.1.0";

fn assert_parse_is_total(packet: &[u8]) {
    let outcome = catch_unwind(AssertUnwindSafe(|| SnmpMessage::parse(packet)));
    let parsed = outcome.expect("SNMP parser panicked on arbitrary input");

    if let Ok(message) = parsed {
        let canonical = message
            .try_serialize()
            .expect("successfully parsed message must be serializable");
        let reparsed = SnmpMessage::parse(&canonical)
            .expect("serialized successfully parsed message must parse again");
        assert_eq!(reparsed, message);
    }
}

fn rich_response() -> SnmpMessage {
    let values = vec![
        SnmpValue::Integer(-129),
        SnmpValue::OctetString(b"mutation-seed".to_vec()),
        SnmpValue::Null,
        SnmpValue::Oid("2.100.3".to_string()),
        SnmpValue::IpAddress([192, 0, 2, 1]),
        SnmpValue::Counter32(u32::MAX),
        SnmpValue::Gauge32(128),
        SnmpValue::TimeTicks(360_000),
        SnmpValue::Opaque(vec![0, 1, 2, 0xff]),
        SnmpValue::Counter64(u64::MAX),
        SnmpValue::NoSuchObject,
        SnmpValue::NoSuchInstance,
        SnmpValue::EndOfMibView,
    ];

    SnmpMessage {
        version: SNMP_VERSION_2C,
        community: "public".to_string(),
        pdu: SnmpPdu {
            pdu_type: SNMP_PDU_RESPONSE,
            request_id: 0x1234_5678,
            error_status: 0,
            error_index: 0,
            varbinds: values
                .into_iter()
                .enumerate()
                .map(|(index, value)| SnmpVarbind {
                    oid: format!("1.3.6.1.4.1.99999.{}.0", index + 1),
                    value,
                })
                .collect(),
        },
    }
}

#[test]
fn parser_survives_truncation_and_single_byte_mutations() {
    let seeds = [
        SnmpMessage::build_get_request("public", 42, &[OID])
            .try_serialize()
            .unwrap(),
        rich_response().try_serialize().unwrap(),
    ];

    for seed in seeds {
        for end in 0..=seed.len() {
            assert_parse_is_total(&seed[..end]);
        }

        for index in 0..seed.len() {
            for mask in [0x01, 0x7f, 0x80, 0xff] {
                let mut mutated = seed.clone();
                mutated[index] ^= mask;
                assert_parse_is_total(&mutated);
            }
        }

        let mut trailing = seed.clone();
        trailing.extend_from_slice(&[0, 0xff, 0x30, 0x80]);
        assert_parse_is_total(&trailing);
    }
}

#[test]
fn parser_survives_deterministic_arbitrary_byte_corpus() {
    let mut state = 0x6a09_e667_f3bc_c909u64;

    for case in 0..512usize {
        let len = (case * 37) % 1025;
        let mut packet = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            packet.push(state as u8);
        }
        assert_parse_is_total(&packet);
    }
}

#[test]
fn parser_rejects_oversized_arbitrary_input_without_panicking() {
    let packet = vec![0xff; toy_tcpip::snmp::SNMP_MAX_MESSAGE_LEN + 1];
    assert_parse_is_total(&packet);
}
