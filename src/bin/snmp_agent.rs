use std::env;
use std::net::UdpSocket;

use toy_tcpip::snmp::{
    SNMP_PDU_GET_BULK_REQUEST, SNMP_PDU_GET_NEXT_REQUEST, SNMP_PDU_GET_REQUEST,
    SNMP_PDU_SET_REQUEST, SnmpError, SnmpMessage, SnmpMib, SnmpValue, SnmpVarbind,
};

const SYS_NAME_OID: &str = "1.3.6.1.2.1.1.5.0";
const SNMP_ERROR_WRONG_TYPE: i32 = 7;
const SNMP_ERROR_NO_CREATION: i32 = 11;
const SNMP_ERROR_NOT_WRITABLE: i32 = 17;

fn build_set_error_response(
    request: &SnmpMessage,
    error_status: i32,
    error_index: usize,
) -> SnmpMessage {
    let mut response = SnmpMessage::build_response(request, request.pdu.varbinds.clone());
    response.pdu.error_status = error_status;
    response.pdu.error_index = error_index as i32;
    response
}

fn handle_set_request(mib: &mut SnmpMib, request: &SnmpMessage) -> SnmpMessage {
    for (offset, varbind) in request.pdu.varbinds.iter().enumerate() {
        let error_index = offset + 1;
        let Some(current) = mib.get(&varbind.oid) else {
            return build_set_error_response(request, SNMP_ERROR_NO_CREATION, error_index);
        };

        if varbind.oid != SYS_NAME_OID {
            return build_set_error_response(request, SNMP_ERROR_NOT_WRITABLE, error_index);
        }

        if !matches!(
            (current, &varbind.value),
            (SnmpValue::OctetString(_), SnmpValue::OctetString(_))
        ) {
            return build_set_error_response(request, SNMP_ERROR_WRONG_TYPE, error_index);
        }
    }

    for varbind in &request.pdu.varbinds {
        mib.set(&varbind.oid, varbind.value.clone());
    }

    SnmpMessage::build_response(request, request.pdu.varbinds.clone())
}

fn handle_request(mib: &mut SnmpMib, request: &SnmpMessage) -> Result<SnmpMessage, SnmpError> {
    let results = match request.pdu.pdu_type {
        SNMP_PDU_GET_REQUEST => request
            .pdu
            .varbinds
            .iter()
            .map(|varbind| SnmpVarbind {
                oid: varbind.oid.clone(),
                value: mib
                    .get(&varbind.oid)
                    .cloned()
                    .unwrap_or(SnmpValue::NoSuchObject),
            })
            .collect(),
        SNMP_PDU_GET_NEXT_REQUEST => {
            let mut results = Vec::with_capacity(request.pdu.varbinds.len());
            for varbind in &request.pdu.varbinds {
                results.push(mib.get_next(&varbind.oid)?.unwrap_or_else(|| SnmpVarbind {
                    oid: varbind.oid.clone(),
                    value: SnmpValue::EndOfMibView,
                }));
            }
            results
        }
        SNMP_PDU_GET_BULK_REQUEST => {
            let oids = request
                .pdu
                .varbinds
                .iter()
                .map(|varbind| varbind.oid.as_str())
                .collect::<Vec<_>>();
            let non_repeaters = usize::try_from(request.pdu.error_status)
                .map_err(|_| SnmpError::InvalidBerEncoding)?;
            let max_repetitions = usize::try_from(request.pdu.error_index)
                .map_err(|_| SnmpError::InvalidBerEncoding)?;
            mib.get_bulk(&oids, non_repeaters, max_repetitions)?
        }
        SNMP_PDU_SET_REQUEST => return Ok(handle_set_request(mib, request)),
        tag => return Err(SnmpError::UnsupportedTag(tag)),
    };

    Ok(SnmpMessage::build_response(request, results))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1161".to_string());
    let socket = UdpSocket::bind(&bind_addr)?;
    let mut mib = SnmpMib::new();
    let mut buffer = [0u8; 65_535];

    eprintln!("SNMPv2c agent listening on {bind_addr}");
    loop {
        let (len, peer) = socket.recv_from(&mut buffer)?;
        let response = SnmpMessage::parse(&buffer[..len])
            .and_then(|request| handle_request(&mut mib, &request))
            .and_then(|response| response.try_serialize());

        match response {
            Ok(bytes) => {
                socket.send_to(&bytes, peer)?;
            }
            Err(error) => eprintln!("dropping invalid SNMP request from {peer}: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_set_request(request_id: i32, varbinds: Vec<SnmpVarbind>) -> SnmpMessage {
        let mut request = SnmpMessage::build_get_request("public", request_id, &[]);
        request.pdu.pdu_type = SNMP_PDU_SET_REQUEST;
        request.pdu.varbinds = varbinds;
        request
    }

    #[test]
    fn get_request_returns_values_and_no_such_object() {
        let mut mib = SnmpMib::new();
        let request = SnmpMessage::build_get_request(
            "public",
            7,
            &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.99.0"],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.request_id, 7);
        assert_eq!(response.pdu.varbinds.len(), 2);
        assert!(matches!(
            response.pdu.varbinds[0].value,
            SnmpValue::OctetString(_)
        ));
        assert_eq!(response.pdu.varbinds[1].value, SnmpValue::NoSuchObject);
    }

    #[test]
    fn get_next_returns_successor_and_end_of_mib_view() {
        let mut mib = SnmpMib::new();
        let mut request =
            SnmpMessage::build_get_request("public", 8, &["1.3.6.1.2.1.1.1.0", "2.999.0"]);
        request.pdu.pdu_type = SNMP_PDU_GET_NEXT_REQUEST;

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(response.pdu.varbinds[1].oid, "2.999.0");
        assert_eq!(response.pdu.varbinds[1].value, SnmpValue::EndOfMibView);
    }

    #[test]
    fn get_bulk_expands_non_repeaters_and_repeaters() {
        let mut mib = SnmpMib::new();
        let request = SnmpMessage::build_get_bulk_request(
            "public",
            9,
            1,
            2,
            &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"],
        )
        .unwrap();

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.varbinds.len(), 3);
        assert_eq!(response.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(response.pdu.varbinds[1].oid, "1.3.6.1.2.1.1.5.0");
        assert_eq!(response.pdu.varbinds[2].oid, "1.3.6.1.2.1.2.2.1.10.1");
    }

    #[test]
    fn set_request_updates_writable_sys_name() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            10,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"edge-router.local".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.error_status, 0);
        assert_eq!(response.pdu.error_index, 0);
        assert_eq!(
            mib.get(SYS_NAME_OID),
            Some(&SnmpValue::OctetString(b"edge-router.local".to_vec()))
        );
        assert_eq!(response.pdu.varbinds, request.pdu.varbinds);
    }

    #[test]
    fn set_request_rejects_wrong_type_without_mutating_mib() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let request = build_set_request(
            11,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::Integer(7),
            }],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_WRONG_TYPE);
        assert_eq!(response.pdu.error_index, 1);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn set_request_rejects_read_only_objects() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            12,
            vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.1.0".to_string(),
                value: SnmpValue::OctetString(b"changed".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NOT_WRITABLE);
        assert_eq!(response.pdu.error_index, 1);
    }

    #[test]
    fn set_request_rejects_unknown_objects() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            13,
            vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.99.0".to_string(),
                value: SnmpValue::OctetString(b"new".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NO_CREATION);
        assert_eq!(response.pdu.error_index, 1);
    }

    #[test]
    fn set_request_is_atomic_when_later_varbind_fails() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let request = build_set_request(
            14,
            vec![
                SnmpVarbind {
                    oid: SYS_NAME_OID.to_string(),
                    value: SnmpValue::OctetString(b"should-not-stick".to_vec()),
                },
                SnmpVarbind {
                    oid: "1.3.6.1.2.1.1.3.0".to_string(),
                    value: SnmpValue::TimeTicks(1),
                },
            ],
        );

        let response = handle_request(&mut mib, &request).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NOT_WRITABLE);
        assert_eq!(response.pdu.error_index, 2);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn wire_roundtrip_preserves_request_id_and_response_values() {
        let mut mib = SnmpMib::new();
        let request = SnmpMessage::build_get_request("public", 15, &["1.3.6.1.2.1.1.3.0"]);
        let parsed_request = SnmpMessage::parse(&request.try_serialize().unwrap()).unwrap();

        let response = handle_request(&mut mib, &parsed_request).unwrap();
        let parsed_response = SnmpMessage::parse(&response.try_serialize().unwrap()).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 15);
        assert_eq!(
            parsed_response.pdu.varbinds[0].value,
            SnmpValue::TimeTicks(360000)
        );
    }

    #[test]
    fn set_wire_roundtrip_applies_update_and_serializes_response() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            16,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"wire-router.local".to_vec()),
            }],
        );
        let parsed_request = SnmpMessage::parse(&request.try_serialize().unwrap()).unwrap();

        let response = handle_request(&mut mib, &parsed_request).unwrap();
        let parsed_response = SnmpMessage::parse(&response.try_serialize().unwrap()).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 16);
        assert_eq!(parsed_response.pdu.error_status, 0);
        assert_eq!(parsed_response.pdu.error_index, 0);
        assert_eq!(parsed_response.pdu.varbinds, request.pdu.varbinds);
        assert_eq!(
            mib.get(SYS_NAME_OID),
            Some(&SnmpValue::OctetString(b"wire-router.local".to_vec()))
        );
    }

    #[test]
    fn unsupported_pdus_are_rejected_by_handler() {
        let mut mib = SnmpMib::new();
        let mut response = SnmpMessage::build_get_request("public", 17, &[]);
        response.pdu.pdu_type = toy_tcpip::snmp::SNMP_PDU_RESPONSE;

        assert_eq!(
            handle_request(&mut mib, &response),
            Err(SnmpError::UnsupportedTag(
                toy_tcpip::snmp::SNMP_PDU_RESPONSE
            ))
        );
    }
}
