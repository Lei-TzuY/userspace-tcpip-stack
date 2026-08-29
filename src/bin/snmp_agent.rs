use std::env;
use std::net::UdpSocket;

use toy_tcpip::snmp::{
    SNMP_PDU_GET_BULK_REQUEST, SNMP_PDU_GET_NEXT_REQUEST, SNMP_PDU_GET_REQUEST, SnmpError,
    SnmpMessage, SnmpMib, SnmpValue, SnmpVarbind,
};

fn handle_request(mib: &SnmpMib, request: &SnmpMessage) -> Result<SnmpMessage, SnmpError> {
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
        tag => return Err(SnmpError::UnsupportedTag(tag)),
    };

    Ok(SnmpMessage::build_response(request, results))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1161".to_string());
    let socket = UdpSocket::bind(&bind_addr)?;
    let mib = SnmpMib::new();
    let mut buffer = [0u8; 65_535];

    eprintln!("SNMPv2c agent listening on {bind_addr}");
    loop {
        let (len, peer) = socket.recv_from(&mut buffer)?;
        let response = SnmpMessage::parse(&buffer[..len])
            .and_then(|request| handle_request(&mib, &request))
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

    #[test]
    fn get_request_returns_values_and_no_such_object() {
        let mib = SnmpMib::new();
        let request = SnmpMessage::build_get_request(
            "public",
            7,
            &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.99.0"],
        );

        let response = handle_request(&mib, &request).unwrap();

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
        let mib = SnmpMib::new();
        let mut request =
            SnmpMessage::build_get_request("public", 8, &["1.3.6.1.2.1.1.1.0", "2.999.0"]);
        request.pdu.pdu_type = SNMP_PDU_GET_NEXT_REQUEST;

        let response = handle_request(&mib, &request).unwrap();

        assert_eq!(response.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(response.pdu.varbinds[1].oid, "2.999.0");
        assert_eq!(response.pdu.varbinds[1].value, SnmpValue::EndOfMibView);
    }

    #[test]
    fn get_bulk_expands_non_repeaters_and_repeaters() {
        let mib = SnmpMib::new();
        let request = SnmpMessage::build_get_bulk_request(
            "public",
            9,
            1,
            2,
            &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"],
        )
        .unwrap();

        let response = handle_request(&mib, &request).unwrap();

        assert_eq!(response.pdu.varbinds.len(), 3);
        assert_eq!(response.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(response.pdu.varbinds[1].oid, "1.3.6.1.2.1.1.5.0");
        assert_eq!(response.pdu.varbinds[2].oid, "1.3.6.1.2.1.2.2.1.10.1");
    }

    #[test]
    fn wire_roundtrip_preserves_request_id_and_response_values() {
        let mib = SnmpMib::new();
        let request = SnmpMessage::build_get_request("public", 10, &["1.3.6.1.2.1.1.3.0"]);
        let parsed_request = SnmpMessage::parse(&request.try_serialize().unwrap()).unwrap();

        let response = handle_request(&mib, &parsed_request).unwrap();
        let parsed_response = SnmpMessage::parse(&response.try_serialize().unwrap()).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 10);
        assert_eq!(
            parsed_response.pdu.varbinds[0].value,
            SnmpValue::TimeTicks(360000)
        );
    }

    #[test]
    fn unsupported_pdus_are_rejected_by_handler() {
        let mut response = SnmpMessage::build_get_request("public", 11, &[]);
        response.pdu.pdu_type = toy_tcpip::snmp::SNMP_PDU_RESPONSE;

        assert_eq!(
            handle_request(&SnmpMib::new(), &response),
            Err(SnmpError::UnsupportedTag(
                toy_tcpip::snmp::SNMP_PDU_RESPONSE
            ))
        );
    }
}
