use std::env;
use std::net::UdpSocket;

use toy_tcpip::snmp::{
    SNMP_PDU_GET_BULK_REQUEST, SNMP_PDU_GET_NEXT_REQUEST, SNMP_PDU_GET_REQUEST,
    SNMP_PDU_SET_REQUEST, SnmpError, SnmpMessage, SnmpMib, SnmpValue, SnmpVarbind,
};

const SYS_NAME_OID: &str = "1.3.6.1.2.1.1.5.0";
const SNMP_ERROR_TOO_BIG: i32 = 1;
const SNMP_ERROR_WRONG_TYPE: i32 = 7;
const SNMP_ERROR_NO_CREATION: i32 = 11;
const SNMP_ERROR_AUTHORIZATION_ERROR: i32 = 16;
const SNMP_ERROR_NOT_WRITABLE: i32 = 17;
const MAX_REQUEST_BYTES: usize = 4_096;
const MAX_COMMUNITY_BYTES: usize = 64;
const MAX_REQUEST_VARBINDS: usize = 64;
const MAX_GET_BULK_REPETITIONS: usize = 64;
const MAX_GET_BULK_VARBINDS: usize = 128;
const MAX_RESPONSE_BYTES: usize = 1_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommunityAccess {
    read_only: String,
    read_write: String,
}

impl CommunityAccess {
    fn new(read_only: impl Into<String>, read_write: impl Into<String>) -> Self {
        Self {
            read_only: read_only.into(),
            read_write: read_write.into(),
        }
    }

    fn access_level(&self, community: &str) -> Option<AccessLevel> {
        if community == self.read_write {
            Some(AccessLevel::ReadWrite)
        } else if community == self.read_only {
            Some(AccessLevel::ReadOnly)
        } else {
            None
        }
    }
}

fn build_error_response(
    request: &SnmpMessage,
    error_status: i32,
    error_index: usize,
) -> SnmpMessage {
    let mut response = SnmpMessage::build_response(request, request.pdu.varbinds.clone());
    response.pdu.error_status = error_status;
    response.pdu.error_index = error_index as i32;
    response
}

fn build_too_big_response(request: &SnmpMessage) -> SnmpMessage {
    let mut response = SnmpMessage::build_response(request, Vec::new());
    response.pdu.error_status = SNMP_ERROR_TOO_BIG;
    response
}

fn handle_set_request(mib: &mut SnmpMib, request: &SnmpMessage) -> SnmpMessage {
    for (offset, varbind) in request.pdu.varbinds.iter().enumerate() {
        let error_index = offset + 1;
        let Some(current) = mib.get(&varbind.oid) else {
            return build_error_response(request, SNMP_ERROR_NO_CREATION, error_index);
        };

        if varbind.oid != SYS_NAME_OID {
            return build_error_response(request, SNMP_ERROR_NOT_WRITABLE, error_index);
        }

        if !matches!(
            (current, &varbind.value),
            (SnmpValue::OctetString(_), SnmpValue::OctetString(_))
        ) {
            return build_error_response(request, SNMP_ERROR_WRONG_TYPE, error_index);
        }
    }

    for varbind in &request.pdu.varbinds {
        mib.set(&varbind.oid, varbind.value.clone());
    }

    SnmpMessage::build_response(request, request.pdu.varbinds.clone())
}

fn bulk_result_count(
    varbind_count: usize,
    non_repeaters: usize,
    max_repetitions: usize,
) -> Option<usize> {
    let non_repeater_count = non_repeaters.min(varbind_count);
    let repeater_count = varbind_count - non_repeater_count;
    repeater_count
        .checked_mul(max_repetitions)
        .and_then(|repeated| non_repeater_count.checked_add(repeated))
}

fn handle_request(
    mib: &mut SnmpMib,
    request: &SnmpMessage,
    access_level: AccessLevel,
) -> Result<SnmpMessage, SnmpError> {
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
            let non_repeaters = usize::try_from(request.pdu.error_status)
                .map_err(|_| SnmpError::InvalidBerEncoding)?;
            let max_repetitions = usize::try_from(request.pdu.error_index)
                .map_err(|_| SnmpError::InvalidBerEncoding)?;
            let projected_count =
                bulk_result_count(request.pdu.varbinds.len(), non_repeaters, max_repetitions);
            if max_repetitions > MAX_GET_BULK_REPETITIONS
                || projected_count.map_or(true, |count| count > MAX_GET_BULK_VARBINDS)
            {
                return Ok(build_too_big_response(request));
            }

            let oids = request
                .pdu
                .varbinds
                .iter()
                .map(|varbind| varbind.oid.as_str())
                .collect::<Vec<_>>();
            mib.get_bulk(&oids, non_repeaters, max_repetitions)?
        }
        SNMP_PDU_SET_REQUEST => {
            if access_level == AccessLevel::ReadOnly {
                return Ok(build_error_response(
                    request,
                    SNMP_ERROR_AUTHORIZATION_ERROR,
                    0,
                ));
            }
            return Ok(handle_set_request(mib, request));
        }
        tag => return Err(SnmpError::UnsupportedTag(tag)),
    };

    Ok(SnmpMessage::build_response(request, results))
}

fn serialize_bounded_response(
    request: &SnmpMessage,
    response: SnmpMessage,
) -> Result<Option<Vec<u8>>, SnmpError> {
    let bytes = response.try_serialize()?;
    if bytes.len() <= MAX_RESPONSE_BYTES {
        return Ok(Some(bytes));
    }

    let too_big = build_too_big_response(request).try_serialize()?;
    Ok((too_big.len() <= MAX_RESPONSE_BYTES).then_some(too_big))
}

fn handle_datagram(
    mib: &mut SnmpMib,
    packet: &[u8],
    access: &CommunityAccess,
) -> Result<Option<Vec<u8>>, SnmpError> {
    if packet.len() > MAX_REQUEST_BYTES {
        return Ok(None);
    }

    let request = SnmpMessage::parse(packet)?;
    if request.community.len() > MAX_COMMUNITY_BYTES {
        return Ok(None);
    }

    let Some(access_level) = access.access_level(&request.community) else {
        return Ok(None);
    };

    if request.pdu.varbinds.len() > MAX_REQUEST_VARBINDS {
        let response = build_too_big_response(&request);
        return serialize_bounded_response(&request, response);
    }

    let response = handle_request(mib, &request, access_level)?;
    serialize_bounded_response(&request, response)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind_addr = args.next().unwrap_or_else(|| "127.0.0.1:1161".to_string());
    let read_community = args.next().unwrap_or_else(|| "public".to_string());
    let write_community = args.next().unwrap_or_else(|| "private".to_string());
    let access = CommunityAccess::new(read_community, write_community);
    let socket = UdpSocket::bind(&bind_addr)?;
    let mut mib = SnmpMib::new();
    let mut buffer = [0u8; MAX_REQUEST_BYTES + 1];

    eprintln!("SNMPv2c agent listening on {bind_addr} with community access control enabled");
    loop {
        let (len, peer) = socket.recv_from(&mut buffer)?;
        match handle_datagram(&mut mib, &buffer[..len], &access) {
            Ok(Some(bytes)) => {
                socket.send_to(&bytes, peer)?;
            }
            Ok(None) => {}
            Err(error) => eprintln!("dropping invalid SNMP request from {peer}: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_set_request(
        community: &str,
        request_id: i32,
        varbinds: Vec<SnmpVarbind>,
    ) -> SnmpMessage {
        let mut request = SnmpMessage::build_get_request(community, request_id, &[]);
        request.pdu.pdu_type = SNMP_PDU_SET_REQUEST;
        request.pdu.varbinds = varbinds;
        request
    }

    fn repeated_oid_varbinds(count: usize) -> Vec<SnmpVarbind> {
        (0..count)
            .map(|_| SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::Null,
            })
            .collect()
    }

    #[test]
    fn community_access_distinguishes_read_write_and_unknown() {
        let access = CommunityAccess::new("public", "private");

        assert_eq!(access.access_level("public"), Some(AccessLevel::ReadOnly));
        assert_eq!(access.access_level("private"), Some(AccessLevel::ReadWrite));
        assert_eq!(access.access_level("unknown"), None);
    }

    #[test]
    fn write_community_wins_when_communities_match() {
        let access = CommunityAccess::new("shared", "shared");

        assert_eq!(access.access_level("shared"), Some(AccessLevel::ReadWrite));
    }

    #[test]
    fn get_request_returns_values_and_no_such_object() {
        let mut mib = SnmpMib::new();
        let request = SnmpMessage::build_get_request(
            "public",
            7,
            &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.99.0"],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

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

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

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

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

        assert_eq!(response.pdu.varbinds.len(), 3);
        assert_eq!(response.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(response.pdu.varbinds[1].oid, "1.3.6.1.2.1.1.5.0");
        assert_eq!(response.pdu.varbinds[2].oid, "1.3.6.1.2.1.2.2.1.10.1");
    }

    #[test]
    fn get_bulk_rejects_excessive_repetitions_before_expansion() {
        let mut mib = SnmpMib::new();
        let request = SnmpMessage::build_get_bulk_request(
            "public",
            10,
            0,
            (MAX_GET_BULK_REPETITIONS + 1) as i32,
            &["1.3.6.1.2.1.1.1.0"],
        )
        .unwrap();

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_TOO_BIG);
        assert_eq!(response.pdu.error_index, 0);
        assert!(response.pdu.varbinds.is_empty());
    }

    #[test]
    fn get_bulk_rejects_projected_varbind_amplification() {
        let mut mib = SnmpMib::new();
        let oids = [
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.1.5.0",
        ];
        let request = SnmpMessage::build_get_bulk_request("public", 11, 0, 64, &oids).unwrap();

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_TOO_BIG);
        assert_eq!(response.pdu.error_index, 0);
        assert!(response.pdu.varbinds.is_empty());
    }

    #[test]
    fn set_request_updates_writable_sys_name() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            "private",
            12,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"edge-router.local".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadWrite).unwrap();

        assert_eq!(response.pdu.error_status, 0);
        assert_eq!(response.pdu.error_index, 0);
        assert_eq!(
            mib.get(SYS_NAME_OID),
            Some(&SnmpValue::OctetString(b"edge-router.local".to_vec()))
        );
        assert_eq!(response.pdu.varbinds, request.pdu.varbinds);
    }

    #[test]
    fn read_only_set_returns_authorization_error_without_mutating_mib() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let request = build_set_request(
            "public",
            13,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"blocked".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadOnly).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_AUTHORIZATION_ERROR);
        assert_eq!(response.pdu.error_index, 0);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn set_request_rejects_wrong_type_without_mutating_mib() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let request = build_set_request(
            "private",
            14,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::Integer(7),
            }],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadWrite).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_WRONG_TYPE);
        assert_eq!(response.pdu.error_index, 1);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn set_request_rejects_read_only_objects() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            "private",
            15,
            vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.1.0".to_string(),
                value: SnmpValue::OctetString(b"changed".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadWrite).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NOT_WRITABLE);
        assert_eq!(response.pdu.error_index, 1);
    }

    #[test]
    fn set_request_rejects_unknown_objects() {
        let mut mib = SnmpMib::new();
        let request = build_set_request(
            "private",
            16,
            vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.99.0".to_string(),
                value: SnmpValue::OctetString(b"new".to_vec()),
            }],
        );

        let response = handle_request(&mut mib, &request, AccessLevel::ReadWrite).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NO_CREATION);
        assert_eq!(response.pdu.error_index, 1);
    }

    #[test]
    fn set_request_is_atomic_when_later_varbind_fails() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let request = build_set_request(
            "private",
            17,
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

        let response = handle_request(&mut mib, &request, AccessLevel::ReadWrite).unwrap();

        assert_eq!(response.pdu.error_status, SNMP_ERROR_NOT_WRITABLE);
        assert_eq!(response.pdu.error_index, 2);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn unknown_community_datagram_is_dropped_without_mutating_mib() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let access = CommunityAccess::new("public", "private");
        let request = build_set_request(
            "unknown",
            18,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"should-not-stick".to_vec()),
            }],
        );
        let packet = request.try_serialize().unwrap();

        assert_eq!(handle_datagram(&mut mib, &packet, &access).unwrap(), None);
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn oversized_datagram_is_dropped_before_parsing() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let packet = vec![0xff; MAX_REQUEST_BYTES + 1];

        assert_eq!(handle_datagram(&mut mib, &packet, &access).unwrap(), None);
    }

    #[test]
    fn oversized_community_is_dropped_after_bounded_parse() {
        let mut mib = SnmpMib::new();
        let long_community = "x".repeat(MAX_COMMUNITY_BYTES + 1);
        let access = CommunityAccess::new(long_community.clone(), "private");
        let request = SnmpMessage::build_get_request(&long_community, 19, &[SYS_NAME_OID]);
        let packet = request.try_serialize().unwrap();

        assert!(packet.len() <= MAX_REQUEST_BYTES);
        assert_eq!(handle_datagram(&mut mib, &packet, &access).unwrap(), None);
    }

    #[test]
    fn excessive_get_varbinds_return_too_big() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let mut request = SnmpMessage::build_get_request("public", 20, &[]);
        request.pdu.varbinds = repeated_oid_varbinds(MAX_REQUEST_VARBINDS + 1);
        let packet = request.try_serialize().unwrap();

        assert!(packet.len() <= MAX_REQUEST_BYTES);
        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("authorized oversized request should receive tooBig");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 20);
        assert_eq!(parsed_response.pdu.error_status, SNMP_ERROR_TOO_BIG);
        assert_eq!(parsed_response.pdu.error_index, 0);
        assert!(parsed_response.pdu.varbinds.is_empty());
    }

    #[test]
    fn excessive_set_varbinds_are_rejected_before_mutation() {
        let mut mib = SnmpMib::new();
        let original = mib.get(SYS_NAME_OID).cloned();
        let access = CommunityAccess::new("public", "private");
        let varbinds = (0..=MAX_REQUEST_VARBINDS)
            .map(|_| SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"should-not-stick".to_vec()),
            })
            .collect();
        let request = build_set_request("private", 21, varbinds);
        let packet = request.try_serialize().unwrap();

        assert!(packet.len() <= MAX_REQUEST_BYTES);
        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("authorized oversized SET should receive tooBig");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(parsed_response.pdu.error_status, SNMP_ERROR_TOO_BIG);
        assert_eq!(parsed_response.pdu.error_index, 0);
        assert!(parsed_response.pdu.varbinds.is_empty());
        assert_eq!(mib.get(SYS_NAME_OID).cloned(), original);
    }

    #[test]
    fn maximum_request_varbind_count_is_still_served() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let mut request = SnmpMessage::build_get_request("public", 22, &[]);
        request.pdu.varbinds = (0..MAX_REQUEST_VARBINDS)
            .map(|_| SnmpVarbind {
                oid: "1.0".to_string(),
                value: SnmpValue::Null,
            })
            .collect();
        let packet = request.try_serialize().unwrap();

        assert!(packet.len() <= MAX_REQUEST_BYTES);
        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("request at the varbind limit should be served");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 22);
        assert_eq!(parsed_response.pdu.error_status, 0);
        assert_eq!(parsed_response.pdu.varbinds.len(), MAX_REQUEST_VARBINDS);
    }

    #[test]
    fn wire_roundtrip_preserves_request_id_and_response_values() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let request = SnmpMessage::build_get_request("public", 23, &["1.3.6.1.2.1.1.3.0"]);
        let packet = request.try_serialize().unwrap();

        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("authorized request should produce a response");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 23);
        assert_eq!(
            parsed_response.pdu.varbinds[0].value,
            SnmpValue::TimeTicks(360000)
        );
    }

    #[test]
    fn oversized_wire_response_is_replaced_with_too_big() {
        let mut mib = SnmpMib::new();
        mib.set(
            SYS_NAME_OID,
            SnmpValue::OctetString(vec![b'x'; MAX_RESPONSE_BYTES * 2]),
        );
        let access = CommunityAccess::new("public", "private");
        let request = SnmpMessage::build_get_request("public", 24, &[SYS_NAME_OID]);
        let packet = request.try_serialize().unwrap();

        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("tooBig response should fit within the response bound");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert!(response.len() <= MAX_RESPONSE_BYTES);
        assert_eq!(parsed_response.pdu.request_id, 24);
        assert_eq!(parsed_response.pdu.error_status, SNMP_ERROR_TOO_BIG);
        assert_eq!(parsed_response.pdu.error_index, 0);
        assert!(parsed_response.pdu.varbinds.is_empty());
    }

    #[test]
    fn set_wire_roundtrip_applies_update_and_serializes_response() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let request = build_set_request(
            "private",
            25,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"wire-router.local".to_vec()),
            }],
        );
        let packet = request.try_serialize().unwrap();

        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("authorized request should produce a response");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(parsed_response.pdu.request_id, 25);
        assert_eq!(parsed_response.pdu.error_status, 0);
        assert_eq!(parsed_response.pdu.error_index, 0);
        assert_eq!(parsed_response.pdu.varbinds, request.pdu.varbinds);
        assert_eq!(
            mib.get(SYS_NAME_OID),
            Some(&SnmpValue::OctetString(b"wire-router.local".to_vec()))
        );
    }

    #[test]
    fn read_only_set_wire_response_is_authorization_error() {
        let mut mib = SnmpMib::new();
        let access = CommunityAccess::new("public", "private");
        let request = build_set_request(
            "public",
            26,
            vec![SnmpVarbind {
                oid: SYS_NAME_OID.to_string(),
                value: SnmpValue::OctetString(b"blocked".to_vec()),
            }],
        );
        let packet = request.try_serialize().unwrap();

        let response = handle_datagram(&mut mib, &packet, &access)
            .unwrap()
            .expect("read-only SET should receive an authorization error response");
        let parsed_response = SnmpMessage::parse(&response).unwrap();

        assert_eq!(
            parsed_response.pdu.error_status,
            SNMP_ERROR_AUTHORIZATION_ERROR
        );
        assert_eq!(parsed_response.pdu.error_index, 0);
    }

    #[test]
    fn unsupported_pdus_are_rejected_by_handler() {
        let mut mib = SnmpMib::new();
        let mut response = SnmpMessage::build_get_request("public", 27, &[]);
        response.pdu.pdu_type = toy_tcpip::snmp::SNMP_PDU_RESPONSE;

        assert_eq!(
            handle_request(&mut mib, &response, AccessLevel::ReadOnly),
            Err(SnmpError::UnsupportedTag(
                toy_tcpip::snmp::SNMP_PDU_RESPONSE
            ))
        );
    }
}
