use std::env;
use std::net::UdpSocket;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use toy_tcpip::snmp::{
    SNMP_PDU_GET_NEXT_REQUEST, SNMP_PDU_RESPONSE, SNMP_PDU_SET_REQUEST, SNMP_VERSION_2C, SnmpError,
    SnmpMessage, SnmpPdu, SnmpValue, SnmpVarbind,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    Get,
    GetNext,
    GetBulk {
        non_repeaters: i32,
        max_repetitions: i32,
    },
    Set(Vec<SnmpVarbind>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    agent: String,
    community: String,
    operation: Operation,
    oids: Vec<String>,
}

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} <agent:port> <community> get <oid> [oid ...]\n  {program} <agent:port> <community> getnext <oid> [oid ...]\n  {program} <agent:port> <community> getbulk <non-repeaters> <max-repetitions> <oid> [oid ...]\n  {program} <agent:port> <community> set <oid> <type> <value> [<oid> <type> <value> ...]\n\nSET types: string, integer, oid, ip, counter32, gauge32, timeticks, counter64, null"
    )
}

fn parse_non_negative(value: &str, name: &str) -> Result<i32, String> {
    let parsed = value
        .parse::<i32>()
        .map_err(|_| format!("{name} must be a non-negative integer"))?;
    if parsed < 0 {
        return Err(format!("{name} must be a non-negative integer"));
    }
    Ok(parsed)
}

fn parse_ip_address(value: &str) -> Result<[u8; 4], String> {
    let octets = value
        .split('.')
        .map(|part| part.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("invalid IPv4 address '{value}'"))?;
    if octets.len() != 4 {
        return Err(format!("invalid IPv4 address '{value}'"));
    }
    Ok([octets[0], octets[1], octets[2], octets[3]])
}

fn parse_set_value(value_type: &str, value: &str) -> Result<SnmpValue, String> {
    match value_type.to_ascii_lowercase().as_str() {
        "string" => Ok(SnmpValue::OctetString(value.as_bytes().to_vec())),
        "integer" => value
            .parse::<i32>()
            .map(SnmpValue::Integer)
            .map_err(|_| format!("invalid integer '{value}'")),
        "oid" => Ok(SnmpValue::Oid(value.to_string())),
        "ip" => parse_ip_address(value).map(SnmpValue::IpAddress),
        "counter32" => value
            .parse::<u32>()
            .map(SnmpValue::Counter32)
            .map_err(|_| format!("invalid counter32 '{value}'")),
        "gauge32" => value
            .parse::<u32>()
            .map(SnmpValue::Gauge32)
            .map_err(|_| format!("invalid gauge32 '{value}'")),
        "timeticks" => value
            .parse::<u32>()
            .map(SnmpValue::TimeTicks)
            .map_err(|_| format!("invalid timeticks '{value}'")),
        "counter64" => value
            .parse::<u64>()
            .map(SnmpValue::Counter64)
            .map_err(|_| format!("invalid counter64 '{value}'")),
        "null" if value == "-" => Ok(SnmpValue::Null),
        "null" => Err("null values must use '-' as the value".to_string()),
        other => Err(format!("unsupported SET type '{other}'")),
    }
}

fn parse_set_varbinds(args: &[String]) -> Result<Vec<SnmpVarbind>, String> {
    if args.is_empty() || !args.len().is_multiple_of(3) {
        return Err("SET requires one or more <oid> <type> <value> triples".to_string());
    }

    args.chunks_exact(3)
        .map(|parts| {
            Ok(SnmpVarbind {
                oid: parts[0].clone(),
                value: parse_set_value(&parts[1], &parts[2])?,
            })
        })
        .collect()
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    if args.len() < 5 {
        return Err(usage(args.first().map_or("snmp_client", String::as_str)));
    }

    let agent = args[1].clone();
    let community = args[2].clone();
    let command = args[3].to_ascii_lowercase();

    let (operation, oid_start) = match command.as_str() {
        "get" => (Operation::Get, Some(4)),
        "getnext" => (Operation::GetNext, Some(4)),
        "getbulk" => {
            if args.len() < 7 {
                return Err(usage(&args[0]));
            }
            let non_repeaters = parse_non_negative(&args[4], "non-repeaters")?;
            let max_repetitions = parse_non_negative(&args[5], "max-repetitions")?;
            (
                Operation::GetBulk {
                    non_repeaters,
                    max_repetitions,
                },
                Some(6),
            )
        }
        "set" => (Operation::Set(parse_set_varbinds(&args[4..])?), None),
        _ => {
            return Err(format!(
                "unknown operation '{command}'\n{}",
                usage(&args[0])
            ));
        }
    };

    let oids = oid_start.map_or_else(Vec::new, |start| args[start..].to_vec());
    if oid_start.is_some() && oids.is_empty() {
        return Err("at least one OID is required".to_string());
    }

    Ok(Config {
        agent,
        community,
        operation,
        oids,
    })
}

fn next_request_id() -> i32 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    (millis & i32::MAX as u128) as i32
}

fn build_request(config: &Config, request_id: i32) -> Result<SnmpMessage, SnmpError> {
    let oid_refs = config.oids.iter().map(String::as_str).collect::<Vec<_>>();
    match &config.operation {
        Operation::Get => Ok(SnmpMessage::build_get_request(
            &config.community,
            request_id,
            &oid_refs,
        )),
        Operation::GetNext => {
            let mut request =
                SnmpMessage::build_get_request(&config.community, request_id, &oid_refs);
            request.pdu.pdu_type = SNMP_PDU_GET_NEXT_REQUEST;
            Ok(request)
        }
        Operation::GetBulk {
            non_repeaters,
            max_repetitions,
        } => SnmpMessage::build_get_bulk_request(
            &config.community,
            request_id,
            *non_repeaters,
            *max_repetitions,
            &oid_refs,
        ),
        Operation::Set(varbinds) => Ok(SnmpMessage {
            version: SNMP_VERSION_2C,
            community: config.community.clone(),
            pdu: SnmpPdu {
                pdu_type: SNMP_PDU_SET_REQUEST,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: varbinds.clone(),
            },
        }),
    }
}

fn validate_response(
    response: &SnmpMessage,
    community: &str,
    request_id: i32,
) -> Result<(), String> {
    if response.community != community {
        return Err("response community does not match the request".to_string());
    }
    if response.pdu.pdu_type != SNMP_PDU_RESPONSE {
        return Err(format!(
            "unexpected response PDU type 0x{:02x}",
            response.pdu.pdu_type
        ));
    }
    if response.pdu.request_id != request_id {
        return Err(format!(
            "response request-id mismatch: expected {request_id}, got {}",
            response.pdu.request_id
        ));
    }
    if response.pdu.error_status != 0 {
        return Err(format!(
            "agent returned error-status {} at error-index {}",
            response.pdu.error_status, response.pdu.error_index
        ));
    }
    Ok(())
}

fn format_value(value: &SnmpValue) -> String {
    value.to_string()
}

fn run(config: &Config) -> Result<(), String> {
    let request_id = next_request_id();
    let request = build_request(config, request_id).map_err(|err| err.to_string())?;
    let bytes = request.try_serialize().map_err(|err| err.to_string())?;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| format!("bind failed: {err}"))?;
    socket
        .set_read_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|err| format!("failed to set receive timeout: {err}"))?;
    socket
        .send_to(&bytes, &config.agent)
        .map_err(|err| format!("send failed: {err}"))?;

    let mut buffer = vec![0u8; MAX_RESPONSE_SIZE];
    let (received, peer) = socket
        .recv_from(&mut buffer)
        .map_err(|err| format!("receive failed: {err}"))?;
    buffer.truncate(received);

    let response = SnmpMessage::parse(&buffer).map_err(|err| format!("invalid response: {err}"))?;
    validate_response(&response, &config.community, request_id)?;

    println!("response from {peer}");
    for varbind in response.pdu.varbinds {
        println!("{} = {}", varbind.oid, format_value(&varbind.value));
    }
    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let config = match parse_args(&args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    if let Err(message) = run(&config) {
        eprintln!("snmp_client: {message}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toy_tcpip::snmp::{SNMP_PDU_GET_BULK_REQUEST, SNMP_PDU_GET_REQUEST};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_get_arguments() {
        let args = strings(&[
            "snmp_client",
            "127.0.0.1:161",
            "public",
            "get",
            "1.3.6.1.2.1.1.1.0",
        ]);
        let config = parse_args(&args).unwrap();
        assert_eq!(config.agent, "127.0.0.1:161");
        assert_eq!(config.community, "public");
        assert_eq!(config.operation, Operation::Get);
        assert_eq!(config.oids, strings(&["1.3.6.1.2.1.1.1.0"]));
    }

    #[test]
    fn parse_getbulk_arguments_and_reject_negative_values() {
        let args = strings(&[
            "snmp_client",
            "127.0.0.1:161",
            "public",
            "getbulk",
            "1",
            "8",
            "1.3.6.1.2.1",
        ]);
        let config = parse_args(&args).unwrap();
        assert_eq!(
            config.operation,
            Operation::GetBulk {
                non_repeaters: 1,
                max_repetitions: 8
            }
        );

        let invalid = strings(&[
            "snmp_client",
            "127.0.0.1:161",
            "public",
            "getbulk",
            "0",
            "-1",
            "1.3.6.1.2.1",
        ]);
        assert!(parse_args(&invalid).is_err());
    }

    #[test]
    fn parse_set_arguments_supports_typed_multi_varbinds() {
        let args = strings(&[
            "snmp_client",
            "127.0.0.1:161",
            "private",
            "set",
            "1.3.6.1.2.1.1.5.0",
            "string",
            "edge-router.local",
            "1.3.6.1.2.1.1.99.0",
            "integer",
            "7",
        ]);
        let config = parse_args(&args).unwrap();
        assert_eq!(config.oids, Vec::<String>::new());
        assert_eq!(
            config.operation,
            Operation::Set(vec![
                SnmpVarbind {
                    oid: "1.3.6.1.2.1.1.5.0".to_string(),
                    value: SnmpValue::OctetString(b"edge-router.local".to_vec()),
                },
                SnmpVarbind {
                    oid: "1.3.6.1.2.1.1.99.0".to_string(),
                    value: SnmpValue::Integer(7),
                },
            ])
        );
    }

    #[test]
    fn parse_set_rejects_bad_triples_types_and_values() {
        let incomplete = strings(&[
            "snmp_client",
            "127.0.0.1:161",
            "private",
            "set",
            "1.3.6.1.2.1.1.5.0",
            "string",
        ]);
        assert!(parse_args(&incomplete).is_err());

        assert!(parse_set_value("unknown", "1").is_err());
        assert!(parse_set_value("integer", "NaN").is_err());
        assert!(parse_set_value("ip", "192.0.2.999").is_err());
        assert!(parse_set_value("null", "anything").is_err());
        assert_eq!(parse_set_value("null", "-").unwrap(), SnmpValue::Null);
    }

    #[test]
    fn build_each_supported_request_type() {
        let mut config = Config {
            agent: "127.0.0.1:161".to_string(),
            community: "public".to_string(),
            operation: Operation::Get,
            oids: strings(&["1.3.6.1.2.1.1.1.0"]),
        };
        assert_eq!(
            build_request(&config, 7).unwrap().pdu.pdu_type,
            SNMP_PDU_GET_REQUEST
        );

        config.operation = Operation::GetNext;
        assert_eq!(
            build_request(&config, 8).unwrap().pdu.pdu_type,
            SNMP_PDU_GET_NEXT_REQUEST
        );

        config.operation = Operation::GetBulk {
            non_repeaters: 0,
            max_repetitions: 4,
        };
        let bulk = build_request(&config, 9).unwrap();
        assert_eq!(bulk.pdu.pdu_type, SNMP_PDU_GET_BULK_REQUEST);
        assert_eq!(bulk.pdu.error_status, 0);
        assert_eq!(bulk.pdu.error_index, 4);

        config.community = "private".to_string();
        config.operation = Operation::Set(vec![SnmpVarbind {
            oid: "1.3.6.1.2.1.1.5.0".to_string(),
            value: SnmpValue::OctetString(b"router".to_vec()),
        }]);
        let set = build_request(&config, 10).unwrap();
        assert_eq!(set.version, SNMP_VERSION_2C);
        assert_eq!(set.community, "private");
        assert_eq!(set.pdu.pdu_type, SNMP_PDU_SET_REQUEST);
        assert_eq!(set.pdu.error_status, 0);
        assert_eq!(set.pdu.error_index, 0);
        assert_eq!(set.pdu.varbinds.len(), 1);
    }

    #[test]
    fn set_request_round_trips_over_wire() {
        let config = Config {
            agent: "127.0.0.1:161".to_string(),
            community: "private".to_string(),
            operation: Operation::Set(vec![SnmpVarbind {
                oid: "1.3.6.1.2.1.1.5.0".to_string(),
                value: SnmpValue::OctetString(b"edge-router".to_vec()),
            }]),
            oids: Vec::new(),
        };
        let request = build_request(&config, 11).unwrap();
        let bytes = request.try_serialize().unwrap();
        let parsed = SnmpMessage::parse(&bytes).unwrap();
        assert_eq!(parsed, request);
    }

    fn response(request_id: i32) -> SnmpMessage {
        SnmpMessage {
            version: 1,
            community: "public".to_string(),
            pdu: SnmpPdu {
                pdu_type: SNMP_PDU_RESPONSE,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![SnmpVarbind {
                    oid: "1.3.6.1.2.1.1.1.0".to_string(),
                    value: SnmpValue::OctetString(b"router".to_vec()),
                }],
            },
        }
    }

    #[test]
    fn response_validation_checks_identity_and_agent_errors() {
        let valid = response(42);
        assert!(validate_response(&valid, "public", 42).is_ok());
        assert!(validate_response(&valid, "private", 42).is_err());
        assert!(validate_response(&valid, "public", 41).is_err());

        let mut errored = response(42);
        errored.pdu.error_status = 5;
        errored.pdu.error_index = 1;
        assert_eq!(
            validate_response(&errored, "public", 42).unwrap_err(),
            "agent returned error-status 5 at error-index 1"
        );
    }
}
