use std::io::ErrorKind;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use toy_tcpip::snmp::{
    SNMP_PDU_RESPONSE, SNMP_PDU_SET_REQUEST, SNMP_VERSION_2C, SnmpMessage, SnmpPdu, SnmpValue,
    SnmpVarbind,
};

const SYS_DESCR_OID: &str = "1.3.6.1.2.1.1.1.0";
const SYS_NAME_OID: &str = "1.3.6.1.2.1.1.5.0";
const UNKNOWN_OID: &str = "1.3.6.1.2.1.1.99.0";

struct Agent {
    child: Child,
    addr: String,
}

impl Agent {
    fn spawn() -> Self {
        let reservation = UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
        let addr = reservation.local_addr().expect("reserved address");
        drop(reservation);

        let child = Command::new(env!("CARGO_BIN_EXE_snmp_agent"))
            .arg(addr.to_string())
            .arg("public")
            .arg("private")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn snmp_agent");

        let agent = Self {
            child,
            addr: addr.to_string(),
        };
        agent.wait_until_ready();
        agent
    }

    fn wait_until_ready(&self) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind readiness probe");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set readiness timeout");
        let request = SnmpMessage::build_get_request("public", 1, &[SYS_NAME_OID])
            .try_serialize()
            .expect("serialize readiness request");
        let mut response = [0u8; 2048];

        for _ in 0..30 {
            socket
                .send_to(&request, &self.addr)
                .expect("send readiness request");
            match socket.recv_from(&mut response) {
                Ok(_) => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
                    ) =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("readiness probe failed: {error}"),
            }
        }

        panic!("snmp_agent did not become ready");
    }

    fn request(&self, request: &SnmpMessage) -> SnmpMessage {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind request socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set request timeout");
        let bytes = request.try_serialize().expect("serialize request");
        socket.send_to(&bytes, &self.addr).expect("send request");

        let mut response = [0u8; 4096];
        let (received, _) = socket.recv_from(&mut response).expect("receive response");
        SnmpMessage::parse(&response[..received]).expect("parse response")
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn set_request(community: &str, request_id: i32, varbinds: Vec<SnmpVarbind>) -> SnmpMessage {
    SnmpMessage {
        version: SNMP_VERSION_2C,
        community: community.to_string(),
        pdu: SnmpPdu {
            pdu_type: SNMP_PDU_SET_REQUEST,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        },
    }
}

fn varbind(oid: &str, value: SnmpValue) -> SnmpVarbind {
    SnmpVarbind {
        oid: oid.to_string(),
        value,
    }
}

fn assert_response(response: &SnmpMessage, request_id: i32, status: i32, index: i32) {
    assert_eq!(response.pdu.pdu_type, SNMP_PDU_RESPONSE);
    assert_eq!(response.pdu.request_id, request_id);
    assert_eq!(response.pdu.error_status, status);
    assert_eq!(response.pdu.error_index, index);
}

fn get_sys_name(agent: &Agent, request_id: i32) -> SnmpValue {
    let request = SnmpMessage::build_get_request("public", request_id, &[SYS_NAME_OID]);
    let response = agent.request(&request);
    assert_response(&response, request_id, 0, 0);
    assert_eq!(response.pdu.varbinds.len(), 1);
    response.pdu.varbinds[0].value.clone()
}

#[test]
fn agent_udp_path_covers_set_state_authorization_and_atomicity() {
    let agent = Agent::spawn();

    assert_eq!(
        get_sys_name(&agent, 10),
        SnmpValue::OctetString(b"toy-router.local".to_vec())
    );

    let denied = agent.request(&set_request(
        "public",
        11,
        vec![varbind(
            SYS_NAME_OID,
            SnmpValue::OctetString(b"forbidden-change".to_vec()),
        )],
    ));
    assert_response(&denied, 11, 16, 0);
    assert_eq!(
        get_sys_name(&agent, 12),
        SnmpValue::OctetString(b"toy-router.local".to_vec())
    );

    let wrong_type = agent.request(&set_request(
        "private",
        13,
        vec![varbind(SYS_NAME_OID, SnmpValue::Integer(7))],
    ));
    assert_response(&wrong_type, 13, 7, 1);

    let not_writable = agent.request(&set_request(
        "private",
        14,
        vec![varbind(
            SYS_DESCR_OID,
            SnmpValue::OctetString(b"replacement".to_vec()),
        )],
    ));
    assert_response(&not_writable, 14, 17, 1);

    let no_creation = agent.request(&set_request(
        "private",
        15,
        vec![varbind(
            UNKNOWN_OID,
            SnmpValue::OctetString(b"replacement".to_vec()),
        )],
    ));
    assert_response(&no_creation, 15, 11, 1);

    let atomic_failure = agent.request(&set_request(
        "private",
        16,
        vec![
            varbind(
                SYS_NAME_OID,
                SnmpValue::OctetString(b"must-not-stick".to_vec()),
            ),
            varbind(UNKNOWN_OID, SnmpValue::OctetString(b"missing".to_vec())),
        ],
    ));
    assert_response(&atomic_failure, 16, 11, 2);
    assert_eq!(
        get_sys_name(&agent, 17),
        SnmpValue::OctetString(b"toy-router.local".to_vec())
    );

    let set = agent.request(&set_request(
        "private",
        18,
        vec![varbind(
            SYS_NAME_OID,
            SnmpValue::OctetString(b"edge-router.test".to_vec()),
        )],
    ));
    assert_response(&set, 18, 0, 0);
    assert_eq!(
        get_sys_name(&agent, 19),
        SnmpValue::OctetString(b"edge-router.test".to_vec())
    );
}
