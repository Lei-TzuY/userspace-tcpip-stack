use std::io::ErrorKind;
use std::net::UdpSocket;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use toy_tcpip::snmp::SnmpMessage;

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
        let request = SnmpMessage::build_get_request("public", 1, &[SYS_NAME_OID]);
        let request = request
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
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("readiness probe failed: {error}"),
            }
        }

        panic!("snmp_agent did not become ready");
    }

    fn client(&self, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_snmp_client"))
            .arg(&self.addr)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run snmp_client");
        let deadline = Instant::now() + Duration::from_secs(5);

        loop {
            match child.try_wait().expect("poll snmp_client") {
                Some(_) => {
                    return child
                        .wait_with_output()
                        .expect("collect snmp_client output");
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("collect timed-out snmp_client output");
                    panic!(
                        "snmp_client timed out\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

#[test]
fn client_and_agent_cover_management_and_set_error_paths() {
    let agent = Agent::spawn();

    let initial = agent.client(&["public", "get", SYS_NAME_OID]);
    assert_success(&initial);
    assert!(stdout(&initial).contains("STRING: \"toy-router.local\""));

    let denied = agent.client(&["public", "set", SYS_NAME_OID, "string", "forbidden-change"]);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("error-status 16 at error-index 0"));

    let unchanged = agent.client(&["public", "get", SYS_NAME_OID]);
    assert_success(&unchanged);
    assert!(stdout(&unchanged).contains("STRING: \"toy-router.local\""));

    let wrong_type = agent.client(&["private", "set", SYS_NAME_OID, "integer", "7"]);
    assert!(!wrong_type.status.success());
    assert!(stderr(&wrong_type).contains("error-status 7 at error-index 1"));

    let not_writable = agent.client(&["private", "set", SYS_DESCR_OID, "string", "replacement"]);
    assert!(!not_writable.status.success());
    assert!(stderr(&not_writable).contains("error-status 17 at error-index 1"));

    let no_creation = agent.client(&["private", "set", UNKNOWN_OID, "string", "replacement"]);
    assert!(!no_creation.status.success());
    assert!(stderr(&no_creation).contains("error-status 11 at error-index 1"));

    let atomic_failure = agent.client(&[
        "private",
        "set",
        SYS_NAME_OID,
        "string",
        "must-not-stick",
        UNKNOWN_OID,
        "string",
        "missing",
    ]);
    assert!(!atomic_failure.status.success());
    assert!(stderr(&atomic_failure).contains("error-status 11 at error-index 2"));

    let still_unchanged = agent.client(&["public", "get", SYS_NAME_OID]);
    assert_success(&still_unchanged);
    assert!(stdout(&still_unchanged).contains("STRING: \"toy-router.local\""));

    let set = agent.client(&["private", "set", SYS_NAME_OID, "string", "edge-router.test"]);
    assert_success(&set);
    assert!(stdout(&set).contains("STRING: \"edge-router.test\""));

    let updated = agent.client(&["public", "get", SYS_NAME_OID]);
    assert_success(&updated);
    assert!(stdout(&updated).contains("STRING: \"edge-router.test\""));
}
