use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::stack::{
    IPV6_RTR_SOLICITATION_INTERVAL_MS, Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig,
};

fn host_stack() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ip: Ipv4Address::new(10, 0, 0, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

#[test]
fn restarted_router_discovery_schedules_retries_from_current_clock() {
    let mut stack = host_stack();

    stack.start_router_discovery();
    assert_eq!(
        stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS).len(),
        1
    );
    assert_eq!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2)
            .len(),
        1
    );
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Exhausted
    );

    let restart_at = IPV6_RTR_SOLICITATION_INTERVAL_MS * 10;
    assert!(stack.step_timers(restart_at).is_empty());

    let first = stack.start_router_discovery();
    assert!(!first.is_empty());
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );

    assert!(
        stack
            .step_timers(restart_at + IPV6_RTR_SOLICITATION_INTERVAL_MS - 1)
            .is_empty()
    );
    assert_eq!(
        stack
            .step_timers(restart_at + IPV6_RTR_SOLICITATION_INTERVAL_MS)
            .len(),
        1
    );
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 2
        }
    );
}

#[test]
fn cancelling_after_exhaustion_returns_discovery_to_idle() {
    let mut stack = host_stack();

    stack.start_router_discovery();
    stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS);
    stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Exhausted
    );

    stack.cancel_router_discovery();
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle
    );
    assert!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 20)
            .is_empty()
    );
}
