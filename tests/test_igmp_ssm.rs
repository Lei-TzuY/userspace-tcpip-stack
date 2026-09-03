//! Integration tests for IGMPv3 & Source-Specific Multicast (SSM) Engine (RFC 3376, RFC 4607).

use toy_tcpip::igmp_ssm::{
    IGMPV3_ALLOW_NEW_SOURCES, IGMPV3_BLOCK_OLD_SOURCES, IGMPV3_MODE_IS_EXCLUDE,
    IGMPV3_MODE_IS_INCLUDE, Igmpv3GroupRecord, Igmpv3HostState, Igmpv3Query, Igmpv3Report,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_igmpv3_general_and_ssm_query_codec() {
    // 1. General Query
    let gen_query = Igmpv3Query::build_general_query(100, 2, 20);
    assert!(gen_query.is_general_query());
    assert!(!gen_query.is_group_specific());
    assert!(!gen_query.is_group_and_source_specific());

    let raw_gen = gen_query.serialize();
    let parsed_gen = Igmpv3Query::parse(&raw_gen, true).unwrap();
    assert_eq!(parsed_gen.max_resp_code, 100);
    assert_eq!(parsed_gen.group_address, Ipv4Address::UNSPECIFIED);

    // 2. Group-and-Source-Specific Query (SSM)
    let ssm_group = Ipv4Address([232, 1, 2, 3]);
    let ssm_src1 = Ipv4Address([192, 0, 2, 10]);
    let ssm_src2 = Ipv4Address([192, 0, 2, 20]);
    let ssm_query =
        Igmpv3Query::build_group_and_source_specific(ssm_group, vec![ssm_src1, ssm_src2], 50);
    assert!(ssm_query.is_group_and_source_specific());

    let raw_ssm = ssm_query.serialize();
    let parsed_ssm = Igmpv3Query::parse(&raw_ssm, true).unwrap();
    assert_eq!(parsed_ssm.group_address, ssm_group);
    assert_eq!(parsed_ssm.source_addresses, vec![ssm_src1, ssm_src2]);
}

#[test]
fn test_igmpv3_membership_report_multi_record_roundtrip() {
    let group_a = Ipv4Address([232, 10, 10, 10]);
    let group_b = Ipv4Address([239, 1, 1, 1]);

    let rec_a = Igmpv3GroupRecord::new(
        IGMPV3_MODE_IS_INCLUDE,
        group_a,
        vec![Ipv4Address([10, 1, 1, 1]), Ipv4Address([10, 1, 1, 2])],
    );
    let rec_b = Igmpv3GroupRecord::new(
        IGMPV3_MODE_IS_EXCLUDE,
        group_b,
        vec![Ipv4Address([10, 2, 2, 2])],
    );

    let report = Igmpv3Report::new(vec![rec_a, rec_b]);
    let raw = report.serialize();

    let parsed = Igmpv3Report::parse(&raw, true).unwrap();
    assert_eq!(parsed.group_records.len(), 2);
    assert_eq!(parsed.group_records[0].record_type, IGMPV3_MODE_IS_INCLUDE);
    assert_eq!(parsed.group_records[0].multicast_address, group_a);
    assert_eq!(parsed.group_records[0].source_addresses.len(), 2);

    assert_eq!(parsed.group_records[1].record_type, IGMPV3_MODE_IS_EXCLUDE);
    assert_eq!(parsed.group_records[1].multicast_address, group_b);
    assert_eq!(parsed.group_records[1].source_addresses.len(), 1);
}

#[test]
fn test_igmpv3_ssm_channel_join_leave_lifecycle() {
    let mut host = Igmpv3HostState::new();
    let channel_group = Ipv4Address([232, 40, 50, 60]);
    let active_source = Ipv4Address([198, 51, 100, 77]);
    let rogue_source = Ipv4Address([198, 51, 100, 99]);

    // Initially, host receives nothing for this channel
    assert!(!host.should_receive(active_source, channel_group));

    // Join (S, G) channel
    let join_report = host.join_ssm_channel(active_source, channel_group);
    assert_eq!(join_report.group_records.len(), 1);
    assert_eq!(
        join_report.group_records[0].record_type,
        IGMPV3_ALLOW_NEW_SOURCES
    );
    assert_eq!(
        join_report.group_records[0].source_addresses,
        vec![active_source]
    );

    // Host should now receive from active_source, but filter out rogue_source
    assert!(host.should_receive(active_source, channel_group));
    assert!(!host.should_receive(rogue_source, channel_group));

    // Leave channel
    let leave_report = host.leave_ssm_channel(active_source, channel_group);
    assert_eq!(
        leave_report.group_records[0].record_type,
        IGMPV3_BLOCK_OLD_SOURCES
    );
    assert!(!host.should_receive(active_source, channel_group));
}
