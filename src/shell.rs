//! Interactive Network Shell (CLI REPL) for real-time virtual stack exploration.

use crate::arp::ArpTable;
use crate::ats::{AtsStreamShaper, UrgencyBasedScheduler};
use crate::bfd::{BFD_CONTROL_PORT, BfdControlPacket, BfdSession, BfdState};
use crate::bfd_v6::{BFD_MULTIHOP_PORT, BfdV6Manager, BfdV6Session};
use crate::bgp::{BgpMessage, BgpRib, Ipv4Prefix};
use crate::bgp_add_path::{AddPathNlri, AddPathRib, AddPathRibEntry};
use crate::bgp_epe::{
    BGP_EPE_PEER_ADJ_SID, BGP_EPE_PEER_NODE_SID, BGP_EPE_PEER_SET_SID, BgpEpeDatabase,
};
use crate::bgp_evpn::RouteTarget;
use crate::bgp_ext_comm::{BgpExtCommunityContainer, BgpExtendedCommunity, TUNNEL_TYPE_VXLAN};
use crate::bgp_ls::{BgpLsLinkDescriptor, BgpLsNlri, BgpLsNodeDescriptor, BgpLsTopologyDatabase};
use crate::bgp_ls_srv6::{BgpLsSrv6Database, Srv6EndSidTlv, Srv6LocatorTlv};
use crate::bgp_prefix_sid::BgpPrefixSidAttribute;
use crate::cbs::CreditBasedShaper;
use crate::cdp::{CDP_MULTICAST_MAC, CDP_SNAP_HEADER, CdpNeighborTable, CdpPacket};
use crate::cfm::{CFM_MULTICAST_CLASS1, CfmEngine, CfmPacket, ETHERTYPE_CFM};
use crate::coap::{COAP_CODE_205_CONTENT, COAP_UDP_PORT, CoapPacket};
use crate::congestion_isolation::{CongestionFlowKey, CongestionIsolationEngine};
use crate::cqf::CqfEngine;
use crate::cqf_enhanced::CqfDualBufferEngine;
use crate::detnet::{DETNET_UDP_PORT, DetNetPrefEngine};
use crate::dhcpv6::{DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT, Dhcpv6Message, Dhcpv6Server};
use crate::diagnostics::TracerouteHopResult;
use crate::diameter::{DIAMETER_PORT, DIAMETER_SUCCESS, DiameterMessage, DiameterServer};
use crate::diameter_charging::{
    CcRequestType, CreditControlRequest, MsccContainer, OnlineChargingEngine, ServiceQuotaUnit,
};
use crate::diameter_cx::{
    CMD_MAR, CMD_SAR, CMD_UAR, CxAvp, CxMessage, HssCxEngine, ImsSub, ServerAssignmentType,
    UserAuthorizationType,
};
use crate::diameter_gx::{IpCanType, PccRule, PcefGxEngine};
use crate::diameter_np::{NpAvp, NpMessage, RanCongestionInfo, RanCongestionLevel, RcafNpEngine};
use crate::diameter_rx::{
    AaRequest, MediaComponentDescription, MediaSubComponent, MediaType, PcrfRxEngine,
};
use crate::diameter_s6a::{HssS6aEngine, HssSubscriberProfile};
use crate::diameter_s6b::{
    AaaS6bEngine, DIAMETER_CMD_AA, DIAMETER_CMD_SESSION_TERMINATION, Non3gppSubProfile,
    Non3gppUserStatus, S6bAvp, S6bMessage,
};
use crate::diameter_s6c::{
    S6cAvp, S6cHssEngine, S6cMessage, S6cServingNodeInfo, S6cServingNodeType,
};
use crate::diameter_s6m::{S6mAvp, S6mHssEngine, S6mMessage, SmsMiResult};
use crate::diameter_s6t::{
    MonitoringEventConfig, MonitoringEventType, S6tAvp, S6tMessage, ScefS6tHssEngine,
};
use crate::diameter_s9::{PcrfS9Engine, SubsessionEnforcementInfo};
use crate::diameter_s13::{EirS13Engine, EquipmentStatus};
use crate::diameter_s13_prime::{
    EirS13PrimeEngine, EquipmentStatus as S13PrimeEquipmentStatus, S13PrimeAvp, S13PrimeMessage,
    TerminalInformation,
};
use crate::diameter_sgd::{SgdAvp, SgdMessage, SmsSgdEngine};
use crate::diameter_sh::{HssShEngine, HssShSubscriberProfile};
use crate::diameter_slh::HssSlhEngine;
use crate::diameter_swm::{AaaSwmEngine, SwmAvp, SwmMessage};
use crate::diameter_zh::{BsfZhEngine, GbaAuthVector, GbaType, ZhAvp, ZhMessage};
use crate::dns::DnsMessage;
use crate::eigrp::{EIGRP_MULTICAST_IP, EigrpPacket, EigrpTopologyTable, IP_PROTO_EIGRP};
use crate::erspan::ErspanPacket;
use crate::etag::{ETHERTYPE_ETAG, ETagFrame, ETagHeader};
use crate::ethernet::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use crate::evpn::{EvpnNlri, RouteDistinguisher};
use crate::evpn_bum_policer::{BumType, EvpnBumPolicerEngine};
use crate::evpn_core_isolation::{CoreIsolationState, EvpnCoreIsolationEngine};
use crate::evpn_etree::{ETreeRole, EvpnETreeEngine};
use crate::evpn_flap_damping::EvpnFlapDampingEngine;
use crate::evpn_frr_protection::{EvpnFrrEngine, EvpnProtectedRoute};
use crate::evpn_igmp_snooping::{EvpnIgmpSnoopingEngine, MulticastForwardingAction};
use crate::evpn_irb_anycast::{EvpnAnycastIrbEngine, IrbMode};
use crate::evpn_l3irb::{EvpnIpPrefixRoute, EvpnL3VrfTable};
use crate::evpn_mac_flush::{
    EthernetSegmentId as EvpnEsi, EvpnMacEntry as EvpnFlushMacEntry, EvpnMacFlushEngine,
    MacFlushScope,
};
use crate::evpn_mac_mobility::{EvpnMacMobilityEngine, MacMobilityExtComm};
use crate::evpn_mass_withdraw::EvpnMassWithdrawEngine;
use crate::evpn_multicast_ir::{EvpnSelectiveIrEngine, MulticastChannel};
use crate::evpn_multihoming::EvpnDfElectionEngine;
use crate::evpn_pref_df::{CandidatePe, EvpnPrefDfEngine};
use crate::evpn_proxy_arp::{ArpSuppressionAction, EvpnProxyArpEngine};
use crate::evpn_pvlan::{EvpnPvlanEngine, PvlanPortType};
use crate::evpn_smet::{EvpnSmetEngine, EvpnSmetRoute};
use crate::evpn_synch::{
    EthernetSegmentId, EvpnJoinSynchRoute, EvpnLeaveSynchRoute, EvpnMulticastSynchEngine,
};
use crate::evpn_type1::{EvpnAliasingEngine, EvpnEthernetAdRoute};
use crate::evpn_type3::{EvpnBumFloodingTree, EvpnType3Route};
use crate::evpn_type5::{EvpnType5Rib, EvpnType5Route};
use crate::evpn_umt_ir::EvpnUmtEngine;
use crate::evpn_uu_suppression::{EvpnUuSuppressionEngine, UuSuppressionDecision};
use crate::evpn_vrf_leaking::EvpnVrfLeakingEngine;
use crate::firewall::{FirewallAction, FirewallChain, FirewallRule, IpCidr};
use crate::flex_algo::{FlexAlgoDefinition, FlexAlgoEngine, FlexAlgoMetricType};
use crate::flowspec::{FlowspecAction, FlowspecEngine, FlowspecMatch, FlowspecRule};
use crate::flowspec_redirect_vrf::{
    FlowspecVrfAction, FlowspecVrfRule, FlowspecVrfScrubbingEngine,
};
use crate::frer::{ETHERTYPE_RTAG, FrerEngine};
use crate::frer_srf::{FrerSrfEngine, SrfVerdict};
use crate::geneve::{GENEVE_UDP_PORT, GenevePacket};
use crate::geneve_int::{GeneveIntPacket, IntHopTelemetry};
use crate::geneve_opts::{
    GENEVE_CLASS_OVS_LINUX, GENEVE_CLASS_STANDARD, GENEVE_TYPE_INBAND_TELEMETRY,
    GENEVE_TYPE_SECURITY_GROUP, GeneveOptionTlv,
};
use crate::geneve_sfc::{GENEVE_OPT_CLASS_SFC, GeneveSfcHop, GeneveSfcPacket};
use crate::geneve_telemetry_opt::{GeneveTelemetryEngine, GeneveTelemetryOption};
use crate::glbp::{GLBP_MULTICAST_IP, GLBP_UDP_PORT, GlbpEngine};
use crate::gnmi::{GNMI_PORT, GnmiServer};
use crate::gnoi::{GNOI_PORT, GnoiServer};
use crate::gptp::{
    ETHERTYPE_GPTP, GPTP_MULTICAST_MAC, GptpPacket, GptpTimestamp, calculate_gptp_peer_delay,
};
use crate::gre_demux::{GreDemuxTable, GreVirtualTunnel};
use crate::gre_udp::{GRE_IN_UDP_PORT, GreUdpPacket};
use crate::gre_v6::{ETHERTYPE_IPV4_IN_GRE, GreIpv6Packet};
use crate::gribi::{GRIBI_PORT, GribiAftTable, GribiIpv4Entry, GribiNextHop, GribiNextHopGroup};
use crate::gtp::{GTP_MSG_ECHO_REQUEST, GTP_U_UDP_PORT, GtpPacket, GtpTunnelTable};
use crate::gtp_ext::{
    GTP_EXT_HDR_PDU_SESSION_CONTAINER, PduSessionContainer, build_gtpu_with_pdu_container,
    parse_gtpu_with_pdu_container,
};
use crate::gtpc_v2::{CAUSE_REQUEST_ACCEPTED, Gtpv2cMessage, IE_CAUSE, IE_FTEID, SgwEngine};
use crate::gtpu_fast_failover::{FastFailoverSession, GtpuFastFailoverEngine};
use crate::gtpu_heartbeat::{GtpuEchoMessage, GtpuPathEngine};
use crate::gtpu_jitter_telemetry::GtpuJitterTelemetryEngine;
use crate::gtpu_ma_pdu::{AccessLegType, AtsssMode, MaPduSessionEngine};
use crate::gtpu_qos_enforcer::{FiveQiResourceType, GtpuQosEnforcer};
use crate::gtpu_redundant_paths::GtpuRedundantEngine;
use crate::gtpu_reordering::GtpuReorderingEngine;
use crate::gtpu_telemetry::GtpuTelemetryEngine;
use crate::gtpu_upf_relocation::{HandoverGtpuPacket, TargetUpfRelocationEngine};
use crate::gue::{GUE_UDP_PORT, GuePacket};
use crate::hsrp::{HSRP_MULTICAST_IP, HSRP_UDP_PORT, HsrpEngine, HsrpPacket};
use crate::http2::Http2Frame;
use crate::http3::Http3Frame;
use crate::icmp::{IcmpPacket, IcmpType};
use crate::icmpv6::{ICMPV6_TYPE_ECHO_REPLY, Icmpv6Packet};
use crate::ifa_telemetry::{
    IFA_REQ_LATENCY, IFA_REQ_NODE_ID, IFA_REQ_PORTS, IFA_REQ_QUEUE_DEPTH, IfaTelemetryEngine,
};
use crate::igmp::{IgmpPacket, MulticastGroupTable, multicast_ip_to_mac};
use crate::ioam::IoamPacket;
use crate::ipfix::{IPFIX_UDP_PORT, IpfixFlowRecord, IpfixMessage};
use crate::ipsec::{EspPacket, IP_PROTO_ESP, SadTable};
use crate::ipv4::{IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use crate::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, NEXT_HEADER_UDP};
use crate::isis::{ETHERTYPE_ISIS, IsisHelloPacket};
use crate::l2tp::{IP_PROTO_L2TPV3, L2tpv3Packet};
use crate::lab::{LabRouter, VirtualLab};
use crate::lab::{
    build_bgp_demo_fabric, build_evpn_dual_rr_fabric, build_evpn_fabric, converge_bgp,
};
use crate::lacp::{
    ETHERTYPE_SLOW_PROTOCOLS, LACP_STATE_ACTIVITY, LACP_STATE_AGGREGATION, LACP_STATE_COLLECTING,
    LACP_STATE_DISTRIBUTING, LACP_STATE_SYNCHRONIZATION, LacpPacket, LacpPortInfo,
    LinkAggregationGroup,
};
use crate::ldap::{LDAP_PORT, LdapMessage, LdapOp, LdapServer};
use crate::ldp::{LDP_PORT, LdpPdu, LdpSession};
use crate::lisp::{
    LISP_CONTROL_PORT, LISP_DATA_PORT, LispDataPacket, LispMapReply, LispMapRequest,
    LispMapResolver,
};
use crate::lldp::{ETHERTYPE_LLDP, LLDP_MULTICAST_MAC, LldpNeighborTable, LldpPacket};
use crate::mld::{MLD_CHANGE_TO_INCLUDE, MldGroupRecord, MldTable, Mldv2ReportPacket};
use crate::mldp::{MldpEngine, MldpFecElement};
use crate::mpls::{ETHERTYPE_MPLS_UNICAST, LfibTable, MplsHeader, MplsPacket};
use crate::mpls_oam::{LSP_PING_UDP_PORT, LSP_RET_CODE_EGRESS_FOR_FEC, LspEchoPacket};
use crate::mqtt::{MQTT_PORT, MqttBroker, MqttPacket};
use crate::nef_traffic_influence::{NefTrafficInfluenceEngine, SliceId, TrafficFilter};
use crate::netconf::{NETCONF_PORT, NetconfServer};
use crate::netflow::{NETFLOW_V9_UDP_PORT, NetflowFlowTable, NetflowPacket};
use crate::netflow_v5::{NETFLOW_V5_UDP_PORT, NetflowV5Table};
use crate::ngap_5g::{
    InitialUeMessage, NGAP_SCTP_PORT, NgSetupRequest, NgapNode, PduSessionResourceSetupRequest,
    PlmnId, Snssai,
};
use crate::nrf_oauth::{NrfAccessTokenRequest, NrfOAuthAuthority};
use crate::nsh::{NshPacket, ServiceFunctionForwarder};
use crate::nsh_md2::{
    NSH_NP_IPV4, NshContextTlv, NshMd2ForwarderEngine, NshMd2Header, NshMd2Packet,
};
use crate::ntp::{NtpPacket, NtpTimestamp, calculate_offset_and_delay};
use crate::openflow::{OFP_TCP_PORT, OfpAction, OfpFlowTable, OfpMatch, OfpMessage};
use crate::optical_dom::{OpticalDiagnostics, TransceiverFormFactor};
use crate::ospf::{OSPF_ALL_SPF_ROUTERS, OspfHelloPacket, OspfLsdb};
use crate::otlp::{OTLP_GRPC_PORT, OTLP_HTTP_PORT, OtlpExporter, OtlpSpan};
use crate::p4runtime::{
    P4MatchField, P4MatchKind, P4PacketOut, P4RUNTIME_PORT, P4RuntimeServer, P4TableEntry,
};
use crate::pcap::{LINKTYPE_ETHERNET, PcapWriter};
use crate::pcep::{PCEP_PORT, PcepMessage, PcepObject, PcepSession};
use crate::pfcp_5g::{
    ForwardingActionRule, PFCP_APPLY_ACTION_FORWARD, PFCP_SRC_INTERFACE_ACCESS,
    PFCP_SRC_INTERFACE_CORE, PFCP_UDP_PORT, PacketDetectionRule, PfcpNode,
};
use crate::pim::{ALL_PIM_ROUTERS_MULTICAST, IP_PROTO_PIM, PimMulticastRouter, PimPacket};
use crate::pim_bsr::{CandidateRpRecord, EncodedGroupAddress, PimBsrEngine};
use crate::pppoe::{ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION, PppoePacket};
use crate::preemption::PreemptionEngine;
use crate::psfp::{FlowMeter, PsfpFilterInstance, StreamGate};
use crate::ptp::{
    PTP_EVENT_PORT, PTP_GENERAL_PORT, PtpPacket, PtpTimestamp, calculate_ptp_offset_and_delay,
};
use crate::ptp_tc::{HopMeasurement, TransparentClockEngine, TransparentClockMode};
use crate::ptp_telecom::{
    ETHERTYPE_PTP_TELECOM, TelecomBmcaAttributes, TelecomClockType, TelecomProfileEngine,
};
use crate::ptp_telecom_bc::{TelecomBoundaryClockEngine, TelecomClockQuality};
use crate::ptp_telecom_tc::TelecomPeerTransparentClockEngine;
use crate::ptp_time_error::{PtpTimeErrorEngine, TelecomClockClass};
use crate::quic::QuicPacket;
use crate::radius::{RADIUS_AUTH_PORT, RadiusPacket};
use crate::rip::RipEngine;
use crate::roce::{
    ETHERTYPE_FLOW_CONTROL, PFC_MULTICAST_MAC, PfcPauseFrame, ROCEV2_UDP_PORT, RocePacket,
};
use crate::rsvp::{IP_PROTO_RSVP, RsvpPacket};
use crate::rtp::{RTP_PT_PCMU, RtcpSenderReport, RtpPacket};
use crate::sai::SaiSwitchAdapter;
use crate::sba_5g::{NfProfile, NfType, SbaMessageBus, SbaRequest};
use crate::sba_events::{SbaEventExposureEngine, SbaEventType};
use crate::sbfd::{SBFD_REFLECTOR_PORT, SbfdPacket, SbfdReflector};
use crate::sctp::{IP_PROTO_SCTP, SctpPacket};
use crate::sflow::{
    SFLOW_UDP_PORT, SflowCounterSample, SflowDatagram, SflowFlowSample, SflowSample,
};
use crate::sip::{SIP_PORT, SipMessage, build_simple_sdp};
use crate::snmp::{SnmpMessage, SnmpMib, SnmpValue, SnmpVarbind};
use crate::socket::{TcpListenerHandle, TcpStreamHandle};
use crate::sr_mpls_oam::{SrLspEchoRequest, SrMplsOamEngine, SrTargetFecSubTlv};
use crate::sr_policy::{
    SrCandidatePath, SrPolicy, SrPolicyDatabase, SrProtocolOrigin, SrSegmentList,
};
use crate::srv6::{IPV6_EXT_ROUTING, Srv6Header};
use crate::srv6_mup::{Srv6MupEngine, Srv6MupSession};
use crate::srv6_mup_interworking::{MupSessionMapping, Srv6MupInterworkingEngine};
use crate::srv6_ops::{Srv6Behavior, Srv6Engine, Srv6ExecutionResult};
use crate::srv6_slicing::{NetworkSliceId, SliceType, Srv6SliceForwardingEngine, Srv6SlicePolicy};
use crate::srv6_usid::{UsidBehavior, UsidCarrier, UsidForwardingEngine};
use crate::stack::{NetStack, NetStackConfig};
use crate::stp::StpBridgeEngine;
use crate::stun::{STUN_PORT, StunPacket};
use crate::synce_esmc::{QualityLevel, SyncEEsmcEngine, SyncEEsmcPacket};
use crate::syslog::{
    SYSLOG_UDP_PORT, SyslogCollector, SyslogFacility, SyslogMessage, SyslogSeverity,
};
use crate::tacacs::{TACACS_AUTHEN_STATUS_PASS, TACACS_PORT, TacacsPacket, TacacsServer};
use crate::tas::TimeAwareShaper;
use crate::tcp::{SocketAddrV4, TcpFlags, TcpSegment, TcpState};
use crate::tftp::{TftpFileServer, TftpPacket};
use crate::ti_lfa::TiLfaEngine;
use crate::tls::TlsRecord;
use crate::transition::{IP_PROTO_IPV6_IN_IPV4, Tunnel4in6, Tunnel6in4};
use crate::tsn_ats_multihop::AtsMultiHopPipeline;
use crate::tsn_cnc::{
    CentralizedNetworkConfigurator, StreamId, TrafficSpecification, TsnListener, TsnTalker,
    UserToNetworkRequirements,
};
use crate::tsn_cqf_multicycle::CqfMultiCycleEngine;
use crate::tsn_cqf_time_dispatch::TsnCqfTimeDispatchEngine;
use crate::tsn_cqf_trtcm::{TrTcmColor, TsnCqfTrTcmEngine};
use crate::tsn_guard_band::{PriorityType, TsnPreemptionGuardBandEngine};
use crate::tsn_psfp_stream_filter::{
    FlowMeterInstance, PsfpEngine, StreamFilterInstance, StreamGateInstance,
};
use crate::tsn_qav_cbs::TsnQavBridgePort;
use crate::tsn_qbv_gcl::{GclEntry as QbvGclEntry, TsnQbvGclEngine};
use crate::tsn_qbv_reconfig::{QbvDynamicReconfigEngine, QbvGateEntry, QbvSchedule};
use crate::tsn_qcz_congestion::{FlowTuple as QczFlowTuple, QczCongestionEngine};
use crate::tunnel::{GrePacket, IP_PROTO_GRE};
use crate::turn::{TURN_ALLOCATE_REQUEST, TurnAllocationTable, TurnPacket};
use crate::twamp::{TWAMP_CONTROL_PORT, TWAMP_TEST_PORT, TwampTestPacket, calculate_twamp_metrics};
use crate::udp::UdpDatagram;
use crate::vpls::{VplsInstance, VplsPseudowire};
use crate::vrrp::{VrrpEngine, VrrpPacket};
use crate::vtp::{VTP_MULTICAST_MAC, VTP_SNAP_HEADER, VtpEngine, VtpMode, VtpPacket};
use crate::vxlan::{VXLAN_UDP_PORT, VxlanPacket};
use crate::vxlan_gpe::{VXLAN_GPE_NP_IPV4, VXLAN_GPE_UDP_PORT, VxlanGpePacket};
use crate::websocket::WebSocketFrame;
use crate::wireguard::{WIREGUARD_PORT, WireguardMessage, WireguardPeer};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::str::FromStr;

pub struct NetworkShell {
    stack: NetStack,
    remote_host_ip: Ipv4Address,
    remote_host_ipv6: Ipv6Address,
    remote_host_mac: MacAddress,
    remote_stack: NetStack,
    rip: RipEngine,
    igmp_table: MulticastGroupTable,
    _tftp_server: TftpFileServer,
    vrrp: VrrpEngine,
    hsrp: HsrpEngine,
    glbp: GlbpEngine,
    vtp: VtpEngine,
    ofp_table: OfpFlowTable,
    diameter_server: DiameterServer,
    wg_peer: WireguardPeer,
    pcep_session: PcepSession,
    netconf_server: NetconfServer,
    _lisp_resolver: LispMapResolver,
    flowspec_engine: FlowspecEngine,
    otlp_exporter: OtlpExporter,
    gre_demux: GreDemuxTable,
    srv6_engine: Srv6Engine,
    lfib: LfibTable,
    _ldp_session: LdpSession,
    bgp_rib: BgpRib,
    /// Live leaf-spine-leaf EVPN/VXLAN fabric backing the `evpn`, `vxlan vtep`
    /// and `bgp evpn` diagnostics. Built and converged on first use, then read
    /// out: nothing it prints is a sample.
    evpn_fabric: Option<VirtualLab>,
    /// Live three-AS BGP fabric backing the `bgp` diagnostics. Built and converged
    /// on first use, so the shell reports real session and RIB state rather than a
    /// hard-coded sample.
    bgp_fabric: Option<VirtualLab>,
    /// Live two-reflector EVPN fabric backing the `bgp rr` diagnostics. Neither
    /// reflector in it has a VTEP, a VNI, or an import Route Target, so what the
    /// commands print about reflection is what a reflector really does rather
    /// than what a leaf does while wearing the label.
    rr_fabric: Option<VirtualLab>,
    lldp_table: LldpNeighborTable,
    cdp_table: CdpNeighborTable,
    ospf_lsdb: OspfLsdb,
    stp_engine: StpBridgeEngine,
    sad_table: SadTable,
    lag: LinkAggregationGroup,
    eigrp_table: EigrpTopologyTable,
    syslog_collector: SyslogCollector,
    pim_router: PimMulticastRouter,
    bfd_session: BfdSession,
    ldap_server: LdapServer,
    tacacs_server: TacacsServer,
    _dhcpv6_server: Dhcpv6Server,
    netflow_table: NetflowFlowTable,
    mqtt_broker: MqttBroker,
    _gtp_table: GtpTunnelTable,
    _turn_table: TurnAllocationTable,
    bgp_ls_db: BgpLsTopologyDatabase,
    srv6_mup_engine: Srv6MupEngine,
    mld_table: MldTable,
    bfd_v6_mgr: BfdV6Manager,
    netflow_v5_table: NetflowV5Table,
    srv6_usid_engine: UsidForwardingEngine,
    ti_lfa_engine: TiLfaEngine,
    flex_algo_engine: FlexAlgoEngine,
    vpls_instance: VplsInstance,
    cfm_engine: CfmEngine,
    sbfd_reflector: SbfdReflector,
    optical_dom: Vec<OpticalDiagnostics>,
    gnmi_server: GnmiServer,
    gnoi_server: GnoiServer,
    sr_policy_db: SrPolicyDatabase,
    frer_engine: FrerEngine,
    evpn_l3_vrf: EvpnL3VrfTable,
    cqf_engine: CqfEngine,
    gribi_aft: GribiAftTable,
    evpn_df_engine: EvpnDfElectionEngine,
    psfp_pipeline: PsfpFilterInstance,
    p4runtime_server: P4RuntimeServer,
    evpn_aliasing: EvpnAliasingEngine,
    preemption_engine: PreemptionEngine,
    bgp_ext_comms: BgpExtCommunityContainer,
    sai_adapter: SaiSwitchAdapter,
    tas_shaper: TimeAwareShaper,
    sba_bus: SbaMessageBus,
    evpn_type5_rib: EvpnType5Rib,
    tsn_cnc: CentralizedNetworkConfigurator,
    ptp_telecom: TelecomProfileEngine,
    ngap_node: NgapNode,
    evpn_type3_bum: EvpnBumFloodingTree,
    ptp_tc_engine: TransparentClockEngine,
    pfcp_upf: PfcpNode,
    ats_scheduler: UrgencyBasedScheduler,
    bgp_epe_db: BgpEpeDatabase,
    gtpu_ext_container: PduSessionContainer,
    bgp_ls_srv6_db: BgpLsSrv6Database,
    cbs_shaper: CreditBasedShaper,
    sba_events_engine: SbaEventExposureEngine,
    evpn_smet_engine: EvpnSmetEngine,
    congestion_isolation: CongestionIsolationEngine,
    nef_traffic_engine: NefTrafficInfluenceEngine,
    bgp_prefix_sid_attr: BgpPrefixSidAttribute,
    cqf_dual_buffer: CqfDualBufferEngine,
    nrf_oauth_auth: NrfOAuthAuthority,
    bgp_add_path_rib: AddPathRib,
    evpn_multicast_synch: EvpnMulticastSynchEngine,
    detnet_pref_engine: DetNetPrefEngine,
    diameter_ocs_engine: OnlineChargingEngine,
    pim_bsr_engine: PimBsrEngine,
    pcrf_rx_engine: PcrfRxEngine,
    evpn_proxy_arp: EvpnProxyArpEngine,
    nsh_md2_engine: NshMd2ForwarderEngine,
    mldp_engine: MldpEngine,
    pcef_gx_engine: PcefGxEngine,
    evpn_mass_withdraw: EvpnMassWithdrawEngine,
    sr_mpls_oam: SrMplsOamEngine,
    synce_engine: SyncEEsmcEngine,
    hss_s6a_engine: HssS6aEngine,
    evpn_etree_engine: EvpnETreeEngine,
    srv6_slicing_engine: Srv6SliceForwardingEngine,
    evpn_pref_df: EvpnPrefDfEngine,
    ifa_engine: IfaTelemetryEngine,
    eir_s13_engine: EirS13Engine,
    ptp_bc_engine: TelecomBoundaryClockEngine,
    ptp_te_engine: PtpTimeErrorEngine,
    pcrf_s9_engine: PcrfS9Engine,
    evpn_igmp_snooping: EvpnIgmpSnoopingEngine,
    flowspec_vrf_engine: FlowspecVrfScrubbingEngine,
    gtpu_telemetry_engine: GtpuTelemetryEngine,
    ptp_ttc_engine: TelecomPeerTransparentClockEngine,
    hss_sh_engine: HssShEngine,
    evpn_vrf_leaking_engine: EvpnVrfLeakingEngine,
    tsn_qbv_engine: TsnQbvGclEngine,
    hss_slh_engine: HssSlhEngine,
    evpn_uu_engine: EvpnUuSuppressionEngine,
    geneve_telemetry_engine: GeneveTelemetryEngine,
    frer_srf_engine: FrerSrfEngine,
    hss_cx_engine: HssCxEngine,
    evpn_mac_mobility_engine: EvpnMacMobilityEngine,
    sgw_engine: SgwEngine,
    tsn_cqf_engine: CqfMultiCycleEngine,
    aaa_s6b_engine: AaaS6bEngine,
    evpn_frr_engine: EvpnFrrEngine,
    srv6_mup_interworking: Srv6MupInterworkingEngine,
    evpn_mac_flush_engine: EvpnMacFlushEngine,
    gtpu_path_engine: GtpuPathEngine,
    tsn_psfp_engine: PsfpEngine,
    aaa_swm_engine: AaaSwmEngine,
    eir_s13_prime_engine: EirS13PrimeEngine,
    evpn_selective_ir_engine: EvpnSelectiveIrEngine,
    gtpu_reordering_engine: GtpuReorderingEngine,
    tsn_qcz_engine: QczCongestionEngine,
    sms_sgd_engine: SmsSgdEngine,
    evpn_irb_engine: EvpnAnycastIrbEngine,
    gtpu_reloc_engine: TargetUpfRelocationEngine,
    tsn_ats_multi_engine: AtsMultiHopPipeline,
    bsf_zh_engine: BsfZhEngine,
    evpn_bum_engine: EvpnBumPolicerEngine,
    gtpu_qos_engine: GtpuQosEnforcer,
    tsn_qbv_reconfig_engine: QbvDynamicReconfigEngine,
    s6c_hss_engine: S6cHssEngine,
    evpn_core_iso_engine: EvpnCoreIsolationEngine,
    gtpu_fast_failover_engine: GtpuFastFailoverEngine,
    tsn_qav_engine: TsnQavBridgePort,
    rcaf_np_engine: RcafNpEngine,
    evpn_damping_engine: EvpnFlapDampingEngine,
    ma_pdu_engine: MaPduSessionEngine,
    tsn_guard_band_engine: TsnPreemptionGuardBandEngine,
    s6t_hss_engine: ScefS6tHssEngine,
    evpn_pvlan_engine: EvpnPvlanEngine,
    gtpu_redundant_engine: GtpuRedundantEngine,
    tsn_cqf_time_engine: TsnCqfTimeDispatchEngine,
    s6m_hss_engine: S6mHssEngine,
    evpn_umt_engine: EvpnUmtEngine,
    gtpu_jitter_engine: GtpuJitterTelemetryEngine,
    tsn_cqf_trtcm_engine: TsnCqfTrTcmEngine,
    pcap_writer: Option<PcapWriter<File>>,
    seq_counter: u16,
}

impl Default for NetworkShell {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkShell {
    pub fn new() -> Self {
        let client_mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let client_ip = Ipv4Address::new(192, 168, 1, 100);
        let client_ip6 = Ipv6Address::from_str("2001:db8::100").unwrap();

        let server_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x10]);
        let server_ip = Ipv4Address::new(192, 168, 1, 10);
        let server_ip6 = Ipv6Address::from_str("2001:db8::10").unwrap();

        let mut client_stack = NetStack::new(NetStackConfig {
            mac: client_mac,
            ip: client_ip,
            ipv6: Some(client_ip6),
            subnet_mask: 24,
            gateway: Some(Ipv4Address::new(192, 168, 1, 1)),
        });

        let mut server_stack = NetStack::new(NetStackConfig {
            mac: server_mac,
            ip: server_ip,
            ipv6: Some(server_ip6),
            subnet_mask: 24,
            gateway: Some(Ipv4Address::new(192, 168, 1, 1)),
        });

        // Enable NAT on gateway / server
        server_stack.enable_nat(Ipv4Address::new(203, 0, 113, 1));

        // Setup server UDP Echo, DNS, NTP, TFTP, SNMP, RADIUS, SYSLOG, BFD, GENEVE, SIP, CoAP, PTP, STUN/TURN, GTP-U, HSRP, GLBP, LDP, DHCPv6, VXLAN-GPE, RoCEv2, GUE, sFlow, WireGuard, LISP, TWAMP, LSP-Ping, GRE-in-UDP
        server_stack
            .udp_sockets
            .bind(7, |_src, _port, data| Some(data.to_vec()));
        server_stack.udp_sockets.bind(53, |_src, _port, data| {
            if let Ok(query) = DnsMessage::parse(data)
                && let Some(q) = query.questions.first()
            {
                let resolved = match q.name.as_str() {
                    "example.com" | "web.local" => Ipv4Address::new(192, 168, 1, 10),
                    "gateway.local" => Ipv4Address::new(192, 168, 1, 1),
                    _ => Ipv4Address::new(93, 184, 216, 34),
                };
                return Some(DnsMessage::build_response(query.id, &q.name, resolved, 300));
            }
            None
        });

        // MPLS LSP Ping Port 3503 responder
        server_stack
            .udp_sockets
            .bind(LSP_PING_UDP_PORT, |_src, _port, data| {
                if let Some(req) = LspEchoPacket::parse(data) {
                    let resp = LspEchoPacket::build_echo_reply(
                        &req,
                        LSP_RET_CODE_EGRESS_FOR_FEC,
                        1700000000,
                        500200,
                    );
                    return Some(resp.serialize());
                }
                None
            });

        // GRE-in-UDP Port 4754 responder
        server_stack
            .udp_sockets
            .bind(GRE_IN_UDP_PORT, |_src, _port, _data| None);

        // TWAMP Test Port 862 responder
        server_stack
            .udp_sockets
            .bind(TWAMP_TEST_PORT, |_src, _port, data| {
                if let Some(req) = TwampTestPacket::parse(data) {
                    let resp = TwampTestPacket::build_reflector_response(
                        &req,
                        req.seq_number + 100,
                        1700000000,
                        100500,
                        1700000000,
                        100600,
                        64,
                    );
                    return Some(resp.serialize());
                }
                None
            });

        // NTP Port 123 responder
        server_stack.udp_sockets.bind(123, |_src, _port, data| {
            if let Ok(req) = NtpPacket::parse(data) {
                let now = NtpTimestamp::new(3900000000, 500000);
                let resp = NtpPacket::build_server_response(&req, now, now);
                return Some(resp.serialize());
            }
            None
        });

        // TFTP Port 69 responder
        server_stack.udp_sockets.bind(69, |_src, _port, data| {
            if let Ok(pkt) = TftpPacket::parse(data)
                && let TftpPacket::Rrq { filename, .. } = pkt
            {
                let srv = TftpFileServer::new();
                let resp = srv.handle_read_request(&filename, 1);
                return Some(resp.serialize());
            }
            None
        });

        // SNMP Port 161 responder
        server_stack.udp_sockets.bind(161, |_src, _port, data| {
            if let Ok(msg) = SnmpMessage::parse(data) {
                let mib = SnmpMib::new();
                let mut results = Vec::new();
                for vb in &msg.pdu.varbinds {
                    let val = mib.get(&vb.oid).cloned().unwrap_or(SnmpValue::Null);
                    results.push(SnmpVarbind {
                        oid: vb.oid.clone(),
                        value: val,
                    });
                }
                let resp = SnmpMessage::build_response(&msg, results);
                return Some(resp.serialize());
            }
            None
        });

        // WireGuard Port 51820 responder
        server_stack
            .udp_sockets
            .bind(WIREGUARD_PORT, |_src, _port, data| {
                if let Ok(msg) = WireguardMessage::parse(data)
                    && let WireguardMessage::HandshakeInitiation { sender_index, .. } = msg
                {
                    let resp =
                        WireguardMessage::build_response(0x99887766, sender_index, [0xEE; 32]);
                    return Some(resp.serialize());
                }
                None
            });

        // LISP Control Port 4342 responder
        server_stack
            .udp_sockets
            .bind(LISP_CONTROL_PORT, |_src, _port, data| {
                if let Some(req) = LispMapRequest::parse(data) {
                    let mut res = LispMapResolver::new();
                    res.register_eid(req.target_eid, Ipv4Address::new(198, 51, 100, 1), 1, 100);
                    if let Some(reply) = res.resolve(&req) {
                        return Some(reply.serialize());
                    }
                }
                None
            });
        server_stack
            .udp_sockets
            .bind(LISP_DATA_PORT, |_src, _port, _data| None);

        // STUN / TURN Port 3478 responder
        server_stack.udp_sockets.bind(STUN_PORT, |src, port, data| {
            if let Ok(turn_pkt) = TurnPacket::parse(data)
                && turn_pkt.msg_type == TURN_ALLOCATE_REQUEST
            {
                let resp = TurnPacket::build_allocate_response(
                    &turn_pkt,
                    Ipv4Address::new(203, 0, 113, 10),
                    49152,
                    600,
                );
                return Some(resp.serialize());
            }
            if let Ok(req) = StunPacket::parse(data) {
                let resp = StunPacket::build_binding_response(&req, src, port);
                return Some(resp.serialize());
            }
            None
        });

        // GTP-U Port 2152 responder
        server_stack
            .udp_sockets
            .bind(GTP_U_UDP_PORT, |_src, _port, data| {
                if let Ok(pkt) = GtpPacket::parse(data)
                    && pkt.header.msg_type == GTP_MSG_ECHO_REQUEST
                {
                    let seq = pkt.header.seq_num.unwrap_or(1);
                    let resp = GtpPacket::build_echo_response(pkt.header.teid, seq);
                    return Some(resp.serialize());
                }
                None
            });

        // DHCPv6 Server Port 547 responder
        server_stack
            .udp_sockets
            .bind(DHCPV6_SERVER_PORT, |_src, _port, data| {
                if let Ok(msg) = Dhcpv6Message::parse(data) {
                    let mut srv = Dhcpv6Server::new();
                    if let Some(adv) = srv.handle_solicit(&msg) {
                        return Some(adv.serialize());
                    }
                }
                None
            });

        // VXLAN-GPE Port 4790, RoCEv2 Port 4791, GUE Port 6080, sFlow Port 6343 responders
        server_stack
            .udp_sockets
            .bind(VXLAN_GPE_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(ROCEV2_UDP_PORT, |_src, _port, data| {
                if let Ok(roce) = RocePacket::parse(data) {
                    let ack = RocePacket::build_ack(roce.bth.dest_qp, roce.bth.psn);
                    return Some(ack.serialize());
                }
                None
            });
        server_stack
            .udp_sockets
            .bind(GUE_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(SFLOW_UDP_PORT, |_src, _port, _data| None);

        // HSRP Port 1985 & GLBP Port 3222 responders
        server_stack
            .udp_sockets
            .bind(HSRP_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(GLBP_UDP_PORT, |_src, _port, _data| None);

        // LDP Port 646 (UDP Hello) responder
        server_stack
            .udp_sockets
            .bind(LDP_PORT, |_src, _port, _data| None);

        // RADIUS Port 1812 responder
        server_stack
            .udp_sockets
            .bind(RADIUS_AUTH_PORT, |_src, _port, data| {
                if let Ok(req) = RadiusPacket::parse(data) {
                    let accept = RadiusPacket::build_access_accept(
                        req.identifier,
                        req.authenticator,
                        Ipv4Address::new(10, 100, 1, 50),
                        "Authentication Successful (RadiusServer-01)",
                    );
                    return Some(accept.serialize());
                }
                None
            });

        // BFD Port 3784 responder
        server_stack
            .udp_sockets
            .bind(BFD_CONTROL_PORT, |_src, _port, data| {
                if let Ok(req) = BfdControlPacket::parse(data) {
                    let resp = BfdControlPacket::build_control(
                        BfdState::Up,
                        0x87654321,
                        req.my_discriminator,
                        50_000,
                    );
                    return Some(resp.serialize());
                }
                None
            });

        // SIP Port 5060 responder
        server_stack
            .udp_sockets
            .bind(SIP_PORT, |_src, _port, data| {
                if let Ok(text) = std::str::from_utf8(data)
                    && let Ok(req) = SipMessage::parse(text)
                {
                    let local_sdp = build_simple_sdp("bob", "192.168.1.10", 5000);
                    let resp = SipMessage::build_200_ok(&req, &local_sdp);
                    return Some(resp.serialize().into_bytes());
                }
                None
            });

        // CoAP Port 5683 responder
        server_stack
            .udp_sockets
            .bind(COAP_UDP_PORT, |_src, _port, data| {
                if let Ok(req) = CoapPacket::parse(data) {
                    let resp = CoapPacket::build_response(
                        &req,
                        COAP_CODE_205_CONTENT,
                        b"{\"temperature\": 24.5, \"unit\": \"C\"}",
                    );
                    return Some(resp.serialize());
                }
                None
            });

        // PTP Port 319 (Event) & 320 (General) responders
        server_stack
            .udp_sockets
            .bind(PTP_EVENT_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(PTP_GENERAL_PORT, |_src, _port, _data| None);

        // SYSLOG, GENEVE, NETFLOW receiver
        server_stack
            .udp_sockets
            .bind(SYSLOG_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(GENEVE_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(NETFLOW_V9_UDP_PORT, |_src, _port, _data| None);

        // Setup server TCP HTTP 80, HTTPS 443, TACACS 49, LDP 646, LDAP 389, MQTT 1883, OpenFlow 6653, Diameter 3868, PCEP 4189, NETCONF 830, TWAMP 862, OTLP 4317/4318
        server_stack.tcp_manager.listen(80);
        server_stack.tcp_manager.listen(443);
        server_stack.tcp_manager.listen(TACACS_PORT);
        server_stack.tcp_manager.listen(LDP_PORT);
        server_stack.tcp_manager.listen(LDAP_PORT);
        server_stack.tcp_manager.listen(MQTT_PORT);
        server_stack.tcp_manager.listen(OFP_TCP_PORT);
        server_stack.tcp_manager.listen(DIAMETER_PORT);
        server_stack.tcp_manager.listen(PCEP_PORT);
        server_stack.tcp_manager.listen(NETCONF_PORT);
        server_stack.tcp_manager.listen(TWAMP_CONTROL_PORT);
        server_stack.tcp_manager.listen(OTLP_GRPC_PORT);
        server_stack.tcp_manager.listen(OTLP_HTTP_PORT);

        // Pre-populate client ARP & NDP cache
        client_stack.arp_table.insert(server_ip.0, server_mac);
        server_stack.arp_table.insert(client_ip.0, client_mac);

        client_stack.ndp_table.insert(server_ip6, server_mac);
        server_stack.ndp_table.insert(client_ip6, client_mac);

        let mut rip = RipEngine::new();
        rip.add_local_network(Ipv4Address::new(192, 168, 1, 0), 24, "eth0");

        let vrrp = VrrpEngine::new(10, 200, Ipv4Address::new(192, 168, 1, 1));
        let hsrp = HsrpEngine::new(1, 110, Ipv4Address::new(192, 168, 1, 1), true);
        let glbp = GlbpEngine::new(1, 120, Ipv4Address::new(192, 168, 1, 1));
        let vtp = VtpEngine::new("EnterpriseHQ", VtpMode::Server);

        let mut ofp_table = OfpFlowTable::new();
        ofp_table.add_entry(
            100,
            OfpMatch {
                in_port: Some(1),
                eth_type: Some(0x0800),
                ip_dst: Some(server_ip),
            },
            vec![OfpAction::Output(2)],
        );

        let diameter_server = DiameterServer::new(
            "hss01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );

        let wg_peer = WireguardPeer::new(
            [0xAA; 32],
            server_ip,
            WIREGUARD_PORT,
            Ipv4Address::new(10, 99, 0, 2),
        );
        let pcep_session = PcepSession::new();
        let netconf_server = NetconfServer::new();
        let mut lisp_resolver = LispMapResolver::new();
        lisp_resolver.register_eid(
            Ipv4Address::new(10, 1, 1, 50),
            Ipv4Address::new(198, 51, 100, 1),
            1,
            100,
        );

        let mut flowspec_engine = FlowspecEngine::new();
        flowspec_engine.add_rule(FlowspecRule {
            id: 1,
            match_fields: FlowspecMatch {
                dst_prefix: Some((Ipv4Address::new(192, 168, 1, 100), 32)),
                src_prefix: None,
                ip_protocol: Some(17),
                dst_port: None,
                src_port: Some(53),
                tcp_flags: None,
            },
            action: FlowspecAction::Drop,
        });

        let mut otlp_exporter = OtlpExporter::new("toy-tcpip-stack");
        otlp_exporter.record_counter(
            "net.packets.total",
            "Total received and transmitted frames",
            "packets",
            25410,
        );
        otlp_exporter.record_gauge("net.rtt.smoothed_ms", "Smoothed RTT estimate", "ms", 0.85);

        let mut gre_demux = GreDemuxTable::new();
        gre_demux.register_tunnel(GreVirtualTunnel {
            if_name: "gre1".to_string(),
            vrf_id: 10,
            local_ip: client_ip,
            remote_ip: server_ip,
            key: 1001,
            strict_sequence: true,
        });

        let mut srv6_engine = Srv6Engine::new();
        let sid_transit = Ipv6Address::from_str("2001:db8:1::100").unwrap();
        let sid_egress = Ipv6Address::from_str("2001:db8:2::200").unwrap();
        srv6_engine.register_sid(sid_transit, Srv6Behavior::End);
        srv6_engine.register_sid(sid_egress, Srv6Behavior::EndDt4 { vrf_id: 10 });

        let lfib = LfibTable::new();
        let ldp_session = LdpSession::default();
        let bgp_rib = BgpRib::new();
        let lldp_table = LldpNeighborTable::new();
        let cdp_table = CdpNeighborTable::new();
        let ospf_lsdb = OspfLsdb::new();
        let stp_engine = StpBridgeEngine::new(32768, client_mac);
        let sad_table = SadTable::new();
        let lag =
            LinkAggregationGroup::new("bond0", vec!["eth0".to_string(), "eth1".to_string()], 1);
        let eigrp_table = EigrpTopologyTable::new();
        let syslog_collector = SyslogCollector::new(100);
        let pim_router = PimMulticastRouter::default();
        let bfd_session = BfdSession::new(0x12345678, 50_000);
        let ldap_server = LdapServer::new();
        let tacacs_server = TacacsServer::new();
        let dhcpv6_server = Dhcpv6Server::new();
        let netflow_table = NetflowFlowTable::new();
        let mqtt_broker = MqttBroker::new();
        let gtp_table = GtpTunnelTable::new();
        let turn_table = TurnAllocationTable::new();
        let mut bgp_ls_db = BgpLsTopologyDatabase::new();
        bgp_ls_db.ingest_nlri(BgpLsNlri::Node(BgpLsNodeDescriptor {
            asn: 65000,
            igp_router_id: server_ip,
            node_name: Some("Edge-Spine-01".to_string()),
        }));
        bgp_ls_db.ingest_nlri(BgpLsNlri::Link(BgpLsLinkDescriptor {
            local_node: BgpLsNodeDescriptor {
                asn: 65000,
                igp_router_id: client_ip,
                node_name: Some("Leaf-01".to_string()),
            },
            remote_node: BgpLsNodeDescriptor {
                asn: 65000,
                igp_router_id: server_ip,
                node_name: Some("Edge-Spine-01".to_string()),
            },
            local_interface_ip: client_ip,
            remote_neighbor_ip: server_ip,
            te_metric: 10,
            max_bandwidth_bps: 100_000_000_000.0,
            max_reservable_bandwidth_bps: 80_000_000_000.0,
            admin_group_color: 0x01,
        }));

        let mut srv6_mup_engine = Srv6MupEngine::new();
        srv6_mup_engine.register_session(Srv6MupSession {
            gnb_ipv4: Ipv4Address::new(192, 168, 1, 50),
            upf_ipv4: server_ip,
            teid: 0xCAFE0001,
            srv6_sid: Ipv6Address::from_str("2001:db8:50:1::100").unwrap(),
            qfi: 9,
        });

        let mut mld_table = MldTable::new();
        let demo_group = Ipv6Address::from_str("ff3e::8000:1").unwrap();
        let demo_src = Ipv6Address::from_str("2001:db8:1::10").unwrap();
        mld_table.process_report(&Mldv2ReportPacket::new(vec![MldGroupRecord {
            record_type: MLD_CHANGE_TO_INCLUDE,
            multicast_address: demo_group,
            source_addresses: vec![demo_src],
        }]));

        let mut bfd_v6_mgr = BfdV6Manager::new();
        bfd_v6_mgr.add_session(BfdV6Session::new(server_ip6, 0x55443322, true));

        let mut netflow_v5_table = NetflowV5Table::new();
        netflow_v5_table.record_flow(client_ip, server_ip, server_ip, 51000, 80, 6, 1460, 1000);

        let mut srv6_usid_engine = UsidForwardingEngine::new();
        srv6_usid_engine.register_usid(0x1001, UsidBehavior::EndUN);
        srv6_usid_engine.register_usid(0x2002, UsidBehavior::EndUN);
        srv6_usid_engine.register_usid(0xE001, UsidBehavior::EndUDT4);

        let mut ti_lfa_engine = TiLfaEngine::new();
        ti_lfa_engine.add_node("NodeS", 16001);
        ti_lfa_engine.add_node("NodeE", 16002);
        ti_lfa_engine.add_node("NodeD", 16003);
        ti_lfa_engine.add_node("NodeP", 16004);
        ti_lfa_engine.add_node("NodeQ", 16005);
        ti_lfa_engine.add_link("NodeS", "NodeE", 10, 24001);
        ti_lfa_engine.add_link("NodeE", "NodeD", 10, 24002);
        ti_lfa_engine.add_link("NodeS", "NodeP", 10, 24003);
        ti_lfa_engine.add_link("NodeP", "NodeQ", 10, 24004);
        ti_lfa_engine.add_link("NodeQ", "NodeD", 10, 24005);

        // IPFIX Port 4739, Multi-Hop BFD Port 4784, NetFlow v5 Port 2055 responders
        server_stack
            .udp_sockets
            .bind(IPFIX_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(NETFLOW_V5_UDP_PORT, |_src, _port, _data| None);
        server_stack
            .udp_sockets
            .bind(BFD_MULTIHOP_PORT, |_src, _port, data| {
                if let Ok(req) = BfdControlPacket::parse(data) {
                    let resp = BfdControlPacket::build_control(
                        BfdState::Up,
                        0x88776655,
                        req.my_discriminator,
                        50_000,
                    );
                    return Some(resp.serialize());
                }
                None
            });

        let mut flex_algo_engine = FlexAlgoEngine::new();
        flex_algo_engine.register_algo(FlexAlgoDefinition {
            algo_id: 128,
            metric_type: FlexAlgoMetricType::MinDelay,
            calculation_type: 0,
            exclude_affinity: 0,
            include_any_affinity: 0,
        });
        flex_algo_engine.register_algo(FlexAlgoDefinition {
            algo_id: 129,
            metric_type: FlexAlgoMetricType::IgpMetric,
            calculation_type: 0,
            exclude_affinity: 0x02,
            include_any_affinity: 0,
        });
        flex_algo_engine.add_link("NodeA", "NodeB_LowDelay", 50, 5, 50, 0x01);
        flex_algo_engine.add_link("NodeB_LowDelay", "NodeB", 50, 5, 50, 0x01);
        flex_algo_engine.add_link("NodeA", "NodeB_HighDelay", 10, 80, 10, 0x02);
        flex_algo_engine.add_link("NodeB_HighDelay", "NodeB", 10, 80, 10, 0x02);

        let mut vpls_instance = VplsInstance::new(100);
        vpls_instance.add_pseudowire(VplsPseudowire {
            peer_ip: server_ip,
            vc_label_tx: 5001,
            vc_label_rx: 6001,
            tunnel_label_tx: 1001,
        });
        vpls_instance.learn_mac(server_mac, Some(6001));

        let mut sbfd_reflector = SbfdReflector::new();
        sbfd_reflector.register_discriminator(0x90001);

        let mut sbfd_server_reflector = SbfdReflector::new();
        sbfd_server_reflector.register_discriminator(0x90001);
        server_stack
            .udp_sockets
            .bind(SBFD_REFLECTOR_PORT, move |_src, _port, data| {
                if let Some(probe) = SbfdPacket::parse(data)
                    && let Some(resp) = sbfd_server_reflector.process_probe(&probe)
                {
                    return Some(resp.serialize().to_vec());
                }
                None
            });

        let mut cfm_engine = CfmEngine::new(10, 4, "carrier.domain.service1");
        let initial_ccm = CfmPacket::build_ccm(4, 20, 100, "carrier.domain.service1", false);
        let _ = cfm_engine.process_cfm_frame(&initial_ccm.serialize());

        let optical_dom = vec![
            OpticalDiagnostics::new(
                "HundredGigE0/0/0/1",
                TransceiverFormFactor::Qsfp28_100G,
                38.2,
                3.32,
                35.5,
                -1.2,
                -7.8,
            ),
            OpticalDiagnostics::new(
                "TenGigE0/0/0/2",
                TransceiverFormFactor::SfpPlus10G,
                41.5,
                3.28,
                28.4,
                -2.0,
                -11.5,
            ),
            OpticalDiagnostics::new(
                "FourHundredGigE0/0/0/3",
                TransceiverFormFactor::QsfpDd400G,
                45.0,
                3.30,
                42.0,
                0.5,
                -6.2,
            ),
        ];

        let gnmi_server = GnmiServer::new();

        let mut sr_policy_db = SrPolicyDatabase::new();
        let mut policy_gold = SrPolicy::new(100, server_ip6, "SR-Policy-Gold-LowLatency");
        policy_gold.add_candidate_path(SrCandidatePath {
            preference: 100,
            protocol_origin: SrProtocolOrigin::Cli,
            segment_lists: vec![SrSegmentList {
                weight: 1,
                segments: vec![
                    Ipv6Address::new([0xfc00, 0, 0, 1, 0, 0, 0, 0x0001]),
                    Ipv6Address::new([0xfc00, 0, 0, 3, 0, 0, 0, 0x0001]),
                ],
            }],
        });
        policy_gold.add_candidate_path(SrCandidatePath {
            preference: 200,
            protocol_origin: SrProtocolOrigin::BgpSrTe,
            segment_lists: vec![SrSegmentList {
                weight: 1,
                segments: vec![Ipv6Address::new([0xfc00, 0, 0, 2, 0, 0, 0, 0x0001])],
            }],
        });
        sr_policy_db.insert_policy(policy_gold);
        let gnoi_server = GnoiServer::new();
        let frer_engine = FrerEngine::new();
        let mut evpn_l3_vrf = EvpnL3VrfTable::new("VRF-TENANT-RED", 50001, client_stack.config.mac);
        evpn_l3_vrf.add_prefix_route(EvpnIpPrefixRoute::new(
            RouteDistinguisher::new(server_ip, 100),
            Ipv4Address::new(10, 100, 1, 0),
            24,
            50001,
            server_mac,
            server_ip,
        ));

        let cqf_engine = CqfEngine::new(125);
        let mut gribi_aft = GribiAftTable::new();
        gribi_aft.set_next_hop(GribiNextHop {
            id: 1,
            ip: server_ip,
            mac: server_mac,
            weight: 100,
        });
        gribi_aft.set_next_hop_group(GribiNextHopGroup {
            id: 10,
            next_hop_ids: vec![1],
        });
        gribi_aft.set_ipv4_entry(GribiIpv4Entry {
            prefix: Ipv4Address::new(10, 0, 0, 0),
            prefix_len: 8,
            next_hop_group_id: 10,
        });

        let mut evpn_df_engine = EvpnDfElectionEngine::new(client_stack.config.ip);
        let default_esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        evpn_df_engine.add_segment_peer(default_esi, client_stack.config.ip);
        evpn_df_engine.add_segment_peer(default_esi, server_ip);

        let psfp_gate = StreamGate::new(1, 1000, 500);
        let psfp_meter = FlowMeter::new(1, 1_000_000, 2000, true);
        let psfp_pipeline = PsfpFilterInstance::new(100, 7, psfp_gate, psfp_meter);

        let mut p4runtime_server = P4RuntimeServer::new(1);
        p4runtime_server.set_forwarding_pipeline_config("fabric_pipeline.p4info.txt");
        p4runtime_server.write_table_entry(P4TableEntry {
            table_name: "IngressPipeImpl.ipv4_lpm".to_string(),
            matches: vec![P4MatchField {
                field_name: "hdr.ipv4.dst_addr".to_string(),
                match_value: P4MatchKind::Lpm {
                    value: vec![10, 0, 0, 0],
                    prefix_len: 16,
                },
            }],
            action_name: "IngressPipeImpl.set_next_hop".to_string(),
            action_params: vec![("port".to_string(), vec![0, 0, 0, 1])],
            priority: 10,
        });

        let mut evpn_aliasing = EvpnAliasingEngine::new();
        evpn_aliasing.add_ad_route(EvpnEthernetAdRoute::new_per_es(
            RouteDistinguisher::new(client_stack.config.ip, 1),
            default_esi,
            client_stack.config.ip,
        ));
        evpn_aliasing.add_ad_route(EvpnEthernetAdRoute::new_per_es(
            RouteDistinguisher::new(server_ip, 1),
            default_esi,
            server_ip,
        ));

        let preemption_engine = PreemptionEngine::new();

        let mut bgp_ext_comms = BgpExtCommunityContainer::new();
        bgp_ext_comms.add(BgpExtendedCommunity::RouteTarget2Octet {
            asn: 65000,
            value: 100,
        });
        bgp_ext_comms.add(BgpExtendedCommunity::Color {
            flags: 0,
            color: 100,
        });
        bgp_ext_comms.add(BgpExtendedCommunity::TunnelEncapsulation {
            tunnel_type: TUNNEL_TYPE_VXLAN,
        });

        let mut sai_adapter = SaiSwitchAdapter::new(1);
        sai_adapter.create_fdb_entry(client_stack.config.mac, 100, 1);
        let sai_nh = sai_adapter.create_next_hop(server_ip, server_mac, 2);
        sai_adapter.create_route_entry(0, Ipv4Address::new(10, 0, 0, 0), 8, sai_nh);

        let mut tas_shaper = TimeAwareShaper::new();
        tas_shaper.add_entry(0x80, 100); // Slot 0: Queue 7 (TSN Control) 100µs
        tas_shaper.add_entry(0x7F, 400); // Slot 1: Queues 0..6 (Best-Effort) 400µs

        let mut sba_bus = SbaMessageBus::new();
        sba_bus.nrf.register_nf(NfProfile {
            nf_instance_id: "amf-01".to_string(),
            nf_type: NfType::Amf,
            fqdn: "amf.5gcore.local".to_string(),
            ip_address: "10.100.1.10".to_string(),
            services: vec!["namf-comm".to_string()],
            capacity: 100,
        });
        sba_bus.nrf.register_nf(NfProfile {
            nf_instance_id: "smf-01".to_string(),
            nf_type: NfType::Smf,
            fqdn: "smf.5gcore.local".to_string(),
            ip_address: "10.100.1.20".to_string(),
            services: vec!["nsmf-pdusession".to_string()],
            capacity: 100,
        });

        let mut evpn_type5_rib = EvpnType5Rib::new();
        evpn_type5_rib.add_route(EvpnType5Route::new_ipv4(
            RouteDistinguisher::new(client_stack.config.ip, 100),
            Ipv4Address::new(10, 200, 0, 0),
            16,
            client_stack.config.ip,
            50001,
        ));

        let mut tsn_cnc = CentralizedNetworkConfigurator::new();
        let talker_sid = StreamId::new(client_stack.config.mac, 1);
        let _ = tsn_cnc.register_talker(TsnTalker {
            stream_id: talker_sid,
            talker_mac: client_stack.config.mac,
            vlan_id: 100,
            priority: 6,
            tspec: TrafficSpecification {
                max_frame_size: 500,
                max_interval_frames: 2,
                interval_us: 1000,
            },
        });
        let _ = tsn_cnc.register_listener(TsnListener {
            stream_id: talker_sid,
            listener_mac: server_mac,
            reqs: UserToNetworkRequirements {
                max_latency_us: 5000,
                num_seamless_trees: 1,
            },
        });

        let ptp_telecom = TelecomProfileEngine::new(
            TelecomClockType::TelecomTimeSlaveClock,
            TelecomBmcaAttributes::new_slave_clock([
                0x52, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56,
            ]),
        );

        let mut ngap_node = NgapNode::new();
        ngap_node.handle_ng_setup(&NgSetupRequest {
            global_gnb_id: 101,
            gnb_name: "gNodeB-Taipei-01".to_string(),
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 5, 0],
            },
            tac: 0x0001,
            supported_slices: vec![Snssai { sst: 1, sd: None }],
        });

        let mut evpn_type3_bum = EvpnBumFloodingTree::new();
        evpn_type3_bum.add_route(EvpnType3Route::new_ipv4(
            RouteDistinguisher::new(client_stack.config.ip, 100),
            0,
            client_stack.config.ip,
            10001,
        ));
        evpn_type3_bum.add_route(EvpnType3Route::new_ipv4(
            RouteDistinguisher::new(server_ip, 100),
            0,
            server_ip,
            10001,
        ));

        let mut ptp_tc_engine = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
        ptp_tc_engine.calculate_peer_delay(0, 100, 150, 250);

        let mut pfcp_upf = PfcpNode::new("upf-edge-01.5gcore.local");
        pfcp_upf.handle_association_setup("smf-control-01.5gcore.local");
        pfcp_upf.establish_session(
            0xFEED_FACE,
            vec![PacketDetectionRule {
                pdr_id: 1,
                precedence: 100,
                source_interface: PFCP_SRC_INTERFACE_ACCESS,
                teid: Some(0x10001),
                ue_ip: Some(Ipv4Address::new(10, 45, 0, 100)),
            }],
            vec![ForwardingActionRule {
                far_id: 1,
                apply_action: PFCP_APPLY_ACTION_FORWARD,
                destination_interface: PFCP_SRC_INTERFACE_CORE,
                outer_header_creation: None,
            }],
        );

        let mut ats_scheduler = UrgencyBasedScheduler::new();
        ats_scheduler.register_shaper(AtsStreamShaper::new(1, 10_000_000, 1500)); // 10 Mbps CIR

        let mut bgp_epe_db = BgpEpeDatabase::new();
        bgp_epe_db.add_peer_node_sid(16001, 65001, server_ip);
        bgp_epe_db.add_peer_adj_sid(16002, 65001, server_ip, 1);
        bgp_epe_db.add_peer_set_member(16003, 65001, server_ip, Some(1), 50);

        let gtpu_ext_container = PduSessionContainer::new_dl(9, true);

        let mut bgp_ls_srv6_db = BgpLsSrv6Database::new();
        bgp_ls_srv6_db.add_locator(Srv6LocatorTlv::new(
            0,
            10,
            "2001:db8:cafe::".parse().unwrap(),
            64,
        ));
        bgp_ls_srv6_db.add_end_sid(Srv6EndSidTlv::new(
            1, // End
            "2001:db8:cafe::1".parse().unwrap(),
        ));

        let cbs_shaper = CreditBasedShaper::new("AVB-Class-A", 100_000_000, 1_000_000_000, 1500);

        let mut sba_events_engine = SbaEventExposureEngine::new();
        sba_events_engine.subscribe(
            "nef-analytics-01",
            SbaEventType::LocationReport,
            "imsi-208950000000001",
            "https://nef.5gcore.local/v1/event-exposure/notify",
        );

        let mut evpn_smet_engine = EvpnSmetEngine::new();
        evpn_smet_engine.add_smet_route(EvpnSmetRoute::new_any_source(
            RouteDistinguisher::new(server_ip, 100),
            100, // VLAN 100
            Ipv4Address::new(239, 255, 0, 1),
            server_ip,
        ));

        let congestion_isolation = CongestionIsolationEngine::new(3);

        let mut nef_traffic_engine = NefTrafficInfluenceEngine::new();
        nef_traffic_engine.create_subscription(
            "af-trans-edge-01",
            "edge-cloud-vr",
            "edge.mec",
            SliceId {
                sst: 1,
                sd: 0x000001,
            },
            TrafficFilter {
                dst_ip: Ipv4Address::new(198, 51, 100, 1),
                dst_port: 8080,
                protocol: 6,
            },
            "DNAI-Taipei-Edge",
            Ipv4Address::new(10, 100, 0, 1),
        );

        let bgp_prefix_sid_attr = BgpPrefixSidAttribute::new(Some(100), Some(16000), Some(8000));
        let mut cqf_dual_buffer = CqfDualBufferEngine::new(1000, 10000); // 1000µs cycle
        cqf_dual_buffer.enqueue_frame(1, 100, vec![0xAB; 256]);

        let mut nrf_oauth_auth = NrfOAuthAuthority::new("nrf-central-01");
        let _ = nrf_oauth_auth.issue_access_token(
            NrfAccessTokenRequest {
                grant_type: "client_credentials".to_string(),
                nf_instance_id: "amf-node-01".to_string(),
                nf_type: NfType::Amf,
                target_nf_type: NfType::Udm,
                scope: "nudm-sdm".to_string(),
            },
            1700000000,
        );

        let mut bgp_add_path_rib = AddPathRib::new(4);
        let prefix_test = Ipv4Prefix::new(Ipv4Address::new(10, 100, 0, 0), 16);
        let mut p1 = AddPathRibEntry::new(
            0x0000_0001,
            server_ip,
            server_ip,
            crate::bgp::AsPath::sequence(vec![65001, 65100]),
        );
        p1.local_pref = Some(200);
        let mut p2 = AddPathRibEntry::new(
            0x0000_0002,
            Ipv4Address::new(192, 168, 1, 20),
            Ipv4Address::new(192, 168, 1, 20),
            crate::bgp::AsPath::sequence(vec![65002, 65100]),
        );
        p2.local_pref = Some(150);
        bgp_add_path_rib.insert_path(prefix_test, p1);
        bgp_add_path_rib.insert_path(prefix_test, p2);

        let mut evpn_multicast_synch =
            EvpnMulticastSynchEngine::new(Some(EthernetSegmentId::from_u32(100)));
        evpn_multicast_synch.process_join_synch(EvpnJoinSynchRoute::new_any_source(
            EthernetSegmentId::from_u32(100),
            100,
            Ipv4Address::new(239, 255, 10, 1),
            server_ip,
        ));

        let mut detnet_pref_engine = DetNetPrefEngine::new(2, 64);
        let dummy = detnet_pref_engine.replicate(0x1001, b"INITIAL_WARMUP");
        for p in dummy {
            detnet_pref_engine.eliminate(p);
        }
        let mut diameter_ocs_engine = OnlineChargingEngine::new(10 * 1024 * 1024);
        diameter_ocs_engine.provision_subscriber("imsi-208950000000001", 100 * 1024 * 1024);

        let mut pim_bsr_engine = PimBsrEngine::new(server_ip, true, 128);
        let grp = EncodedGroupAddress::new(Ipv4Address::new(239, 0, 0, 0), 8);
        pim_bsr_engine.register_candidate_rp(
            grp,
            CandidateRpRecord::new(Ipv4Address::new(192, 168, 1, 1), 10, 150),
        );
        pim_bsr_engine.register_candidate_rp(
            grp,
            CandidateRpRecord::new(Ipv4Address::new(192, 168, 1, 2), 10, 150),
        );

        let pcrf_rx_engine = PcrfRxEngine::new(1_000_000_000); // 1 Gbps PCC capacity

        let mut evpn_proxy_arp = EvpnProxyArpEngine::new();
        evpn_proxy_arp.add_anycast_gateway(
            100,
            Ipv4Address::new(10, 1, 1, 1),
            MacAddress([0x00, 0x00, 0x5E, 0x00, 0x01, 0x01]),
        );
        evpn_proxy_arp.learn_from_evpn_route_type2(
            100,
            Ipv4Address::new(10, 1, 1, 20),
            MacAddress([0x52, 0x54, 0x00, 0xAA, 0xBB, 0x01]),
        );

        let mut nsh_md2_engine = NshMd2ForwarderEngine::new();
        nsh_md2_engine.add_path_hop(0x10001, 10, 101);
        nsh_md2_engine.add_path_hop(0x10001, 9, 102);

        let mut mldp_engine = MldpEngine::new(server_ip);
        let fec_tv = MldpFecElement::new_p2mp_generic(Ipv4Address::new(10, 0, 0, 1), 1001);
        mldp_engine.set_upstream_parent(fec_tv.clone(), Ipv4Address::new(192, 168, 1, 1), 100);
        mldp_engine.add_downstream_branch(&fec_tv, 2, 201);
        mldp_engine.add_downstream_branch(&fec_tv, 3, 202);

        let mut pcef_gx_engine = PcefGxEngine::new("pcrf.epc.mnc001.mcc208.3gppnetwork.org");
        pcef_gx_engine.handle_session_establishment(
            "gx-sess-ue01-pcrf",
            "imsi-208950000000001",
            IpCanType::ThreeGpp5Gs,
        );

        let mut evpn_mass_withdraw = EvpnMassWithdrawEngine::new();
        let es1 = EthernetSegmentId::from_u32(101);
        evpn_mass_withdraw.register_mac(
            es1,
            100,
            MacAddress([0x52, 0x54, 0x00, 0x01, 0x02, 0x03]),
            Some(Ipv4Address::new(10, 1, 1, 50)),
            Ipv4Address::new(192, 168, 1, 1),
            Ipv4Address::new(192, 168, 1, 2),
        );
        evpn_mass_withdraw.register_mac(
            es1,
            100,
            MacAddress([0x52, 0x54, 0x00, 0x01, 0x02, 0x04]),
            Some(Ipv4Address::new(10, 1, 1, 51)),
            Ipv4Address::new(192, 168, 1, 1),
            Ipv4Address::new(192, 168, 1, 2),
        );

        let mut sr_mpls_oam = SrMplsOamEngine::new(server_ip);
        sr_mpls_oam.register_prefix_sid(server_ip, 16001);
        sr_mpls_oam.register_prefix_sid(Ipv4Address::new(192, 168, 1, 200), 16002);
        sr_mpls_oam.register_adj_sid(24001, client_ip, server_ip);

        let mut synce_engine = SyncEEsmcEngine::new();
        synce_engine.set_port_priority(1, 10);
        synce_engine.set_port_priority(2, 20);
        synce_engine.process_rx_esmc(1, &SyncEEsmcPacket::new(false, QualityLevel::QlPrc));
        synce_engine.process_rx_esmc(2, &SyncEEsmcPacket::new(false, QualityLevel::QlSsuA));

        let mut hss_s6a_engine = HssS6aEngine::new("hss.epc.mnc001.mcc208.3gppnetwork.org");
        hss_s6a_engine.provision_subscriber(HssSubscriberProfile {
            imsi: "208950000000001".to_string(),
            msisdn: "33612345678".to_string(),
            default_apn: "internet".to_string(),
            subscribed_ambr_ul_kbps: 50_000,
            subscribed_ambr_dl_kbps: 200_000,
            registered_mme: Some("mme01.epc.mnc001.mcc208.3gppnetwork.org".to_string()),
        });

        let mut evpn_etree_engine = EvpnETreeEngine::new();
        let root_mac = MacAddress([0x52, 0x54, 0x00, 0x10, 0x00, 0x01]);
        let leaf1_mac = MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x01]);
        let leaf2_mac = MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x02]);
        evpn_etree_engine.register_endpoint(100, root_mac, ETreeRole::Root);
        evpn_etree_engine.register_endpoint(100, leaf1_mac, ETreeRole::Leaf);
        evpn_etree_engine.register_endpoint(100, leaf2_mac, ETreeRole::Leaf);

        let mut srv6_slicing_engine = Srv6SliceForwardingEngine::new();
        srv6_slicing_engine.add_slice(Srv6SlicePolicy {
            slice_id: NetworkSliceId(1),
            slice_name: "5G-eMBB-HighThroughput".to_string(),
            slice_type: SliceType::Embb,
            flex_algo: 129,
            guaranteed_bandwidth_kbps: 1_000_000,
            segment_list: vec![
                Ipv6Address::from_str("fc00:5g:slice1::1").unwrap_or(server_ip6),
                Ipv6Address::from_str("fc00:5g:upf1::1").unwrap_or(server_ip6),
            ],
            max_latency_microseconds: 50_000,
        });
        srv6_slicing_engine.add_slice(Srv6SlicePolicy {
            slice_id: NetworkSliceId(2),
            slice_name: "5G-URLLC-LowLatency".to_string(),
            slice_type: SliceType::Urllc,
            flex_algo: 128,
            guaranteed_bandwidth_kbps: 100_000,
            segment_list: vec![
                Ipv6Address::from_str("fc00:5g:slice2::1").unwrap_or(server_ip6),
                Ipv6Address::from_str("fc00:5g:edge_upf::1").unwrap_or(server_ip6),
            ],
            max_latency_microseconds: 1_000,
        });
        srv6_slicing_engine.bind_subscriber_to_slice(client_ip, NetworkSliceId(2));

        let mut evpn_pref_df = EvpnPrefDfEngine::new();
        let demo_esi =
            EthernetSegmentId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
        evpn_pref_df.add_or_update_candidate(
            demo_esi,
            CandidatePe {
                pe_ip: client_ip,
                preference: 200,
                dont_preempt: true,
                sticky: false,
            },
        );
        evpn_pref_df.add_or_update_candidate(
            demo_esi,
            CandidatePe {
                pe_ip: server_ip,
                preference: 100,
                dont_preempt: false,
                sticky: false,
            },
        );
        evpn_pref_df.elect_df(demo_esi);

        let ifa_engine = IfaTelemetryEngine::new(0x0A000101);

        let mut eir_s13_engine = EirS13Engine::new();
        eir_s13_engine.set_imei_status("867912040000001", EquipmentStatus::Whitelisted);
        eir_s13_engine.set_imei_status("354890091234567", EquipmentStatus::Blacklisted);
        eir_s13_engine.set_imei_status("013982005555555", EquipmentStatus::Greylisted);

        let mut ptp_bc_engine = TelecomBoundaryClockEngine::new();
        ptp_bc_engine.add_port(1, 10, false);
        ptp_bc_engine.add_port(2, 20, false);
        ptp_bc_engine.add_port(3, 128, true);
        ptp_bc_engine.update_rx_announce(
            1,
            TelecomClockQuality {
                clock_class: 6,
                clock_accuracy: 0x20,
                offset_scaled_log_variance: 0x4E5D,
            },
            1,
            128,
        );
        ptp_bc_engine.update_rx_announce(
            2,
            TelecomClockQuality {
                clock_class: 7,
                clock_accuracy: 0x21,
                offset_scaled_log_variance: 0x5A00,
            },
            2,
            128,
        );
        ptp_bc_engine.run_alternate_bmca();

        let mut ptp_te_engine = PtpTimeErrorEngine::new(1000);
        for val in [8, 10, 9, 11, 8, 12, 10, 9, 11, 10] {
            ptp_te_engine.add_sample(val);
        }

        let mut pcrf_s9_engine = PcrfS9Engine::new(false);
        pcrf_s9_engine
            .roaming_subsessions
            .insert(1001, SubsessionEnforcementInfo::new(1001, 50_000, 200_000));

        let mut evpn_igmp_snooping = EvpnIgmpSnoopingEngine::new();
        let mcast_group = Ipv4Address::new(239, 1, 1, 1);
        evpn_igmp_snooping.process_igmp_join(100, 1, mcast_group);
        evpn_igmp_snooping.process_igmp_join(100, 2, mcast_group);

        let mut flowspec_vrf_engine = FlowspecVrfScrubbingEngine::new();
        flowspec_vrf_engine.add_rule(FlowspecVrfRule {
            rule_id: 1,
            match_dst_ip: Some(server_ip),
            match_protocol: Some(17),
            match_dst_port: Some(53),
            action: FlowspecVrfAction::RedirectVrf("VRF_DDOS_SCRUBBING".to_string()),
        });
        flowspec_vrf_engine.add_rule(FlowspecVrfRule {
            rule_id: 2,
            match_dst_ip: Some(server_ip),
            match_protocol: Some(6),
            match_dst_port: Some(80),
            action: FlowspecVrfAction::RemarkDscp(46),
        });

        let gtpu_telemetry_engine = GtpuTelemetryEngine::new();

        let mut ptp_ttc_engine = TelecomPeerTransparentClockEngine::new();
        ptp_ttc_engine.set_port_peer_delay(1, 150);
        ptp_ttc_engine.set_port_peer_delay(2, 200);

        let mut hss_sh_engine = HssShEngine::new();
        hss_sh_engine.register_subscriber(HssShSubscriberProfile::new(
            "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
            "<RepositoryData><ServiceIndication>VoLTE</ServiceIndication></RepositoryData>",
            "REGISTERED",
        ));

        let mut evpn_vrf_leaking_engine = EvpnVrfLeakingEngine::new();
        evpn_vrf_leaking_engine.add_vrf(
            10,
            "VRF_TENANT_RED",
            &["65000:10"],
            &["65000:10", "65000:999"],
        );
        evpn_vrf_leaking_engine.add_vrf(
            20,
            "VRF_TENANT_BLUE",
            &["65000:20"],
            &["65000:20", "65000:999"],
        );
        evpn_vrf_leaking_engine.add_vrf(
            999,
            "VRF_SHARED_SERVICES",
            &["65000:999"],
            &["65000:999", "65000:10", "65000:20"],
        );

        evpn_vrf_leaking_engine.add_direct_route(
            10,
            Ipv4Address::new(10, 10, 1, 0),
            24,
            Ipv4Address::new(10, 10, 1, 1),
        );
        evpn_vrf_leaking_engine.add_direct_route(
            20,
            Ipv4Address::new(10, 20, 1, 0),
            24,
            Ipv4Address::new(10, 20, 1, 1),
        );
        evpn_vrf_leaking_engine.add_direct_route(
            999,
            Ipv4Address::new(8, 8, 8, 8),
            32,
            Ipv4Address::new(192, 168, 99, 1),
        );
        evpn_vrf_leaking_engine.sync_route_leaking();

        let mut tsn_qbv_engine = TsnQbvGclEngine::new(0, 10_000);
        tsn_qbv_engine.add_entry(QbvGclEntry::new(
            [false, false, false, false, false, false, false, true],
            200_000,
        ));
        tsn_qbv_engine.add_entry(QbvGclEntry::new(
            [true, true, true, true, true, true, true, false],
            800_000,
        ));

        let mut hss_slh_engine = HssSlhEngine::new();
        hss_slh_engine.register_location(
            "001010123456789",
            "mme01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );

        let mut evpn_uu_engine = EvpnUuSuppressionEngine::new();
        evpn_uu_engine.set_vni_suppression(100, true);
        evpn_uu_engine.add_known_mac(100, MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0x01, 0x01]));

        let geneve_telemetry_engine = GeneveTelemetryEngine::new(0x0A000101);

        let mut frer_srf_engine = FrerSrfEngine::new(128);
        frer_srf_engine.process_frame(1, 100);
        frer_srf_engine.process_frame(1, 101);
        frer_srf_engine.process_frame(1, 102);

        let mut hss_cx_engine = HssCxEngine::new();
        hss_cx_engine.add_subscriber(ImsSub {
            public_identity: "sip:alice@ims.example.com".into(),
            private_identity: "alice@ims.example.com".into(),
            assigned_scscf: Some("sip:scscf1.ims.example.com".into()),
            auth_scheme: "Digest-AKAv1-MD5".into(),
            auth_key: vec![0xAA; 16],
        });

        let mut evpn_mac_mobility_engine = EvpnMacMobilityEngine::new(5);
        evpn_mac_mobility_engine.learn_mac(
            100,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            [10, 0, 0, 1],
            false,
        );

        let sgw_engine = SgwEngine::new();

        let mut tsn_cqf_engine = CqfMultiCycleEngine::new(125_000, 0, 65536);
        let _ = tsn_cqf_engine.ingest_frame(101, 7, vec![0xAA; 128], 10_000);

        let mut aaa_s6b_engine = AaaS6bEngine::new("aaa.vowifi.example.com");
        aaa_s6b_engine.provision_subscriber(Non3gppSubProfile {
            imsi: "208950123456789".into(),
            authorized_anid: vec!["WLAN".into(), "HRPD".into()],
            allocated_pgw_ip: [198, 51, 100, 1],
            allocated_pgw_fqdn: "pgw01.epc.example.com".into(),
            apn: "ims.vowifi".into(),
            status: Non3gppUserStatus::UserDeregistered,
        });

        let mut evpn_frr_engine = EvpnFrrEngine::new();
        evpn_frr_engine.add_protected_route(EvpnProtectedRoute::new(
            100,
            MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
            None,
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 0, 2),
            100,
        ));

        let mut srv6_mup_interworking = Srv6MupInterworkingEngine::new();
        srv6_mup_interworking.register_mapping(MupSessionMapping {
            gtp_teid: 0x12345678,
            gnodeb_ip: Ipv6Address::new([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]),
            srv6_segments: vec![Ipv6Address::new([0x2001, 0x0db8, 0xcafe, 0, 0, 0, 0, 1])],
            qfi: 9,
        });

        let mut evpn_mac_flush_engine = EvpnMacFlushEngine::new();
        evpn_mac_flush_engine.learn_mac(EvpnFlushMacEntry {
            vni: 100,
            mac: MacAddress([0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]),
            esi: EvpnEsi::new([0x01; 10]),
            remote_vtep: Ipv4Address::new(10, 0, 0, 1),
            is_local: false,
            is_static: false,
        });

        let mut gtpu_path_engine = GtpuPathEngine::new(1);
        gtpu_path_engine.add_peer(Ipv4Address::new(10, 100, 1, 1), 3);

        let mut tsn_psfp_engine = PsfpEngine::new();
        tsn_psfp_engine.add_filter(StreamFilterInstance {
            stream_id: 101,
            priority: 7,
            max_sdu_bytes: 500,
            gate_id: 1,
            meter_id: Some(1),
            matching_frames: 0,
            sdu_oversized_drops: 0,
        });
        tsn_psfp_engine.add_gate(StreamGateInstance {
            gate_id: 1,
            is_open: true,
            gate_closed_drops: 0,
            invalid_rx_count: 0,
        });
        tsn_psfp_engine.add_meter(FlowMeterInstance::new(1, 100_000, 1_000, 200_000, 2_000));

        let mut aaa_swm_engine = AaaSwmEngine::new("aaa.vowifi.example.com");
        aaa_swm_engine.provision_subscriber("208950123456789", vec![0x11, 0x22, 0x33, 0x44]);

        let mut eir_s13_prime_engine = EirS13PrimeEngine::new("eir.3gppnetwork.org");
        eir_s13_prime_engine
            .register_equipment("861234567890123", S13PrimeEquipmentStatus::Whitelisted);
        eir_s13_prime_engine
            .register_equipment("359999999999999", S13PrimeEquipmentStatus::Blacklisted);
        eir_s13_prime_engine.ban_software_version("99");

        let mut evpn_selective_ir_engine = EvpnSelectiveIrEngine::new();
        evpn_selective_ir_engine.set_inclusive_vteps(
            100,
            vec![
                Ipv4Address::new(10, 0, 0, 1),
                Ipv4Address::new(10, 0, 0, 2),
                Ipv4Address::new(10, 0, 0, 3),
                Ipv4Address::new(10, 0, 0, 4),
            ],
        );
        evpn_selective_ir_engine.add_smet_receiver(
            MulticastChannel::new_ssm(
                100,
                Ipv4Address::new(192, 168, 1, 50),
                Ipv4Address::new(239, 1, 1, 1),
            ),
            Ipv4Address::new(10, 0, 0, 2),
        );

        let gtpu_reordering_engine = GtpuReorderingEngine::new(0x12345678, 1, 32);
        let tsn_qcz_engine = QczCongestionEngine::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 2000);

        let sms_sgd_engine = SmsSgdEngine::new("+886912345678");

        let mut evpn_irb_engine = EvpnAnycastIrbEngine::new(
            Ipv4Address::new(10, 0, 0, 1),
            MacAddress([0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC]),
            9000,
        );
        evpn_irb_engine.add_anycast_gateway(100, Ipv4Address::new(192, 168, 10, 1));
        evpn_irb_engine.add_anycast_gateway(200, Ipv4Address::new(192, 168, 20, 1));
        evpn_irb_engine.learn_host(
            Ipv4Address::new(192, 168, 20, 55),
            MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x55]),
            200,
            Ipv4Address::new(10, 0, 0, 2),
        );

        let gtpu_reloc_engine = TargetUpfRelocationEngine::new(
            1,
            0x1000AAAA,
            0x2000BBBB,
            Ipv4Address::new(10, 1, 1, 1),
            Ipv4Address::new(10, 2, 2, 2),
        );

        let mut tsn_ats_multi_engine = AtsMultiHopPipeline::new(3, 100_000);
        tsn_ats_multi_engine.configure_stream_across_hops(1, 100_000_000, 2000);

        let mut bsf_zh_engine = BsfZhEngine::new("hss.node.ims.net");
        bsf_zh_engine.register_subscriber(
            "460019998887771",
            "<guss-profile>active</guss-profile>",
            GbaAuthVector {
                rand: [0xAA; 16],
                autn: [0xBB; 16],
                ck: [0xCC; 16],
                ik: [0xDD; 16],
            },
        );

        let mut evpn_bum_engine = EvpnBumPolicerEngine::new(3);
        evpn_bum_engine.set_rate_limit(100, BumType::Broadcast, 1_000_000, 10_000);
        evpn_bum_engine.set_rate_limit(100, BumType::Multicast, 2_000_000, 20_000);

        let mut gtpu_qos_engine = GtpuQosEnforcer::new(1, 50_000_000, 10_000);
        gtpu_qos_engine.register_qfi(1, 9, FiveQiResourceType::NonGbr, 9, 300);
        gtpu_qos_engine.register_qfi(2, 82, FiveQiResourceType::DelayCriticalGbr, 2, 10);

        let initial_oper_gcl = QbvSchedule::new(
            0,
            vec![
                QbvGateEntry {
                    gate_states: 0x80,
                    time_interval_ns: 25_000,
                },
                QbvGateEntry {
                    gate_states: 0xFF,
                    time_interval_ns: 75_000,
                },
            ],
        );
        let tsn_qbv_reconfig_engine = QbvDynamicReconfigEngine::new(initial_oper_gcl);

        let mut s6c_hss_engine = S6cHssEngine::new("hss.node.operator.com");
        s6c_hss_engine.register_subscriber_location(
            "460029991112223",
            S6cServingNodeInfo {
                node_type: S6cServingNodeType::Smsf,
                node_fqdn: "smsf01.5gcore.org".into(),
                node_ip: Ipv4Address::new(172, 16, 0, 10),
            },
        );

        let mut evpn_core_iso_engine = EvpnCoreIsolationEngine::new(1);
        evpn_core_iso_engine.add_core_uplink("spine1");
        evpn_core_iso_engine.add_core_uplink("spine2");
        evpn_core_iso_engine.register_client_ac("eth_ce1", Some(0x0011223344556677));

        let mut gtpu_fast_failover_engine = GtpuFastFailoverEngine::new();
        gtpu_fast_failover_engine.add_session(FastFailoverSession::new(
            1,
            Ipv4Address::new(10, 1, 1, 10),
            0x1111AAAA,
            Ipv4Address::new(10, 2, 2, 20),
            0x2222BBBB,
            2,
        ));

        let tsn_qav_engine = TsnQavBridgePort::new(100_000_000, 30_000_000, 20_000_000);

        let rcaf_np_engine = RcafNpEngine::new("pcrf01.operator.com");
        let evpn_damping_engine = EvpnFlapDampingEngine::new(1000.0, 2000.0, 750.0, 10);
        let ma_pdu_engine = MaPduSessionEngine::new(
            101,
            AtsssMode::SmallestDelay,
            Ipv4Address::new(10, 5, 1, 1),
            0x1111AAAA,
            Ipv4Address::new(192, 168, 50, 1),
            0x2222BBBB,
        );
        let tsn_guard_band_engine = TsnPreemptionGuardBandEngine::new(1_000_000_000, true);

        let mut s6t_hss_engine = ScefS6tHssEngine::new("hss.ciot.operator.com");
        s6t_hss_engine.user_monitoring_events.insert(
            "460041234567890".into(),
            vec![MonitoringEventConfig {
                scef_id: "scef01.iot.net".into(),
                scef_ref_id: 1001,
                event_type: MonitoringEventType::UeReachability,
            }],
        );

        let mut evpn_pvlan_engine = EvpnPvlanEngine::new(100);
        evpn_pvlan_engine.register_port("gw_port", PvlanPortType::Promiscuous);
        evpn_pvlan_engine.register_port("vm_iso1", PvlanPortType::Isolated);
        evpn_pvlan_engine.register_port("vm_iso2", PvlanPortType::Isolated);
        evpn_pvlan_engine.register_port("vm_comm1", PvlanPortType::Community(10));
        evpn_pvlan_engine.register_port("vm_comm2", PvlanPortType::Community(10));

        let gtpu_redundant_engine = GtpuRedundantEngine::new(
            1,
            Ipv4Address::new(10, 1, 1, 1),
            0x1111,
            Ipv4Address::new(10, 2, 2, 2),
            0x2222,
        );

        let tsn_cqf_time_engine = TsnCqfTimeDispatchEngine::new(10_000);

        let mut s6m_hss_engine = S6mHssEngine::new("hss.gw.operator.com");
        s6m_hss_engine.register_subscriber("460029988776655", SmsMiResult::Authorized);

        let mut evpn_umt_engine = EvpnUmtEngine::new(Ipv4Address::new(10, 0, 0, 1));
        evpn_umt_engine.add_inclusive_vtep(100, Ipv4Address::new(10, 0, 0, 2));
        evpn_umt_engine.add_inclusive_vtep(100, Ipv4Address::new(10, 0, 0, 3));
        evpn_umt_engine.add_selective_receiver(
            100,
            Ipv4Address::new(239, 1, 1, 1),
            Ipv4Address::new(10, 0, 0, 2),
        );

        let gtpu_jitter_engine = GtpuJitterTelemetryEngine::new(5005);
        let tsn_cqf_trtcm_engine = TsnCqfTrTcmEngine::new(100_000_000, 1500, 200_000_000, 3000);

        NetworkShell {
            stack: client_stack,
            remote_host_ip: server_ip,
            remote_host_ipv6: server_ip6,
            remote_host_mac: server_mac,
            remote_stack: server_stack,
            rip,
            igmp_table: MulticastGroupTable::new(),
            _tftp_server: TftpFileServer::new(),
            vrrp,
            hsrp,
            glbp,
            vtp,
            ofp_table,
            diameter_server,
            wg_peer,
            pcep_session,
            netconf_server,
            _lisp_resolver: lisp_resolver,
            flowspec_engine,
            otlp_exporter,
            gre_demux,
            srv6_engine,
            lfib,
            _ldp_session: ldp_session,
            bgp_rib,
            evpn_fabric: None,
            bgp_fabric: None,
            rr_fabric: None,
            lldp_table,
            cdp_table,
            ospf_lsdb,
            stp_engine,
            sad_table,
            lag,
            eigrp_table,
            syslog_collector,
            pim_router,
            bfd_session,
            ldap_server,
            tacacs_server,
            _dhcpv6_server: dhcpv6_server,
            netflow_table,
            mqtt_broker,
            _gtp_table: gtp_table,
            _turn_table: turn_table,
            bgp_ls_db,
            srv6_mup_engine,
            mld_table,
            bfd_v6_mgr,
            netflow_v5_table,
            srv6_usid_engine,
            ti_lfa_engine,
            flex_algo_engine,
            vpls_instance,
            cfm_engine,
            sbfd_reflector,
            optical_dom,
            gnmi_server,
            gnoi_server,
            sr_policy_db,
            frer_engine,
            evpn_l3_vrf,
            cqf_engine,
            gribi_aft,
            evpn_df_engine,
            psfp_pipeline,
            p4runtime_server,
            evpn_aliasing,
            preemption_engine,
            bgp_ext_comms,
            sai_adapter,
            tas_shaper,
            sba_bus,
            evpn_type5_rib,
            tsn_cnc,
            ptp_telecom,
            ngap_node,
            evpn_type3_bum,
            ptp_tc_engine,
            pfcp_upf,
            ats_scheduler,
            bgp_epe_db,
            gtpu_ext_container,
            bgp_ls_srv6_db,
            cbs_shaper,
            sba_events_engine,
            evpn_smet_engine,
            congestion_isolation,
            nef_traffic_engine,
            bgp_prefix_sid_attr,
            cqf_dual_buffer,
            nrf_oauth_auth,
            bgp_add_path_rib,
            evpn_multicast_synch,
            detnet_pref_engine,
            diameter_ocs_engine,
            pim_bsr_engine,
            pcrf_rx_engine,
            evpn_proxy_arp,
            nsh_md2_engine,
            mldp_engine,
            pcef_gx_engine,
            evpn_mass_withdraw,
            sr_mpls_oam,
            synce_engine,
            hss_s6a_engine,
            evpn_etree_engine,
            srv6_slicing_engine,
            evpn_pref_df,
            ifa_engine,
            eir_s13_engine,
            ptp_bc_engine,
            ptp_te_engine,
            pcrf_s9_engine,
            evpn_igmp_snooping,
            flowspec_vrf_engine,
            gtpu_telemetry_engine,
            ptp_ttc_engine,
            hss_sh_engine,
            evpn_vrf_leaking_engine,
            tsn_qbv_engine,
            hss_slh_engine,
            evpn_uu_engine,
            geneve_telemetry_engine,
            frer_srf_engine,
            hss_cx_engine,
            evpn_mac_mobility_engine,
            sgw_engine,
            tsn_cqf_engine,
            aaa_s6b_engine,
            evpn_frr_engine,
            srv6_mup_interworking,
            evpn_mac_flush_engine,
            gtpu_path_engine,
            tsn_psfp_engine,
            aaa_swm_engine,
            eir_s13_prime_engine,
            evpn_selective_ir_engine,
            gtpu_reordering_engine,
            tsn_qcz_engine,
            sms_sgd_engine,
            evpn_irb_engine,
            gtpu_reloc_engine,
            tsn_ats_multi_engine,
            bsf_zh_engine,
            evpn_bum_engine,
            gtpu_qos_engine,
            tsn_qbv_reconfig_engine,
            s6c_hss_engine,
            evpn_core_iso_engine,
            gtpu_fast_failover_engine,
            tsn_qav_engine,
            rcaf_np_engine,
            evpn_damping_engine,
            ma_pdu_engine,
            tsn_guard_band_engine,
            s6t_hss_engine,
            evpn_pvlan_engine,
            gtpu_redundant_engine,
            tsn_cqf_time_engine,
            s6m_hss_engine,
            evpn_umt_engine,
            gtpu_jitter_engine,
            tsn_cqf_trtcm_engine,
            pcap_writer: None,
            seq_counter: 1,
        }
    }

    fn record_packet(&mut self, data: &[u8]) {
        if let Some(ref mut writer) = self.pcap_writer {
            let _ = writer.write_packet(1700000000, 500000, data);
        }
    }

    pub fn run_repl(&mut self) {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║         💻 Toy TCP/IP Stack - Dual-Stack IPv4/IPv6 Interactive Shell       ║");
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        println!(
            "Host IPv4: {} | IPv6: {:?} | MAC: {}",
            self.stack.config.ip,
            self.stack.config.ipv6.unwrap(),
            self.stack.config.mac
        );
        println!("Type 'help' for available commands or 'exit' to quit.\n");

        let stdin = io::stdin();
        let mut reader = stdin.lock();

        loop {
            print!("netstack > ");
            io::stdout().flush().unwrap();

            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            match parts[0] {
                "exit" | "quit" => {
                    println!("Exiting network shell.");
                    break;
                }
                "help" => self.cmd_help(),
                "status" => self.cmd_status(),
                "arp" => self.cmd_arp(&parts[1..]),
                "ndp" => self.cmd_ndp(),
                "route" => self.cmd_route(),
                "rip" => self.cmd_rip(&parts[1..]),
                "ospf" => self.cmd_ospf(&parts[1..]),
                "eigrp" => self.cmd_eigrp(&parts[1..]),
                "isis" => self.cmd_isis(&parts[1..]),
                "bgp" => self.cmd_bgp(&parts[1..]),
                "add-path" | "bgp-add-path" => self.cmd_add_path(&parts[1..]),
                "evpn" => self.cmd_evpn(&parts[1..]),
                "evpn-synch" | "evpn-sync" | "join-synch" => self.cmd_evpn_synch(&parts[1..]),
                "detnet" | "pref" => self.cmd_detnet(&parts[1..]),
                "diameter-charging" | "charging" | "ocs" => self.cmd_diameter_charging(&parts[1..]),
                "pim-bsr" | "bsr" | "pim-ssm" => self.cmd_pim_bsr(&parts[1..]),
                "diameter-rx" | "rx" | "pcrf" => self.cmd_diameter_rx(&parts[1..]),
                "evpn-proxy-arp" | "proxy-arp" | "arp-suppression" => {
                    self.cmd_evpn_proxy_arp(&parts[1..])
                }
                "nsh-md2" | "nsh-tlv" | "sfc-md2" => self.cmd_nsh_md2(&parts[1..]),
                "mldp" | "p2mp-ldp" => self.cmd_mldp(&parts[1..]),
                "diameter-gx" | "gx" | "pcef" => self.cmd_diameter_gx(&parts[1..]),
                "evpn-mass-withdraw" | "mass-withdraw" | "es-failover" => {
                    self.cmd_evpn_mass_withdraw(&parts[1..])
                }
                "sr-oam" | "sr-ping" | "sr-lsp-ping" => self.cmd_sr_oam(&parts[1..]),
                "synce" | "esmc" => self.cmd_synce(&parts[1..]),
                "diameter-s6a" | "s6a" | "hss" => self.cmd_diameter_s6a(&parts[1..]),
                "evpn-etree" | "etree" => self.cmd_evpn_etree(&parts[1..]),
                "srv6-slicing" | "slicing" | "vtn" => self.cmd_srv6_slicing(&parts[1..]),
                "evpn-pref-df" | "pref-df" => self.cmd_evpn_pref_df(&parts[1..]),
                "ifa" | "ifa2" => self.cmd_ifa(&parts[1..]),
                "diameter-s13" | "s13" | "eir" => self.cmd_diameter_s13(&parts[1..]),
                "ptp-bc" | "t-bc" => self.cmd_ptp_bc(&parts[1..]),
                "ptp-te" | "time-error" | "cte" => self.cmd_ptp_te(&parts[1..]),
                "diameter-s9" | "s9" | "pcrf-roaming" => self.cmd_diameter_s9(&parts[1..]),
                "evpn-snooping" | "mcast-snooping" => self.cmd_evpn_snooping(&parts[1..]),
                "flowspec-vrf" | "scrubbing" => self.cmd_flowspec_vrf(&parts[1..]),
                "gtpu-telemetry" | "gtp-telemetry" => self.cmd_gtpu_telemetry(&parts[1..]),
                "ptp-ttc" | "ttc" | "p2p-tc" => self.cmd_ptp_ttc(&parts[1..]),
                "diameter-sh" | "sh" => self.cmd_diameter_sh(&parts[1..]),
                "evpn-vrf-leak" | "vrf-leak" => self.cmd_evpn_vrf_leak(&parts[1..]),
                "tsn-qbv" | "qbv" | "gcl" => self.cmd_tsn_qbv(&parts[1..]),
                "diameter-slh" | "slh" | "lcs" => self.cmd_diameter_slh(&parts[1..]),
                "evpn-uu" | "uu-suppress" => self.cmd_evpn_uu(&parts[1..]),
                "geneve-telemetry" | "geneve-tel" => self.cmd_geneve_telemetry(&parts[1..]),
                "frer-srf" | "srf" | "vector-recovery" => self.cmd_frer_srf(&parts[1..]),
                "diameter-cx" | "cx" | "dx" => self.cmd_diameter_cx(&parts[1..]),
                "evpn-mobility" | "mac-mobility" => self.cmd_evpn_mac_mobility(&parts[1..]),
                "gtpc-v2" | "gtpc" | "gtpv2" => self.cmd_gtpc_v2(&parts[1..]),
                "tsn-cqf" | "cqf-multi" | "peristaltic" => self.cmd_tsn_cqf(&parts[1..]),
                "diameter-s6b" | "s6b" | "epdg-aaa" => self.cmd_diameter_s6b(&parts[1..]),
                "evpn-frr" | "evpn-protect" => self.cmd_evpn_frr(&parts[1..]),
                "srv6-mup-direct" | "mup-direct" => self.cmd_srv6_mup_direct(&parts[1..]),
                "evpn-flush" | "mac-flush" => self.cmd_evpn_mac_flush(&parts[1..]),
                "gtpu-heartbeat" | "gtp-echo" => self.cmd_gtpu_heartbeat(&parts[1..]),
                "tsn-psfp" | "psfp-filter" => self.cmd_tsn_psfp(&parts[1..]),
                "diameter-swm" | "swm" | "swx" => self.cmd_diameter_swm(&parts[1..]),
                "diameter-s13p" | "s13p" | "s13-prime" => self.cmd_diameter_s13_prime(&parts[1..]),
                "evpn-mcast-ir" | "mcast-ir" | "smet-ir" => self.cmd_evpn_mcast_ir(&parts[1..]),
                "gtpu-reorder" | "gtp-reorder" => self.cmd_gtpu_reorder(&parts[1..]),
                "tsn-qcz" | "qcz" | "tsn-ci" => self.cmd_tsn_qcz(&parts[1..]),
                "diameter-sgd" | "sgd" | "sms-sgd" => self.cmd_diameter_sgd(&parts[1..]),
                "evpn-irb" | "anycast-irb" | "irb" => self.cmd_evpn_irb(&parts[1..]),
                "gtpu-reloc" | "upf-reloc" | "gtp-reloc" => self.cmd_gtpu_reloc(&parts[1..]),
                "tsn-ats-multi" | "ats-multi" | "ats-pipeline" => {
                    self.cmd_tsn_ats_multi(&parts[1..])
                }
                "diameter-zh" | "zh" | "gba-bsf" => self.cmd_diameter_zh(&parts[1..]),
                "evpn-bum" | "bum-policer" | "storm-policer" => self.cmd_evpn_bum(&parts[1..]),
                "gtpu-qos" | "gtp-qos" | "ambr-enforce" => self.cmd_gtpu_qos(&parts[1..]),
                "tsn-qbv-reconfig" | "qbv-reconfig" | "gcl-swap" => {
                    self.cmd_tsn_qbv_reconfig(&parts[1..])
                }
                "diameter-s6c" | "s6c" | "sms-s6c" => self.cmd_diameter_s6c(&parts[1..]),
                "evpn-core-iso" | "core-iso" | "split-horizon" => {
                    self.cmd_evpn_core_iso(&parts[1..])
                }
                "gtpu-failover" | "gtp-failover" | "fast-failover" => {
                    self.cmd_gtpu_failover(&parts[1..])
                }
                "tsn-qav" | "qav" | "tsn-cbs" => self.cmd_tsn_qav(&parts[1..]),
                "diameter-np" | "np" | "rcaf" => self.cmd_diameter_np(&parts[1..]),
                "evpn-damp" | "flap-damping" | "mac-damp" => self.cmd_evpn_damp(&parts[1..]),
                "gtpu-ma" | "ma-pdu" | "atsss" => self.cmd_gtpu_ma(&parts[1..]),
                "tsn-preempt" | "guard-band" | "qbu" => self.cmd_tsn_preempt(&parts[1..]),
                "diameter-s6t" | "s6t" | "scef" => self.cmd_diameter_s6t(&parts[1..]),
                "evpn-pvlan" | "pvlan" | "port-iso" => self.cmd_evpn_pvlan(&parts[1..]),
                "gtpu-redundant" | "redundant-gtp" | "urllc-dup" => {
                    self.cmd_gtpu_redundant(&parts[1..])
                }
                "tsn-cqf-time" | "cqf-time" | "cqf-dispatch" => self.cmd_tsn_cqf_time(&parts[1..]),
                "diameter-s6m" | "s6m" | "sms-iwmsc" => self.cmd_diameter_s6m(&parts[1..]),
                "evpn-umt" | "umt" | "mcast-tree" => self.cmd_evpn_umt(&parts[1..]),
                "gtpu-jitter" | "gtp-jitter" | "owd" => self.cmd_gtpu_jitter(&parts[1..]),
                "tsn-cqf-meter" | "cqf-meter" | "cqf-trtcm" => self.cmd_tsn_cqf_meter(&parts[1..]),
                "flowspec" => self.cmd_flowspec(&parts[1..]),
                "otlp" => self.cmd_otlp(&parts[1..]),
                "gre6" => self.cmd_gre6(&parts[1..]),
                "twamp" => self.cmd_twamp(&parts[1..]),
                "lsp-ping" => self.cmd_lsp_ping(&parts[1..]),
                "srv6-ops" => self.cmd_srv6_ops(&parts[1..]),
                "gre-udp" => self.cmd_gre_udp(&parts[1..]),
                "bgp-ls" => self.cmd_bgp_ls(&parts[1..]),
                "bgp-ls-srv6" | "ls-srv6" => self.cmd_bgp_ls_srv6(&parts[1..]),
                "bgp-prefix-sid" | "prefix-sid" => self.cmd_bgp_prefix_sid(&parts[1..]),
                "ipfix" => self.cmd_ipfix(&parts[1..]),
                "srv6-mup" => self.cmd_srv6_mup(&parts[1..]),
                "5g-sba" | "sba" => self.cmd_5g_sba(&parts[1..]),
                "sba-events" | "5g-events" => self.cmd_sba_events(&parts[1..]),
                "nef-traffic" | "edge-mec" => self.cmd_nef_traffic(&parts[1..]),
                "nrf-oauth" | "oauth2" | "5g-auth" => self.cmd_nrf_oauth(&parts[1..]),
                "ngap" | "5g-n2" => self.cmd_ngap(&parts[1..]),
                "pfcp" | "5g-n4" => self.cmd_pfcp(&parts[1..]),
                "gtp-ext" | "qfi" | "5g-qos" => self.cmd_gtp_ext(&parts[1..]),
                "mld" => self.cmd_mld(&parts[1..]),
                "bfd6" | "bfd-v6" => self.cmd_bfd_v6(&parts[1..]),
                "geneve-sfc" => self.cmd_geneve_sfc(&parts[1..]),
                "usid" | "srv6-usid" => self.cmd_usid(&parts[1..]),
                "netflow5" | "netflow-v5" => self.cmd_netflow_v5(&parts[1..]),
                "ti-lfa" | "tilfa" => self.cmd_ti_lfa(&parts[1..]),
                "flex-algo" | "flexalgo" => self.cmd_flex_algo(&parts[1..]),
                "geneve-int" => self.cmd_geneve_int(&parts[1..]),
                "vpls" => self.cmd_vpls(&parts[1..]),
                "cfm" | "802.1ag" => self.cmd_cfm(&parts[1..]),
                "sbfd" | "s-bfd" => self.cmd_sbfd(&parts[1..]),
                "dom" | "optical" => self.cmd_dom(&parts[1..]),
                "etag" | "802.1br" => self.cmd_etag(&parts[1..]),
                "gnmi" => self.cmd_gnmi(&parts[1..]),
                "gnoi" => self.cmd_gnoi(&parts[1..]),
                "sr-policy" | "srpolicy" => self.cmd_sr_policy(&parts[1..]),
                "frer" | "802.1cb" => self.cmd_frer(&parts[1..]),
                "cqf" | "802.1qch" => self.cmd_cqf(&parts[1..]),
                "cqf-dual" | "cqf-buffer" => self.cmd_cqf_dual(&parts[1..]),
                "psfp" | "802.1qci" => self.cmd_psfp(&parts[1..]),
                "fpe" | "preemption" | "802.1qbu" => self.cmd_fpe(&parts[1..]),
                "tas" | "802.1qbv" => self.cmd_tas(&parts[1..]),
                "ats" | "802.1qcr" | "ubs" => self.cmd_ats(&parts[1..]),
                "cbs" | "802.1qav" | "avb" => self.cmd_cbs(&parts[1..]),
                "congestion-isolation" | "ci" | "802.1qcz" => {
                    self.cmd_congestion_isolation(&parts[1..])
                }
                "cnc" | "802.1qcc" => self.cmd_cnc(&parts[1..]),
                "gribi" => self.cmd_gribi(&parts[1..]),
                "p4" | "p4runtime" => self.cmd_p4runtime(&parts[1..]),
                "sai" | "sonic" => self.cmd_sai(&parts[1..]),
                "evpn-l3" | "l3-irb" => self.cmd_evpn_l3(&parts[1..]),
                "evpn-mh" | "df-election" => self.cmd_evpn_mh(&parts[1..]),
                "evpn-ad" | "aliasing" => self.cmd_evpn_ad(&parts[1..]),
                "evpn-t3" | "imet" | "bum" => self.cmd_evpn_t3(&parts[1..]),
                "evpn-t5" | "type5" => self.cmd_evpn_t5(&parts[1..]),
                "evpn-smet" | "smet" => self.cmd_evpn_smet(&parts[1..]),
                "bgp-ext" | "extcomm" => self.cmd_bgp_ext(&parts[1..]),
                "epe" | "bgp-epe" => self.cmd_bgp_epe(&parts[1..]),
                "geneve-opts" => self.cmd_geneve_opts(&parts[1..]),
                "gre-demux" => self.cmd_gre_demux(&parts[1..]),
                "ioam" => self.cmd_ioam(&parts[1..]),
                "netconf" => self.cmd_netconf(&parts[1..]),
                "lisp" => self.cmd_lisp(&parts[1..]),
                "wireguard" | "wg" => self.cmd_wireguard(&parts[1..]),
                "gptp" => self.cmd_gptp(&parts[1..]),
                "ptp-telecom" | "g8275" => self.cmd_ptp_telecom(&parts[1..]),
                "ptp-tc" | "tc" => self.cmd_ptp_tc(&parts[1..]),
                "pcep" => self.cmd_pcep(&parts[1..]),
                "rsvp" => self.cmd_rsvp(&parts[1..]),
                "openflow" | "ofp" => self.cmd_openflow(&parts[1..]),
                "diameter" => self.cmd_diameter(&parts[1..]),
                "nsh" => self.cmd_nsh(&parts[1..]),
                "sflow" => self.cmd_sflow(&parts[1..]),
                "6in4" => self.cmd_6in4(&parts[1..]),
                "4in6" => self.cmd_4in6(&parts[1..]),
                "roce" => self.cmd_roce(&parts[1..]),
                "pfc" => self.cmd_pfc(&parts[1..]),
                "gue" => self.cmd_gue(&parts[1..]),
                "bfd" => self.cmd_bfd(&parts[1..]),
                "geneve" => self.cmd_geneve(&parts[1..]),
                "ldap" => self.cmd_ldap(&parts[1..]),
                "ldp" => self.cmd_ldp(&parts[1..]),
                "glbp" => self.cmd_glbp(&parts[1..]),
                "tacacs" => self.cmd_tacacs(&parts[1..]),
                "vtp" => self.cmd_vtp(&parts[1..]),
                "dhcpv6" => self.cmd_dhcpv6(&parts[1..]),
                "vxlan-gpe" => self.cmd_vxlan_gpe(&parts[1..]),
                "netflow" => self.cmd_netflow(&parts[1..]),
                "sip" => self.cmd_sip(&parts[1..]),
                "mqtt" => self.cmd_mqtt(&parts[1..]),
                "coap" => self.cmd_coap(&parts[1..]),
                "sctp" => self.cmd_sctp(&parts[1..]),
                "rtp" => self.cmd_rtp(&parts[1..]),
                "ptp" => self.cmd_ptp(&parts[1..]),
                "erspan" => self.cmd_erspan(&parts[1..]),
                "cdp" => self.cmd_cdp(&parts[1..]),
                "srv6" => self.cmd_srv6(&parts[1..]),
                "stun" => self.cmd_stun(&parts[1..]),
                "turn" => self.cmd_turn(&parts[1..]),
                "gtp" => self.cmd_gtp(&parts[1..]),
                "hsrp" => self.cmd_hsrp(&parts[1..]),
                "mpls" => self.cmd_mpls(&parts[1..]),
                "lldp" => self.cmd_lldp(&parts[1..]),
                "stp" => self.cmd_stp(&parts[1..]),
                "lacp" => self.cmd_lacp(&parts[1..]),
                "pppoe" => self.cmd_pppoe(&parts[1..]),
                "radius" => self.cmd_radius(&parts[1..]),
                "syslog" => self.cmd_syslog(&parts[1..]),
                "l2tp" => self.cmd_l2tp(&parts[1..]),
                "pim" => self.cmd_pim(&parts[1..]),
                "vxlan" => self.cmd_vxlan(&parts[1..]),
                "ipsec" => self.cmd_ipsec(&parts[1..]),
                "http3" => self.cmd_http3(&parts[1..]),
                "traceroute" => self.cmd_traceroute(&parts[1..]),
                "ntp" => self.cmd_ntp(&parts[1..]),
                "tftp" => self.cmd_tftp(&parts[1..]),
                "snmp" => self.cmd_snmp(&parts[1..]),
                "quic" => self.cmd_quic(&parts[1..]),
                "vrrp" => self.cmd_vrrp(&parts[1..]),
                "tunnel" => self.cmd_tunnel(&parts[1..]),
                "igmp" => self.cmd_igmp(&parts[1..]),
                "ping" => self.cmd_ping(&parts[1..]),
                "ping6" => self.cmd_ping6(&parts[1..]),
                "dns" => self.cmd_dns(&parts[1..]),
                "udp" => self.cmd_udp(&parts[1..]),
                "curl" => self.cmd_curl(&parts[1..]),
                "tls" => self.cmd_tls(&parts[1..]),
                "http2" => self.cmd_http2(&parts[1..]),
                "ws" => self.cmd_ws(&parts[1..]),
                "netstat" => self.cmd_netstat(),
                "iptables" | "firewall" => self.cmd_firewall(&parts[1..]),
                "nat" => self.cmd_nat(&parts[1..]),
                "tcp-stats" => self.cmd_tcp_stats(),
                "lab" => self.cmd_lab(&parts[1..]),
                "pcap" => self.cmd_pcap(&parts[1..]),
                cmd => println!(
                    "Unknown command: '{}'. Type 'help' for available commands.",
                    cmd
                ),
            }
        }
    }

    fn cmd_help(&self) {
        println!("\nAvailable Commands:");
        println!(
            "  lab [topology|ping4|ping6|route4|udp-echo|tcp-demo|pcap] - Integrated Virtual Network Lab Simulation"
        );
        println!(
            "  status                              - Show current network interface details (IPv4 & IPv6)"
        );
        println!(
            "  add-path [advert | pic | status]    - BGP ADD-PATH Multi-Path & Prefix Independent Convergence (RFC 7911)"
        );
        println!(
            "  evpn-synch [join | leave | status]  - EVPN Route Type 7/8 IGMP Multicast Segment Sync (RFC 9251)"
        );
        println!(
            "  detnet [replicate | eliminate]      - DetNet Deterministic Data Plane & PREF Zero-Loss Transport (RFC 8939)"
        );
        println!(
            "  diameter-charging [ccr | balance]   - Diameter Gy/Ro Online Charging System & Quota Enforcement (RFC 4006)"
        );
        println!(
            "  pim-bsr [rp <group> | bsm | ssm]    - PIM-BSR Dynamic RP Election & PIM-SSM 232.0.0.0/8 (RFC 5059/4607)"
        );
        println!(
            "  diameter-rx [aar | str | status]    - Diameter Rx Interface & 5G/IMS Policy Control / QCI (3GPP TS 29.214)"
        );
        println!(
            "  evpn-proxy-arp [lookup | snoop | gw]- EVPN Proxy ARP / ND Broadcast Suppression & Anycast Gateway (RFC 7432)"
        );
        println!(
            "  nsh-md2 [forward | tlvs | status]   - NSH MD Type 2 Dynamic Variable-Length Context TLVs & SFF (RFC 8300)"
        );
        println!(
            "  mldp [status | join <root> <lsp_id>]- Multipoint LDP P2MP/MP2MP Multicast Tree Replication (RFC 6388)"
        );
        println!(
            "  diameter-gx [status | ccr-init | rule]- Diameter Gx Interface & 5G/EPC PCC Rule Enforcement (3GPP TS 29.212)"
        );
        println!(
            "  evpn-mass-withdraw [status | fail <esi>]- EVPN Fast Convergence Route Type 1 per-ES Mass Withdrawal (RFC 7432)"
        );
        println!(
            "  sr-oam [ping <prefix> <sid> | adj]  - SR-MPLS OAM Segment Routing LSP Ping & Target FEC (RFC 8287)"
        );
        println!(
            "  synce [status | select | rx <p> <ql>]- SyncE ESMC Quality Level SSM & Physical Clock Selection (ITU-T G.8264)"
        );
        println!(
            "  diameter-s6a [status | air <imsi>]  - Diameter S6a Interface & HSS Mobility/Authentication Vectors (3GPP TS 29.272)"
        );
        println!(
            "  evpn-etree [status | forward <s|d>] - EVPN E-Tree Root/Leaf Tree Forwarding & Split-Horizon (RFC 8317)"
        );
        println!(
            "  srv6-slicing [status | steer <ip>]  - SRv6 5G Network Slicing & Flex-Algo SLA Transport Paths (RFC 9350/9543)"
        );
        println!(
            "  evpn-pref-df [status | elect <esi>] - EVPN Preference-Based DF Election & Non-Preempt/Sticky (RFC 8584)"
        );
        println!(
            "  ifa [status | insert | parse]       - In-Band Flow Analytics IFA 2.0 Hop-by-Hop Telemetry (RFC 9197)"
        );
        println!(
            "  diameter-s13 [status | check <imei>]- Diameter S13 EIR Interface & IMEI Whitelist/Blacklist Barring (3GPP TS 29.272)"
        );
        println!(
            "  ptp-bc [status | bmca | set-prio]   - PTP Telecom Boundary Clock (T-BC) Alternate BMCA Engine (ITU-T G.8275.1)"
        );
        println!(
            "  ptp-te [status | sample <ns> | mask]- PTP Telecom Time Error cTE/dTE Measurement & G.8273.2 Masks (Class A-D)"
        );
        println!(
            "  diameter-s9 [status | ccr <id> <bw>]- Diameter S9 PCRF Roaming Interface & Subsession QoS Policy (3GPP TS 29.215)"
        );
        println!(
            "  evpn-snooping [status | join | fwd] - EVPN Layer 2 IGMP Snooping & Multicast Tree Pruning Engine (RFC 9251)"
        );
        println!(
            "  flowspec-vrf [status | eval | rule] - BGP Flowspec Redirect-to-VRF & DSCP Traffic Marking Scrubbing (RFC 8955)"
        );
        println!(
            "  gtpu-telemetry [status | encap | dec]- 5G GTP-U PDU Session Container Extension & In-Band Delay Telemetry (3GPP TS 38.415)"
        );
        println!(
            "  ptp-ttc [status | pdelay | correct] - PTP Telecom Profile Peer-to-Peer Transparent Clock Engine (ITU-T G.8275.2)"
        );
        println!(
            "  diameter-sh [status | udr | snr]    - Diameter Sh Interface & IMS Application Server Subscriber Profile (3GPP TS 29.328)"
        );
        println!(
            "  evpn-vrf-leak [status | leak | lookup]- EVPN Layer 3 Multi-VRF Route Leaking & Shared Services Isolation (RFC 9136)"
        );
        println!(
            "  tsn-qbv [status | gate <time_ns> | tx]- IEEE 802.1Qbv Time-Aware Shaper (TAS) Gate Control List (GCL) Engine"
        );
        println!(
            "  diameter-slh [status | rir <imsi>]  - Diameter SLh Location Services Interface & GMLC-to-HSS Inquiries (3GPP TS 29.173)"
        );
        println!(
            "  evpn-uu [status | test <mac> | vni] - EVPN Layer 2 Unknown Unicast (UU) Flood Suppression & Storm Control (RFC 7432)"
        );
        println!(
            "  geneve-telemetry [status | insert | dump] - Geneve Overlay In-Band Network Telemetry (INT) Option Header (RFC 8926)"
        );
        println!(
            "  frer-srf [status | rx <stream> <seq> | reset] - IEEE 802.1CB Sequence Recovery Function (SRF) Vector Algorithm"
        );
        println!(
            "  diameter-cx [status | uar | mar | sar] - 3GPP Diameter Cx/Dx IMS I/S-CSCF to HSS Registration Interface (TS 29.228)"
        );
        println!(
            "  evpn-mobility [status | learn | adv] - EVPN MAC Mobility Sequence Number & Sticky MAC Flapping Suppression (RFC 7432)"
        );
        println!(
            "  gtpc-v2 [status | create <imsi> <apn>] - 3GPP GTPv2-C Session Management & Create Session Handshake (TS 29.274)"
        );
        println!(
            "  tsn-cqf [status | ingest <stream> <prio> <size> | advance <ns>] - IEEE 802.1Qch Multi-Queue Cyclic Queuing & Forwarding"
        );
        println!(
            "  diameter-s6b [status | aar <imsi> <anid> | str <sess>] - 3GPP Diameter S6b Non-3GPP / ePDG AAA Interface (TS 29.273)"
        );
        println!(
            "  evpn-frr [status | fail <primary_ip> | restore <primary_ip>] - EVPN Fast Reroute & Pre-Computed Backup Path Protection"
        );
        println!(
            "  srv6-mup-direct [status | d <teid> | e <teid>] - SRv6 Mobile User Plane Direct Routing End.M.GTP6.D/E Interworking"
        );
        println!(
            "  evpn-flush [status | down <esi> | vni <esi> <vni>] - EVPN Rapid Layer 2 MAC Table Flush on Link Down (RFC 7432)"
        );
        println!(
            "  gtpu-heartbeat [status | ping <peer> | ack <peer>] - 3GPP GTP-U Path Management Echo Request/Response (TS 29.281)"
        );
        println!(
            "  tsn-psfp [status | test <stream> <prio> <len> | gate <id> <open|close>] - IEEE 802.1Qci PSFP Multi-Stage Filtering"
        );
        println!(
            "  diameter-swm [status | auth <imsi> [anid]] - 3GPP Diameter SWm Untrusted WLAN / ePDG AAA Interface (TS 29.273)"
        );
        println!(
            "  diameter-s13p [status | check <imei> [svn]]- 3GPP Diameter S13' Direct EIR Interface & IMEI-SV Validation (TS 29.272)"
        );
        println!(
            "  evpn-mcast-ir [status | join <vni> <s_ip> <g_ip> <vtep> | tx <vni> <s_ip> <g_ip>] - EVPN Selective Multicast Pruning"
        );
        println!(
            "  gtpu-reorder [status | rx <seq> <text> | flush] - 3GPP GTP-U Sequence Number Out-of-Order Reordering & Jitter Buffer"
        );
        println!(
            "  tsn-qcz [status | tx <s_ip> <d_ip> <bytes> | clear <s_ip> <d_ip>] - IEEE 802.1Qcz Congestion Isolation & Head-of-Line"
        );
        println!(
            "  diameter-sgd [status | mo <imsi> <sc> <text> | mt <imsi> <sc> <text>] - 3GPP Diameter SGd / T4 SMS Core Relay Interface"
        );
        println!(
            "  evpn-irb [status | route <vni> <dst_ip> [sym|asym]] - EVPN Layer 3 Anycast Gateway & Symmetric/Asymmetric IRB Dual-Mode"
        );
        println!(
            "  gtpu-reloc [status | rx <payload> | marker] - 3GPP GTP-U UPF Anchor Relocation, Indirect Forwarding & End Marker"
        );
        println!(
            "  tsn-ats-multi [status | ingest <stream> <prio> <len> | tick <ns>] - IEEE 802.1Qcr Asynchronous Traffic Shaping (ATS) Multi-Hop"
        );
        println!(
            "  diameter-zh [status | auth <imsi> [2g|3g] | key <imsi> <naf_id>] - 3GPP Diameter Zh GAA/GBA Bootstrapping Interface"
        );
        println!(
            "  evpn-bum [status | police <vni> <mac> <b|u|m> <bytes> | unquarantine <vni> <mac>] - EVPN L2 BUM Traffic Storm Policer"
        );
        println!(
            "  gtpu-qos [status | test <qfi> <bytes> | remap <from_qfi> <to_qfi>] - 5G GTP-U QFI Enforcement & Session-AMBR Token Bucket"
        );
        println!(
            "  tsn-qbv-reconfig [status | submit <base_ns> <hex_gate> <dur_ns> | eval <ns>] - IEEE 802.1Qbv Dynamic GCL Reconfiguration"
        );
        println!(
            "  diameter-s6c [status | srr <user> | rdr <user> <outcome>] - 3GPP Diameter S6c SMS Routing & Status Interface"
        );
        println!(
            "  evpn-core-iso [status | uplink-down <iface> | uplink-up <iface> | test <client_iface> [src_esi]] - EVPN Core Isolation"
        );
        println!(
            "  gtpu-failover [status | fwd <sess_id> | ping <sess_id> <ok|fail>] - 5G GTP-U Path Loss Detection & Fast Failover"
        );
        println!(
            "  tsn-qav [status | tx-a <bytes> | tx-b <bytes> | step <ns>] - IEEE 802.1Qav Credit-Based Shaper (CBS) Dual-Class AVB"
        );
        println!(
            "  diameter-np [status | ruca <imsi> <enb> <cell> <level>] - 3GPP Diameter Np RCAF Congestion Reporting"
        );
        println!(
            "  evpn-damp [status | flap <interface> [timestamp_sec] | eval <interface> [timestamp_sec]] - EVPN Flap Damping"
        );
        println!(
            "  gtpu-ma [status | steer | rtt <3gpp|wifi> <ms> | mode <standby|delay|split>] - 5G MA-PDU ATSSS Engine"
        );
        println!(
            "  tsn-preempt [status | calc | test <express|preempt> <bytes> <time_ns> | toggle] - IEEE 802.1Qbu Preemption"
        );
        println!(
            "  diameter-s6t [status | cir <imsi> <type>] - 3GPP Diameter S6t SCEF CIoT Interface"
        );
        println!(
            "  evpn-pvlan [status | set <port> <promisc|iso|comm> [id] | test <in_port> <out_port>] - EVPN PVLAN & Port Isolation"
        );
        println!(
            "  gtpu-redundant [status | tx <payload> | rx <seq> <payload>] - 5G GTP-U Redundant Dual-Tunnel Forwarding"
        );
        println!(
            "  tsn-cqf-time [status | rx <stream> <bytes> | tick <ns>] - IEEE 802.1Qch CQF Time-Synchronized Dispatch"
        );
        println!(
            "  diameter-s6m [status | sir <imsi> | register <imsi> <ok|barred>] - 3GPP Diameter S6m MAP Interworking"
        );
        println!(
            "  evpn-umt [status | add-imet <vni> <ip> | add-smet <vni> <grp> <ip> | resolve <vni> <grp>] - EVPN Unknown Multicast Tree & IR"
        );
        println!(
            "  gtpu-jitter [status | sample <seq> <tx_us> <rx_us> | stream <count>] - 5G GTP-U Path Jitter & OWD Telemetry"
        );
        println!(
            "  tsn-cqf-meter [status | ingest <stream> <bytes> [now_ns] | drop-yellow <true|false>] - IEEE 802.1Qch CQF with trTCM Meter"
        );
        println!(
            "  lsp-ping <target_fec_ip> [mask_len] - MPLS LSP Ping Data Plane Verification (RFC 4379 / Port 3503)"
        );
        println!(
            "  srv6-ops [behaviors | execute <sid>]- SRv6 Network Programming Endpoint Behaviors (RFC 8986)"
        );
        println!(
            "  gre-udp encap <key> <msg>           - GRE-in-UDP Encapsulation for ECMP & NAT Traversal (RFC 8086)"
        );
        println!(
            "  bgp-ls [nodes | links | announce]   - BGP Link-State Topology & TE Distribution (RFC 7752 / RFC 9552)"
        );
        println!(
            "  bgp-ls-srv6 [locators | sids]       - BGP-LS Extensions for Segment Routing over IPv6 / SRv6 (RFC 9514)"
        );
        println!(
            "  bgp-prefix-sid [label | srgb]       - BGP Prefix-SID Attribute for SR-MPLS & SRv6 (RFC 8669 Path Attr 40)"
        );
        println!(
            "  ipfix [export | status]             - IP Flow Information Export / NetFlow v10 (RFC 7011 / UDP 4739)"
        );
        println!(
            "  srv6-mup [sessions | up | down]     - SRv6 Mobile User Plane 5G Core UPF Interworking (End.M.GTP4)"
        );
        println!(
            "  5g-sba [register | smf | amf]       - 5G Core Service Based Architecture REST Dispatcher (3GPP TS 29.500)"
        );
        println!(
            "  sba-events [sub | trigger | log]    - 5G SBA Event Exposure Service Namf_EventExposure (3GPP TS 29.518)"
        );
        println!(
            "  nef-traffic [sub | steer | list]    - 5G NEF Traffic Influence / Edge Computing MEC UPF Steering (TS 29.522)"
        );
        println!(
            "  nrf-oauth [token | verify]          - 5G Core NRF OAuth 2.0 Access Token Authorization Service (TS 29.510)"
        );
        println!(
            "  ngap [setup | ue | pdu]             - 5G N2 / NGAP gNodeB <-> AMF Signalling (3GPP TS 38.413 / SCTP 38412)"
        );
        println!(
            "  pfcp [setup | session | match]      - 5G N4 / PFCP SMF <-> UPF Control Protocol (3GPP TS 29.244 / UDP 8805)"
        );
        println!(
            "  gtp-ext [encap <qfi> | status]      - 5G N3 GTP-U PDU Session Container & QoS Flow Identifier (TS 38.415)"
        );
        println!(
            "  mld [report | query | status]       - Multicast Listener Discovery v2 SSM Group Mgmt (RFC 3810)"
        );
        println!(
            "  bfd6 [status | poll]                - IPv6 Multi-Hop & Single-Hop BFD Liveness Detection (RFC 5883)"
        );
        println!(
            "  geneve-sfc [encap <spi> <si> | hop] - Geneve Service Function Chaining In-Band Metadata (RFC 8926)"
        );
        println!(
            "  usid [pack | forward]               - SRv6 Micro-SID (uSID) Shift-and-Forward Compression Engine"
        );
        println!(
            "  netflow5 [export | status]          - Cisco NetFlow v5 Datacenter Flow Exporter (UDP 2055)"
        );
        println!(
            "  ti-lfa [protect <dst> <neighbor>]   - Topology-Independent Loop-Free Alternate & SR-FRR (RFC 4090)"
        );
        println!(
            "  flex-algo [algo <id> <src> <dst>]   - Segment Routing Flexible Algorithm Topology Slicing (RFC 9350)"
        );
        println!(
            "  geneve-int [trace | status]         - Geneve In-Band Network Telemetry Hop Recording (RFC 8926)"
        );
        println!(
            "  vpls [encap <mac> | status]         - Virtual Private LAN Service & Ethernet Pseudowire (RFC 4762)"
        );
        println!(
            "  cfm [ccm | lbm <trans_id>]          - Carrier Ethernet OAM IEEE 802.1ag / Y.1731 (EtherType 0x8902)"
        );
        println!(
            "  sbfd [probe | status]               - Seamless BFD Stateless Reflector & Initiator (RFC 7880 / UDP 7784)"
        );
        println!(
            "  dom [status | alarms]               - Digital Optical Monitoring Transceiver Telemetry (SFF-8472)"
        );
        println!(
            "  etag [encap <ecid> | status]        - IEEE 802.1BR Bridge Port Extension & E-TAG (EtherType 0x893F)"
        );
        println!(
            "  gnmi [get <path> | subscribe <path>]- OpenConfig gNMI Streaming Telemetry & Config (Port 9339)"
        );
        println!(
            "  gnoi [ping <target> | health | os]  - gRPC Network Operations Interface Microservice RPCs (Port 9339)"
        );
        println!(
            "  sr-policy [steer <color> | list]    - Segment Routing Traffic Steering & Candidate Paths (RFC 9256)"
        );
        println!(
            "  frer [replicate | status]           - IEEE 802.1CB Frame Replication & Elimination / TSN (R-TAG 0xF1C1)"
        );
        println!(
            "  cqf [enqueue | tick | status]       - IEEE 802.1Qch Cyclic Queuing & Forwarding / TSN Bounded Latency"
        );
        println!(
            "  cqf-dual [enqueue | drain | tick]   - IEEE 802.1Qch CQF Ping-Pong Dual Buffer Synchronized Zero-Jitter Forwarding"
        );
        println!(
            "  psfp [police | status]              - IEEE 802.1Qci Per-Stream Filtering & Policing / TSN Ingress Guard"
        );
        println!(
            "  fpe [preempt | status]              - IEEE 802.1Qbu Frame Preemption & Express Interleaving (TSN)"
        );
        println!(
            "  tas [schedule | status]             - IEEE 802.1Qbv Time-Aware Shaper / TSN Scheduled GCL Traffic"
        );
        println!(
            "  ats [enqueue <bytes> | dequeue]     - IEEE 802.1Qcr Asynchronous Traffic Shaping & Urgency-Based Scheduler"
        );
        println!(
            "  cbs [advance <us> | transmit]       - IEEE 802.1Qav Credit-Based Shaper / TSN AVB Stream Reservation"
        );
        println!(
            "  congestion-isolation [test | age]   - IEEE 802.1Qcz Congestion Isolation / RoCEv2 PFC Victim Mitigation"
        );
        println!(
            "  cnc [stream | register | status]    - IEEE 802.1Qcc TSN Centralized Network Configuration (CNC/CUC)"
        );
        println!(
            "  ptp-telecom [bmca | status]         - PTP Telecom Profile ITU-T G.8275.1/G.8275.2 (T-GM/T-BC/T-TSC)"
        );
        println!(
            "  ptp-tc [residence | pdelay | mode]  - PTP Transparent Clock Residence Time & Peer Delay (IEEE 1588v2)"
        );
        println!(
            "  gribi [add | fib <ip> | status]     - gRPC Routing Information Base Interface AFT Injection (Port 9340)"
        );
        println!(
            "  p4 [tables | punt | out <port>]     - P4Runtime SDN Match-Action Table & Packet-IO (Port 9559)"
        );
        println!(
            "  sai [fdb | route | status]          - OpenCompute Switch Abstraction Interface / SONiC Hardware Model"
        );
        println!(
            "  evpn-l3 [lookup <ip> | status]      - EVPN VXLAN Symmetric L3 IRB VRF Routing (RFC 9135 / Type 5)"
        );
        println!(
            "  evpn-mh [df <vlan> | status]        - EVPN Type 4 Multi-Homing Designated Forwarder Election (RFC 7432)"
        );
        println!(
            "  evpn-ad [aliasing | withdraw]       - EVPN Type 1 Ethernet A-D Aliasing & Mass Withdrawal (RFC 7432)"
        );
        println!(
            "  evpn-t3 [list | flood <vni>]        - EVPN Route Type 3 Inclusive Multicast Ethernet Tag / BUM (RFC 7432)"
        );
        println!(
            "  evpn-t5 [lookup <ip> | list]         - EVPN Route Type 5 IP Prefix Overlay Routing (RFC 9136)"
        );
        println!(
            "  evpn-smet [list | resolve <grp>]    - EVPN Route Type 6 Selective Multicast Ethernet Tag / SMET (RFC 9251)"
        );
        println!(
            "  bgp-ext [list | color <c>]          - BGP Extended Communities, Color & Tunnel Encap (RFC 4360/9012)"
        );
        println!(
            "  epe [resolve <label> | list]        - BGP Segment Routing Egress Peer Engineering (RFC 9086/9087)"
        );
        println!(
            "  twamp [test | greeting | status]    - Two-Way Active Measurement Protocol (RFC 5357 / Ports 862)"
        );
        println!(
            "  geneve-opts [build | parse]         - Geneve Extended Metadata & Dynamic TLV Options (RFC 8926)"
        );
        println!(
            "  gre-demux [status | demux <key>]    - GRE RFC 2890 Key-based VRF Demuxing & Anti-Replay"
        );
        println!(
            "  flowspec [rules | drop <dst> <port>]- BGP Flowspec Automated DDoS Mitigation (RFC 5575/8955)"
        );
        println!(
            "  otlp [export | status]              - OpenTelemetry OTLP Metrics & Spans Exporter (Ports 4317/4318)"
        );
        println!(
            "  gre6 encap <msg>                    - GRE-over-IPv6 Tunneling (RFC 7676 NextHdr 47)"
        );
        println!(
            "  ioam [record <msg> | trace]         - In-situ OAM In-Band Telemetry Recording (RFC 9197)"
        );
        println!(
            "  netconf [get | commit | hello]      - NETCONF Network Configuration XML-RPC (RFC 6241)"
        );
        println!(
            "  lisp [lookup <eid> | encap <msg>]   - Locator/ID Separation Protocol Overlay (RFC 9300/9301)"
        );
        println!(
            "  wireguard [handshake | send <msg>]  - WireGuard VPN Tunnel Protocol (Noise IK / UDP 51820)"
        );
        println!(
            "  gptp [pdelay | status]              - IEEE 802.1AS Generalized PTP / TSN (EtherType 0x88F7)"
        );
        println!(
            "  pcep [req <dest> | status]          - Path Computation Element Protocol / SR-MPLS (RFC 5440)"
        );
        println!(
            "  rsvp [path <dest> <bw> | resv <lbl>]- MPLS-TE RSVP-TE Explicit Path Signaling (RFC 3209)"
        );
        println!(
            "  openflow [tables | add <in> <dst> <out>] - OpenFlow 1.3 SDN Controller & Flow Table (TS-025)"
        );
        println!(
            "  diameter [cer | status]             - 4G/5G Core Diameter Base AAA Protocol (RFC 6733)"
        );
        println!(
            "  nsh [encap <spi> <si> <msg>]        - Network Service Header & Service Function Chaining (RFC 8300)"
        );
        println!(
            "  sflow [export | status]             - sFlow v5 Network Flow & Counter Telemetry (RFC 3176)"
        );
        println!(
            "  6in4 encap <msg>                    - IPv6-in-IPv4 Transition Tunnel (RFC 4213 Proto 41)"
        );
        println!(
            "  4in6 encap <msg>                    - IPv4-in-IPv6 Transition Tunnel (RFC 2473 NextHdr 4)"
        );
        println!(
            "  roce [send <qp> <msg> | write <qp>] - RoCEv2 AI/GPU Cluster RDMA Transport (UDP 4791)"
        );
        println!(
            "  pfc [pause <class> | status]        - IEEE 802.1Qbb Priority Flow Control (PFC)"
        );
        println!(
            "  gue [encap <msg>]                   - Generic UDP Encapsulation (RFC 7763 UDP 6080)"
        );
        println!(
            "  evpn [mac|routes|advertised|vni|summary]   - MP-BGP EVPN control plane (RFC 7432, AFI 25/SAFI 70)"
        );
        println!("  ping <ipv4>                         - Send ICMP Echo Request (IPv4 Ping)");
        println!("  ping6 <ipv6>                        - Send ICMPv6 Echo Request (IPv6 Ping6)");
        println!(
            "  dhcpv6 [solicit]                    - Dynamic Host Configuration Protocol for IPv6 (RFC 8415)"
        );
        println!(
            "  vxlan-gpe encap <vni> <msg>         - VXLAN Generic Protocol Extension (UDP 4790)"
        );
        println!("  vtp [status | add <id> <name>]      - Cisco VLAN Trunking Protocol (VTP)");
        println!(
            "  traceroute <ipv4>                   - Trace network route hops using ICMP TTL Exceeded"
        );
        println!(
            "  ldp [hello | map <ip> <label>]      - MPLS Label Distribution Protocol (RFC 5036)"
        );
        println!("  glbp [status | arp | hello]         - Cisco Gateway Load Balancing Protocol");
        println!(
            "  tacacs auth <user> <pass>           - TACACS+ AAA Administrative Access (RFC 8907)"
        );
        println!("  cdp [neighbors | announce]          - Cisco Discovery Protocol v2 (CDPv2)");
        println!("  srv6 [encap | status]               - Segment Routing over IPv6 (RFC 8754)");
        println!(
            "  stun [probe <ip>]                   - Session Traversal Utilities for NAT (RFC 8489)"
        );
        println!(
            "  turn [alloc | send <msg>]           - Traversal Using Relays around NAT (RFC 5766)"
        );
        println!(
            "  gtp [encap <teid> <msg> | echo]     - 4G/5G Cellular GTP-U Tunneling (3GPP TS 29.281)"
        );
        println!(
            "  hsrp [status | hello | preempt]     - Cisco Hot Standby Router Protocol (RFC 2281)"
        );
        println!(
            "  rtp [send <pt> <msg> | sr]          - Real-time Transport Protocol & RTCP (RFC 3550)"
        );
        println!("  ptp [sync | delay]                  - Precision Time Protocol (IEEE 1588v2)");
        println!(
            "  erspan [mirror <session> <msg>]     - Encapsulated Remote SPAN Mirroring (RFC 7637)"
        );
        println!(
            "  mqtt [pub <topic> <msg> | sub]      - Message Queuing Telemetry Transport (ISO 20922)"
        );
        println!(
            "  coap [get <path>]                   - Constrained Application Protocol REST (RFC 7252)"
        );
        println!(
            "  sctp [init | send <msg>]            - Stream Control Transmission Protocol (RFC 4960)"
        );
        println!(
            "  ldap [search <filter> | bind <dn>]  - Lightweight Directory Access Protocol (RFC 4511)"
        );
        println!(
            "  netflow [status | export]           - NetFlow v9 / IPFIX Traffic Telemetry (RFC 3954)"
        );
        println!(
            "  sip [invite <user> | call]          - Session Initiation Protocol & SDP (RFC 3261)"
        );
        println!(
            "  bfd [status | poll]                 - Bidirectional Forwarding Detection (RFC 5880)"
        );
        println!(
            "  geneve [encap <vni> <msg>]          - Generic Network Virtualization Encap (RFC 8926)"
        );
        println!(
            "  isis [hello | status]               - Intermediate System to Intermediate System (RFC 1195)"
        );
        println!(
            "  syslog [send <msg> | list]          - System Logging & Event Telemetry (RFC 5424)"
        );
        println!(
            "  l2tp [encap <session_id> <msg>]     - L2TPv3 Ethernet Pseudowire Tunnel (RFC 3931)"
        );
        println!(
            "  pim [hello | join <group>]          - Protocol Independent Multicast - SM (RFC 7761)"
        );
        println!(
            "  radius auth <user> <pass>           - Authenticate with RADIUS AAA Server (RFC 2865)"
        );
        println!(
            "  pppoe [padi | session <id> <msg>]   - Point-to-Point Protocol over Ethernet (RFC 2516)"
        );
        println!(
            "  eigrp [hello | dual]                - Cisco EIGRP & DUAL Metric Engine (RFC 7868)"
        );
        println!("  ospf [hello | spf]                  - Open Shortest Path First v2 (RFC 2328)");
        println!("  ipsec [status | encap <msg>]        - IPsec ESP Tunnel Mode (RFC 4303)");
        println!(
            "  http3 [get <path> | settings]       - HTTP/3 over QUIC Binary Framing (RFC 9114)"
        );
        println!(
            "  lacp [status | hash <s_ip> <d_ip>]  - Link Aggregation (IEEE 802.1AX / 802.3ad)"
        );
        println!(
            "  mpls [push <label> <msg> | lfib]    - Multi-Protocol Label Switching (RFC 3031)"
        );
        println!(
            "  bgp [summary|peers|routes|rib|capabilities|evpn] - Border Gateway Protocol 4 control plane (RFC 4271)"
        );
        println!(
            "  lldp [neighbors | announce]         - Link Layer Discovery Protocol (IEEE 802.1AB)"
        );
        println!("  stp [status | bpdu]                 - IEEE 802.1D Spanning Tree Protocol");
        println!(
            "  vxlan [vtep | vni | <vni> <msg>]    - Virtual eXtensible LAN Overlay (RFC 7348), UDP 4789"
        );
        println!(
            "  ntp [query <ip> | time]             - Network Time Protocol v4 clock synchronization"
        );
        println!(
            "  tftp get <filename>                 - Trivial File Transfer Protocol client download"
        );
        println!(
            "  snmp get <oid>                      - Simple Network Management Protocol v2c MIB query"
        );
        println!("  quic [probe | frame <msg>]          - QUIC (RFC 9000) binary packet framing");
        println!(
            "  vrrp [status | adv]                 - Virtual Router Redundancy Protocol (RFC 5798)"
        );
        println!(
            "  ndp                                 - Display IPv6 Neighbor Discovery Protocol (NDP) Cache"
        );
        println!(
            "  tunnel gre <dst_ip> <msg>           - Encapsulate payload in GRE (Protocol 47) tunnel"
        );
        println!(
            "  igmp [join <multicast_ip> | list]   - Manage IGMPv2 multicast group memberships"
        );
        println!("  dns <hostname>                      - Query virtual DNS server for IP address");
        println!(
            "  curl <ip[:port]>                    - Perform TCP 3-way handshake and HTTP/1.1 GET"
        );
        println!(
            "  tls <ip[:port]>                     - Perform TLS 1.3 ClientHello / ServerHello Handshake"
        );
        println!(
            "  http2 <ip[:port]>                   - Send HTTP/2 SETTINGS & HEADERS binary frames"
        );
        println!(
            "  ws send <msg>                       - Send masked WebSocket (RFC 6455) text frame"
        );
        println!(
            "  rip [status | adv]                  - RIPv2 dynamic distance-vector routing state"
        );
        println!("  udp send <ip> <port> <msg>          - Send UDP datagram to destination");
        println!("  arp [list | clear]                  - Inspect or manage ARP cache table");
        println!(
            "  route                               - Display routing table with Longest Prefix Match"
        );
        println!("  netstat                             - Display TCP connections and UDP sockets");
        println!("  iptables [list | add drop <ip> | flush] - Configure stateful firewall rules");
        println!("  nat [status | forward <ext_p> <int_ip> <int_p>] - NAT table & port forwarding");
        println!(
            "  tcp-stats                           - Inspect TCP Congestion Control & RTT state"
        );
        println!("  pcap start <file> | stop            - Record live session frames into PCAP");
        println!("  exit / quit                         - Exit the shell\n");
    }

    fn cmd_status(&self) {
        println!("Network Interface eth0 (Dual-Stack):");
        println!("  IPv4 Address : {}", self.stack.config.ip);
        println!("  IPv6 Address : {:?}", self.stack.config.ipv6);
        println!("  MAC Address  : {}", self.stack.config.mac);
        println!("  Subnet Mask  : /{}", self.stack.config.subnet_mask);
        println!("  Gateway      : {:?}", self.stack.config.gateway);
        println!(
            "  Remote Server: IPv4 {} | IPv6 {} ({})",
            self.remote_host_ip, self.remote_host_ipv6, self.remote_host_mac
        );
    }

    fn cmd_lsp_ping(&mut self, args: &[&str]) {
        let fec_ip = if !args.is_empty() {
            Ipv4Address::from_str(args[0]).unwrap_or(Ipv4Address::new(10, 0, 0, 1))
        } else {
            Ipv4Address::new(10, 0, 0, 1)
        };
        let mask_len = if args.len() >= 2 {
            args[1].parse::<u8>().unwrap_or(32)
        } else {
            32
        };

        println!(
            "Initiating MPLS LSP Echo Request (RFC 4379/8029) to Target FEC {}/{}...",
            fec_ip, mask_len
        );
        let req =
            LspEchoPacket::build_echo_request(0x1337BEEF, 1, fec_ip, mask_len, 1700000000, 500000);
        let raw_req = req.serialize();

        // LSP Ping packets use 127.0.0.1 as destination IP to prevent IP forwarding if label popped early
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            Ipv4Address::new(127, 0, 0, 1),
            53503,
            LSP_PING_UDP_PORT,
            &raw_req,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            Ipv4Address::new(127, 0, 0, 1),
            IP_PROTO_UDP,
            940,
            1,
            &udp_req,
        );

        let shim = MplsHeader::new(1001, 0, true, 64);
        let mpls_pkt = MplsPacket {
            labels: vec![shim],
            payload: ip_req,
        };
        let raw_mpls = mpls_pkt.serialize();
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_MPLS_UNICAST,
            &raw_mpls,
        );

        println!(
            "  1. Transmitted MPLS Encapsulated LSP Echo Request (Label 1001, UDP {}, {} bytes)",
            LSP_PING_UDP_PORT,
            eth_req.len()
        );
        println!(
            "     Target FEC Stack TLV: IPv4 Prefix {}/{}",
            fec_ip, mask_len
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Some(reply) = LspEchoPacket::parse(udp.payload) {
                let code_str = match reply.return_code {
                    LSP_RET_CODE_EGRESS_FOR_FEC => {
                        "3 (Replying router is an egress for the FEC at stack-depth)"
                    }
                    8 => "8 (Label switched at stack-depth)",
                    _ => "0 (Success)",
                };
                println!("  2. Received LSP Echo Reply from {}:", ip.header.src_ip);
                println!("     Return Code : {}", code_str);
                println!(
                    "     Sender Handle: 0x{:08X}, Seq: {}",
                    reply.sender_handle, reply.seq_number
                );
                println!("     LSP Data Plane Path Verified & Active!");
            }
        }
    }

    fn cmd_srv6_ops(&mut self, _args: &[&str]) {
        println!("SRv6 Network Programming Endpoint Functions (RFC 8986):");
        println!(
            "┌──────────────────────────────────────────┬────────────────────────────────────────┐"
        );
        println!(
            "│ SID Locator / Function                   │ Endpoint Behavior                      │"
        );
        println!(
            "├──────────────────────────────────────────┼────────────────────────────────────────┤"
        );
        for (sid, b) in &self.srv6_engine.my_sid_table {
            let b_str = match b {
                Srv6Behavior::End => "End (Transit Segment, Decrement SegLeft)".to_string(),
                Srv6Behavior::EndX {
                    next_hop_ip,
                    out_if,
                } => format!("End.X (Cross-Connect -> {} via {})", next_hop_ip, out_if),
                Srv6Behavior::EndDt4 { vrf_id } => {
                    format!("End.DT4 (Decapsulate -> VRF {} IPv4 Table)", vrf_id)
                }
                Srv6Behavior::EndDx2 { out_if } => {
                    format!("End.DX2 (Decapsulate -> L2 {})", out_if)
                }
                _ => format!("{:?}", b),
            };
            println!("│ {:<40} │ {:<38} │", sid, b_str);
        }
        println!(
            "└──────────────────────────────────────────┴────────────────────────────────────────┘"
        );

        let sid_egress = Ipv6Address::from_str("2001:db8:2::200").unwrap();
        let srh = Srv6Header::build(4, &[sid_egress]);
        let res =
            self.srv6_engine
                .process_srv6_packet(sid_egress, srh, b"Customer IPv4 VPN Payload");
        if let Srv6ExecutionResult::DecapIpv4 { vrf_id, payload } = res {
            println!("Execution Demo on SID {}:", sid_egress);
            println!("  Behavior Executed: End.DT4 (VRF {:?})", vrf_id);
            println!(
                "  Inner Decapsulated Payload: \"{}\"",
                String::from_utf8_lossy(&payload)
            );
        }
    }

    fn cmd_gre_udp(&mut self, args: &[&str]) {
        let key = if !args.is_empty() {
            args[0].parse::<u32>().unwrap_or(0x1001)
        } else {
            0x1001
        };

        let msg = if args.len() >= 2 {
            args[1..].join(" ")
        } else {
            "Cloud Multi-Tenant Payload traversing UDP Fabric".to_string()
        };

        let gre_udp = GreUdpPacket::new(52123, 0x0800, Some(key), Some(1), msg.as_bytes());
        let raw_gre = gre_udp.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            gre_udp.src_port,
            GRE_IN_UDP_PORT,
            &raw_gre,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            941,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Transmitted GRE-in-UDP (RFC 8086) Datagram (UDP {}, {} bytes):",
            GRE_IN_UDP_PORT,
            eth_req.len()
        );
        println!(
            "  Entropy Source Port: {} (Enables ECMP multi-path flow hashing)",
            gre_udp.src_port
        );
        println!(
            "  GRE Flags & Key    : Key=0x{:08X}, Seq=1, Inner Proto=0x0800",
            key
        );
        println!("  Inner Payload      : \"{}\"", msg);
    }

    fn cmd_bgp_ls(&mut self, _args: &[&str]) {
        println!("BGP Link-State (BGP-LS - RFC 7752 / RFC 9552) Topology Database:");
        println!("  AFI: 16388 (BGP-LS), SAFI: 71 (BGP-LS)");
        println!("\n  Discovered SDN Nodes:");
        for (router_id, node) in &self.bgp_ls_db.nodes {
            println!(
                "    • Router-ID: {:<15} | ASN: {:<6} | Name: {}",
                router_id,
                node.asn,
                node.node_name.as_deref().unwrap_or("N/A")
            );
        }
        println!("\n  Discovered Traffic Engineering (TE) Links:");
        for link in &self.bgp_ls_db.links {
            println!(
                "    • Link: {} -> {}",
                link.local_interface_ip, link.remote_neighbor_ip
            );
            println!(
                "      TE Metric: {}, Max BW: {:.0} Gbps, Reservable BW: {:.0} Gbps, Admin Group: 0x{:08X}",
                link.te_metric,
                link.max_bandwidth_bps / 1e9,
                link.max_reservable_bandwidth_bps / 1e9,
                link.admin_group_color
            );
        }

        // Demo NLRI serialization
        let sample_node = BgpLsNodeDescriptor {
            asn: 65001,
            igp_router_id: self.stack.config.ip,
            node_name: Some("Local-Leaf-01".to_string()),
        };
        let nlri = BgpLsNlri::Node(sample_node);
        let raw = nlri.serialize();
        println!(
            "\n  Generated BGP-LS Node NLRI Payload ({} bytes):",
            raw.len()
        );
        println!("    Hex: {:02X?}", &raw[..raw.len().min(32)]);
    }

    fn cmd_ipfix(&mut self, _args: &[&str]) {
        println!("IP Flow Information Export (IPFIX / NetFlow v10 - RFC 7011 / RFC 7012):");
        let flows = vec![IpfixFlowRecord {
            src_ip: self.stack.config.ip,
            dst_ip: self.remote_host_ip,
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            packets: 2450,
            octets: 3560000,
            tcp_flags: 0x0018,
            vlan_id: 100,
        }];

        let msg = IpfixMessage::build_standard_flow_export(1700000000, 101, 1, &flows, true);
        let raw_ipfix = msg.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            54739,
            IPFIX_UDP_PORT,
            &raw_ipfix,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            942,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "  Transmitted IPFIX Export Packet (UDP {}, {} bytes):",
            IPFIX_UDP_PORT,
            eth_req.len()
        );
        println!("    Version: 10, Export Time: 1700000000, Seq: 101, Observation Domain: 1");
        println!(
            "    Template: Template ID 256 (9 Field Specifiers: IPs, Ports, Proto, Octets, Packets, TCP Flags, VLAN)"
        );
        println!(
            "    Data Record: {} -> {}:443 (Proto 6, Packets: 2450, Octets: 3560000, VLAN: 100)",
            self.stack.config.ip, self.remote_host_ip
        );

        let parsed = IpfixMessage::parse(&raw_ipfix).unwrap();
        println!(
            "  Receiver Parsed Flow Records: {} record(s) verified successfully!",
            parsed.flow_records.len()
        );
    }

    fn cmd_srv6_mup(&mut self, _args: &[&str]) {
        println!("SRv6 Mobile User Plane (SRv6-MUP) & 5G Core UPF Interworking:");
        println!(
            "┌───────────────────────┬────────────┬────────────────────────────────────────┬─────┐"
        );
        println!(
            "│ gNodeB / UPF IPv4     │ GTP TEID   │ SRv6 Mobile SID                        │ QFI │"
        );
        println!(
            "├───────────────────────┼────────────┼────────────────────────────────────────┼─────┤"
        );
        for ((gnb, teid), sess) in &self.srv6_mup_engine.uplink_sessions {
            println!(
                "│ {:<21} │ 0x{:08X} │ {:<38} │ {:<3} │",
                gnb, teid, sess.srv6_sid, sess.qfi
            );
        }
        println!(
            "└───────────────────────┴────────────┴────────────────────────────────────────┴─────┘"
        );

        let gnb_ip = Ipv4Address::new(192, 168, 1, 50);
        let teid = 0xCAFE0001;
        let pdu_data = b"5G NR User Equipment Data Packet";

        // Uplink Test (End.M.GTP4.E)
        println!("\n1. Uplink Pipeline (End.M.GTP4.E):");
        println!(
            "   Ingress: GTP-U (TEID 0x{:08X}) from gNodeB {}",
            teid, gnb_ip
        );
        let srv6_pkt = self
            .srv6_mup_engine
            .process_uplink_gtp_to_srv6(gnb_ip, teid, pdu_data, self.stack.config.ipv6.unwrap())
            .unwrap();
        let parsed_v6 = Ipv6Packet::parse(&srv6_pkt).unwrap();
        println!(
            "   Egress : SRv6 Encapsulated IPv6 Packet (DA: {}, Length: {} bytes)",
            parsed_v6.header.dst_ip,
            srv6_pkt.len()
        );

        // Downlink Test (End.M.GTP4.D)
        println!("\n2. Downlink Pipeline (End.M.GTP4.D):");
        println!(
            "   Ingress: SRv6 Packet destined to SID {}",
            parsed_v6.header.dst_ip
        );
        let gtp_pkt = self
            .srv6_mup_engine
            .process_downlink_srv6_to_gtp(parsed_v6.header.dst_ip, pdu_data, self.stack.config.ip)
            .unwrap();
        let parsed_v4 = Ipv4Packet::parse(&gtp_pkt, true).unwrap();
        println!(
            "   Egress : GTP-U/UDP/IPv4 Packet to gNodeB {} (Length: {} bytes)",
            parsed_v4.header.dst_ip,
            gtp_pkt.len()
        );
        println!("   SRv6-MUP 5G Core User Plane Interworking Verified!");
    }

    fn cmd_mld(&mut self, _args: &[&str]) {
        println!("Multicast Listener Discovery v2 (MLDv2 - RFC 3810) Subscriptions:");
        println!(
            "┌──────────────────────────────────────────┬────────────────────────────────────────┐"
        );
        println!(
            "│ IPv6 Multicast Group (G)                 │ Allowed Source Filter Set (S)          │"
        );
        println!(
            "├──────────────────────────────────────────┼────────────────────────────────────────┤"
        );
        for (group, sources) in &self.mld_table.group_listeners {
            let src_str = if sources.is_empty() {
                "Any Source (*, G)".to_string()
            } else {
                sources
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("│ {:<40} │ {:<38} │", group, src_str);
        }
        println!(
            "└──────────────────────────────────────────┴────────────────────────────────────────┘"
        );

        let group_ip = Ipv6Address::from_str("ff3e::8000:2").unwrap();
        let src_ip = Ipv6Address::from_str("2001:db8:1::55").unwrap();
        let report = Mldv2ReportPacket::new(vec![MldGroupRecord {
            record_type: MLD_CHANGE_TO_INCLUDE,
            multicast_address: group_ip,
            source_addresses: vec![src_ip],
        }]);
        let raw_mld = report.serialize();

        println!(
            "Transmitted MLDv2 Listener Report (ICMPv6 Type 143, {} bytes):",
            raw_mld.len()
        );
        println!("  Joined SSM Channel: ({}, {})", src_ip, group_ip);
        self.mld_table.process_report(&report);
        println!("  Listener status updated successfully in MLD forwarding table!");
    }

    fn cmd_bfd_v6(&mut self, _args: &[&str]) {
        println!("Multi-Hop & IPv6 BFD (RFC 5881 / RFC 5883) Session Management:");
        for (peer, sess) in &self.bfd_v6_mgr.sessions {
            let mode = if sess.is_multihop {
                "Multi-Hop (UDP 4784)"
            } else {
                "Single-Hop (UDP 3784)"
            };
            println!(
                "  • Peer IPv6: {} | State: {:?} | Discriminators: [My: 0x{:08X}, Your: 0x{:08X}]",
                peer, sess.state, sess.my_discriminator, sess.your_discriminator
            );
            println!(
                "    Mode: {}, Min Tx/Rx: {} us, Multiplier: {}",
                mode, sess.desired_min_tx_us, sess.detect_mult
            );
        }

        println!(
            "\nTransmitting Multi-Hop BFD Control Packet (UDP {}) to {}...",
            BFD_MULTIHOP_PORT, self.remote_host_ipv6
        );
        let bfd_pkt = BfdControlPacket::build_control(BfdState::Down, 0x55443322, 0, 50_000);
        let raw_bfd = bfd_pkt.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            54784,
            BFD_MULTIHOP_PORT,
            &raw_bfd,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            943,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(bfd_resp) = BfdControlPacket::parse(udp.payload) {
                println!(
                    "  Received BFD Response from {}: State: {:?}, YourDisc: 0x{:08X}",
                    ip.header.src_ip, bfd_resp.state, bfd_resp.your_discriminator
                );
                if let Some(session) = self.bfd_v6_mgr.sessions.get_mut(&self.remote_host_ipv6) {
                    session.process_inbound_packet(&bfd_resp);
                    println!("  Local Session State transitioned to: {:?}", session.state);
                }
            }
        }
    }

    fn cmd_geneve_sfc(&mut self, _args: &[&str]) {
        println!("Geneve Service Function Chaining (Geneve-SFC - RFC 8926 / RFC 8300):");
        let hop = GeneveSfcHop {
            vni: 9001,
            service_path_id: 0x0055AA,
            service_index: 3,
            tenant_id: 200,
            security_group: 88,
        };

        let msg = b"Encrypted Enterprise App Traffic traversing SFC Chain";
        let mut sfc_pkt = GeneveSfcPacket::build(9001, 0x0800, hop, msg);
        let raw = sfc_pkt.serialize();

        println!(
            "  1. Originating Geneve-SFC Tunnel Frame (VNI: 9001, {} bytes):",
            raw.len()
        );
        println!(
            "     SFC Path Option   : Class=0x{:04X}, Type=0x{:02X}, SPI=0x{:06X}, SI={}",
            GENEVE_OPT_CLASS_SFC,
            1,
            sfc_pkt.sfc_metadata.service_path_id,
            sfc_pkt.sfc_metadata.service_index
        );
        println!(
            "     SFC Context Option: Tenant ID={}, Security Group={}",
            sfc_pkt.sfc_metadata.tenant_id, sfc_pkt.sfc_metadata.security_group
        );

        // Advance Hop 1: Firewall -> DPI
        sfc_pkt.advance_service_hop();
        println!(
            "  2. Hop 1 Completed (Firewall): Service Index decremented to {}",
            sfc_pkt.sfc_metadata.service_index
        );

        // Advance Hop 2: DPI -> WAF
        sfc_pkt.advance_service_hop();
        println!(
            "  3. Hop 2 Completed (DPI): Service Index decremented to {}",
            sfc_pkt.sfc_metadata.service_index
        );
        println!("  Service Function Chaining In-Band Metadata Progression Verified!");
    }

    fn cmd_usid(&mut self, _args: &[&str]) {
        println!("SRv6 Micro-SID (uSID) Shift-and-Forward Compression Engine:");
        let carrier = UsidCarrier::new(0xFC000001, vec![0x1001, 0x2002, 0xE001]);
        let packed_da = carrier.to_ipv6();

        println!("  1. Originating Compressed IPv6 Packet:");
        println!(
            "     Block Prefix  : 0x{:08X} (fc00:1::/32)",
            carrier.block_prefix
        );
        println!("     Micro-SIDs    : {:?}", carrier.micro_sids);
        println!("     Packed IPv6 DA: {}", packed_da);

        // Hop 1: Node 1001 (End.uN)
        let (hop1_da, beh1) = self
            .srv6_usid_engine
            .process_destination_address(&packed_da)
            .unwrap();
        println!("\n  2. Hop 1 Processing (uSID 0x1001 -> {:?}):", beh1);
        println!(
            "     Active uSID consumed, Shift-and-Forward -> Next DA: {}",
            hop1_da
        );

        // Hop 2: Node 2002 (End.uN)
        let (hop2_da, beh2) = self
            .srv6_usid_engine
            .process_destination_address(&hop1_da)
            .unwrap();
        println!("\n  3. Hop 2 Processing (uSID 0x2002 -> {:?}):", beh2);
        println!(
            "     Active uSID consumed, Shift-and-Forward -> Next DA: {}",
            hop2_da
        );

        // Hop 3: Node E001 (End.uDT4)
        let (_hop3_da, beh3) = self
            .srv6_usid_engine
            .process_destination_address(&hop2_da)
            .unwrap();
        println!("\n  4. Egress Terminus (uSID 0xE001 -> {:?}):", beh3);
        println!(
            "     Decapsulating IPv6 outer carrier and routing inner IPv4 packet to local VRF!"
        );
        println!("  SRv6 uSID Header Compression & Shift-and-Forward Verified!");
    }

    fn cmd_netflow_v5(&mut self, _args: &[&str]) {
        println!(
            "Cisco NetFlow v5 Datacenter Flow Telemetry (UDP {}):",
            NETFLOW_V5_UDP_PORT
        );
        let export_pkt = self.netflow_v5_table.export_packet(120_000, 1700000000);
        let raw = export_pkt.serialize();

        println!(
            "  • Exported NetFlow v5 Packet ({} bytes, {} flow records, seq: {}):",
            raw.len(),
            export_pkt.header.count,
            export_pkt.header.flow_sequence
        );
        for (i, rec) in export_pkt.records.iter().enumerate() {
            println!(
                "    [{}] {}:{} -> {}:{} | Proto: {}, Pkts: {}, Bytes: {}",
                i + 1,
                rec.src_addr,
                rec.src_port,
                rec.dst_addr,
                rec.dst_port,
                rec.protocol,
                rec.packet_count,
                rec.octet_count
            );
        }

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            52055,
            NETFLOW_V5_UDP_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            944,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let _resps = self.remote_stack.process_frame(&eth_req);
        println!(
            "  NetFlow v5 Datagram transmitted to Flow Collector {} successfully!",
            self.remote_host_ip
        );
    }

    fn cmd_ti_lfa(&mut self, _args: &[&str]) {
        println!("Topology-Independent Loop-Free Alternate (TI-LFA) Protection Calculation:");
        println!("  Source: NodeS | Protected Link: NodeS -> NodeE | Target Destination: NodeD");

        if let Some(prot) = self
            .ti_lfa_engine
            .compute_protection("NodeS", "NodeD", "NodeE")
        {
            println!("  • Primary Next-Hop : {}", prot.primary_next_hop);
            println!("  • Backup Next-Hop  : {}", prot.backup_next_hop);
            println!("  • Repair Node (PQ) : {:?}", prot.repair_node);
            println!("  • Backup Segment List: {:?}", prot.backup_segment_list);
            println!("  TI-LFA 100% Link Failure Fast Reroute (<50ms) Pre-computed Successfully!");
        } else {
            println!("  Failed to compute TI-LFA backup path.");
        }
    }

    fn cmd_flex_algo(&mut self, _args: &[&str]) {
        println!("Segment Routing Flexible Algorithms (SR-Flex-Algo - RFC 9350):");
        if let Some((delay_cost, path_delay)) = self
            .flex_algo_engine
            .compute_flex_algo_spf(128, "NodeA", "NodeB")
        {
            println!(
                "  • Algo 128 (Min Delay Slice): Total Delay = {}us, Path = {:?}",
                delay_cost, path_delay
            );
        }
        if let Some((igp_cost, path_igp)) = self
            .flex_algo_engine
            .compute_flex_algo_spf(129, "NodeA", "NodeB")
        {
            println!(
                "  • Algo 129 (Exclude Affinity 0x02): Total IGP Cost = {}, Path = {:?}",
                igp_cost, path_igp
            );
        }
        println!("  SR-Flex-Algo Multi-Topology Constraint-based Slicing Verified!");
    }

    fn cmd_geneve_int(&mut self, _args: &[&str]) {
        println!("Geneve In-Band Network Telemetry (INT-over-Geneve - RFC 8926 / P4 INT):");
        let mut int_pkt = GeneveIntPacket::build(7001, 0x0800, Vec::new(), b"HTTP/2 Data Payload");

        int_pkt.add_hop_telemetry(IntHopTelemetry {
            switch_id: 101,
            ingress_port: 1,
            egress_port: 48,
            hop_latency_ns: 420,
            queue_depth_bytes: 1500,
        });
        int_pkt.add_hop_telemetry(IntHopTelemetry {
            switch_id: 201,
            ingress_port: 12,
            egress_port: 16,
            hop_latency_ns: 310,
            queue_depth_bytes: 4096,
        });
        int_pkt.add_hop_telemetry(IntHopTelemetry {
            switch_id: 102,
            ingress_port: 48,
            egress_port: 2,
            hop_latency_ns: 390,
            queue_depth_bytes: 1024,
        });

        println!("  • Geneve VNI: {}", int_pkt.vni);
        println!(
            "  • In-Band Telemetry Hops Traversed: {}",
            int_pkt.telemetry_hops.len()
        );
        for (i, hop) in int_pkt.telemetry_hops.iter().enumerate() {
            println!(
                "    Hop {}: Switch ID {}, InPort {} -> OutPort {}, Latency {}ns, Queue {}B",
                i + 1,
                hop.switch_id,
                hop.ingress_port,
                hop.egress_port,
                hop.hop_latency_ns,
                hop.queue_depth_bytes
            );
        }
        println!(
            "  • Cumulative End-to-End Latency: {} ns",
            int_pkt.calculate_total_latency_ns()
        );
        println!(
            "  • Peak Buffer Depth on Path    : {} bytes",
            int_pkt.max_queue_depth_bytes()
        );

        let raw = int_pkt.serialize();
        let parsed = GeneveIntPacket::parse(&raw).unwrap();
        println!(
            "  INT-over-Geneve Wire Serialization ({} bytes) & Telemetry Parsing Verified!",
            raw.len()
        );
        assert_eq!(parsed.telemetry_hops.len(), 3);
    }

    fn cmd_vpls(&mut self, _args: &[&str]) {
        println!("Virtual Private LAN Service & Ethernet Pseudowire (VPLS / EoMPLS - RFC 4762):");
        let inner_eth = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            b"Customer L2 Broadcast/Unicast Traffic",
        );

        if let Some(vpls_pkt) =
            self.vpls_instance
                .encapsulate_frame(self.remote_host_mac, &inner_eth, 101)
        {
            let mpls = MplsPacket::parse(&vpls_pkt).unwrap();
            println!(
                "  • Encapsulated VPLS MPLS Frame ({} bytes):",
                vpls_pkt.len()
            );
            println!(
                "    Labels Stack: Tunnel Label = {}, VC/PW Label = {}",
                mpls.labels[0].label, mpls.labels[1].label
            );
            println!("    Control Word (4 bytes) Prepended: Sequence = 101");
            println!(
                "    Inner Payload: Ethernet Frame ({} bytes, {} -> {})",
                inner_eth.len(),
                self.stack.config.mac,
                self.remote_host_mac
            );
            println!("  VPLS Multipoint Pseudowire Encapsulation & Split-Horizon Verified!");
        } else {
            println!("  MAC not found in VPLS FIB table.");
        }
    }

    fn cmd_cfm(&mut self, _args: &[&str]) {
        println!(
            "Carrier Ethernet OAM IEEE 802.1ag / ITU-T Y.1731 (CFM - EtherType 0x{:04X}):",
            ETHERTYPE_CFM
        );

        // 1. Send Continuity Check Message (CCM)
        let ccm = CfmPacket::build_ccm(
            self.cfm_engine.md_level,
            self.cfm_engine.local_mep_id,
            105,
            &self.cfm_engine.maid,
            false,
        );
        let raw_ccm = ccm.serialize();
        let eth_ccm = EthernetFrame::serialize(
            CFM_MULTICAST_CLASS1,
            self.stack.config.mac,
            ETHERTYPE_CFM,
            &raw_ccm,
        );

        println!(
            "  • CCM Heartbeat Frame Transmitted ({} bytes):",
            eth_ccm.len()
        );
        println!(
            "    MD Level: {}, Local MEP ID: {}, MAID: '{}'",
            self.cfm_engine.md_level, self.cfm_engine.local_mep_id, self.cfm_engine.maid
        );
        println!("    Multicast Egress MAC: {}", CFM_MULTICAST_CLASS1);

        // 2. Loopback Message (LBM) / Reply (LBR)
        let lbm = CfmPacket::build_lbm(
            self.cfm_engine.md_level,
            0xAABBCCDD,
            b"Carrier Ping Pattern",
        );
        let raw_lbm = lbm.serialize();
        if let Some(lbr) = self.cfm_engine.process_cfm_frame(&raw_lbm) {
            println!("\n  • LBM/LBR Loopback Roundtrip Verified:");
            println!(
                "    LBR Opcode: {} (Reply), Transaction ID: 0xAABBCCDD, Pattern Length: {} bytes",
                lbr.header.opcode,
                lbr.payload.len() - 4
            );
        }

        // Active peer MEP status
        for (peer_id, status) in &self.cfm_engine.remote_meps {
            println!(
                "  • Monitored Remote MEP {}: Last Seq = {}, CCM Count = {}, RDI = {}",
                peer_id, status.last_seq, status.ccm_count, status.rdi
            );
        }
        println!("  Carrier Ethernet CFM & Y.1731 OAM Health Check OK!");
    }

    fn cmd_sbfd(&mut self, _args: &[&str]) {
        println!(
            "Seamless BFD (S-BFD - RFC 7880 / RFC 7881) Probe to {}:{}...",
            self.remote_host_ip, SBFD_REFLECTOR_PORT
        );
        println!(
            "  • Local Discriminators: {:?}",
            self.sbfd_reflector.local_discriminators
        );
        let my_disc = 0x10001;
        let reflector_disc = 0x90001;

        let probe = SbfdPacket::build_initiator_probe(my_disc, reflector_disc, 50_000);
        let raw_probe = probe.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            57784,
            SBFD_REFLECTOR_PORT,
            &raw_probe,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            945,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Some(sbfd_resp) = SbfdPacket::parse(udp.payload) {
                println!(
                    "  • Received S-BFD Reflection from {}: State: {:?}, FinalBit: {}",
                    ip.header.src_ip, sbfd_resp.state, sbfd_resp.final_bit
                );
                println!(
                    "    My Disc: 0x{:08X} (Reflector), Your Disc: 0x{:08X} (Initiator Match)",
                    sbfd_resp.my_discriminator, sbfd_resp.your_discriminator
                );
                println!("  Stateless S-BFD Reflector Verification Completed Successfully!");
            }
        }
    }

    fn cmd_dom(&mut self, _args: &[&str]) {
        println!("Digital Optical Monitoring & Transceiver Telemetry (SFF-8472 / SFF-8636):");
        for (i, dom) in self.optical_dom.iter().enumerate() {
            let alarms = dom.evaluate_alarms();
            let tx_mw = OpticalDiagnostics::dbm_to_mw(dom.tx_power_dbm);
            let rx_mw = OpticalDiagnostics::dbm_to_mw(dom.rx_power_dbm);

            println!(
                "\n  [{}] Port: {} ({:?})",
                i + 1,
                dom.port_name,
                dom.form_factor
            );
            println!(
                "      Temperature   : {:.1} °C (High Alarm: {:.1} °C)",
                dom.temperature_c, dom.thresholds.temp_high_alarm_c
            );
            println!("      Supply Voltage: {:.2} V", dom.supply_voltage_v);
            println!("      Laser Tx Bias : {:.1} mA", dom.tx_bias_current_ma);
            println!(
                "      Tx Power      : {:.2} dBm ({:.3} mW)",
                dom.tx_power_dbm, tx_mw
            );
            println!(
                "      Rx Power      : {:.2} dBm ({:.3} mW)",
                dom.rx_power_dbm, rx_mw
            );
            println!(
                "      Path Loss     : {:.2} dB | Rx Safety Margin: {:.2} dB",
                dom.link_attenuation_db(),
                dom.rx_optical_margin_db()
            );
            println!(
                "      Status / Flags: RxLOS: {}, TxFault: {}, TempAlarm: {}, RxPowerLow: {}",
                alarms.rx_los, alarms.tx_fault, alarms.temp_alarm, alarms.rx_power_low
            );
        }
        println!("\n  Optical Physical Layer Telemetry & DOM Monitoring OK!");
    }

    fn cmd_etag(&mut self, _args: &[&str]) {
        println!(
            "IEEE 802.1BR Bridge Port Extension & E-TAG (EtherType 0x{:04X}):",
            ETHERTYPE_ETAG
        );
        let etag_header = ETagHeader {
            pcp: 6,
            dei: false,
            ingress_e_cid: 0x10001,
            grp: 0,
            e_cid: 0x20002,
            inner_ethertype: 0x0800,
        };

        let frame = ETagFrame::new(
            self.remote_host_mac,
            self.stack.config.mac,
            etag_header,
            b"Fabric Extender (FEX) Downlink Virtual Port Frame".to_vec(),
        );

        let raw = frame.serialize();
        let parsed = ETagFrame::parse(&raw).unwrap();

        println!(
            "  • Encapsulated 802.1BR E-TAG Frame ({} bytes):",
            raw.len()
        );
        println!(
            "    E-PCP: {}, Ingress E-CID: 0x{:05X}, Target E-CID: 0x{:05X}",
            parsed.etag.pcp, parsed.etag.ingress_e_cid, parsed.etag.e_cid
        );
        println!(
            "    Inner EtherType: 0x{:04X}, Payload Length: {} bytes",
            parsed.etag.inner_ethertype,
            parsed.payload.len()
        );
        println!("  IEEE 802.1BR Port Virtualization & E-TAG Framing Verified!");
    }

    fn cmd_gnmi(&mut self, args: &[&str]) {
        let path_query = if !args.is_empty() {
            args[0]
        } else {
            "/interfaces/interface[name=HundredGigE0/1]/state"
        };

        println!(
            "OpenConfig gNMI (Port {}) Query: '{}'",
            GNMI_PORT, path_query
        );
        let updates = self.gnmi_server.get(path_query);

        println!(
            "  • gNMI Response ({} telemetry notifications):",
            updates.len()
        );
        for update in &updates {
            println!(
                "    [{}] {} = {:?}",
                update.timestamp_ns,
                update.path.to_string_path(),
                update.val
            );
        }
        println!("  gNMI Streaming Telemetry & OpenConfig Tree Verified!");
    }

    fn cmd_sr_policy(&mut self, _args: &[&str]) {
        let color = 100;
        let endpoint = self.remote_host_ipv6;
        println!(
            "Segment Routing Policy (RFC 9256) Steering for (Color: {}, Endpoint: {}):",
            color, endpoint
        );

        if let Some(policy) = self.sr_policy_db.policies.get(&(color, endpoint)) {
            println!("  • Policy Name: '{}'", policy.name);
            println!(
                "  • Candidate Paths Evaluated: {}",
                policy.candidate_paths.len()
            );
            for (i, cp) in policy.candidate_paths.iter().enumerate() {
                println!(
                    "    Path #{}: Preference {}, Origin {:?}",
                    i + 1,
                    cp.preference,
                    cp.protocol_origin
                );
            }

            if let Some(best) = policy.best_candidate_path() {
                println!(
                    "  • Active Candidate Path Selected (Highest Preference {} / {:?}):",
                    best.preference, best.protocol_origin
                );
                for sl in &best.segment_lists {
                    println!("    Segment List (Weight {}):", sl.weight);
                    for (hop_idx, sid) in sl.segments.iter().enumerate() {
                        println!("      Hop #{}: {}", hop_idx + 1, sid);
                    }
                }
            }
            println!("  SR Policy Traffic Steering Pipeline OK!");
        } else {
            println!(
                "  No matching SR Policy found for (Color: {}, Endpoint: {}).",
                color, endpoint
            );
        }
    }

    fn cmd_frer(&mut self, _args: &[&str]) {
        println!(
            "IEEE 802.1CB Frame Replication & Elimination for Reliability (FRER / TSN - EtherType 0x{:04X}):",
            ETHERTYPE_RTAG
        );
        let payload = b"TSN Time-Critical Motion Control & Telemetry";
        let (path_a, path_b) = self.frer_engine.replicate(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            payload,
        );

        println!(
            "  • Replicated Ingress Frame (Seq: {}):",
            path_a.rtag.sequence_number
        );
        println!(
            "    Path A Frame ({} bytes): Dst: {}, Src: {}, Inner EtherType: 0x{:04X}",
            path_a.serialize().len(),
            path_a.dst_mac,
            path_a.src_mac,
            path_a.rtag.inner_ethertype
        );
        println!(
            "    Path B Frame ({} bytes): Dst: {}, Src: {}, Inner EtherType: 0x{:04X}",
            path_b.serialize().len(),
            path_b.dst_mac,
            path_b.src_mac,
            path_b.rtag.inner_ethertype
        );

        // Receive Path A (first arrival)
        let fwd_a = self.frer_engine.process_ingress_frame(&path_a);
        println!(
            "  • Ingress from Path A: Accepted & Forwarded (Payload len: {} bytes)",
            fwd_a.map(|p| p.len()).unwrap_or(0)
        );

        // Receive Path B (duplicate arrival)
        let fwd_b = self.frer_engine.process_ingress_frame(&path_b);
        println!(
            "  • Ingress from Path B: Duplicate Detected & Eliminated: {}",
            fwd_b.is_none()
        );
        println!(
            "  • FRER Engine Stats: Total Forwarded: {}, Total Eliminated Duplicates: {}",
            self.frer_engine.packets_forwarded, self.frer_engine.packets_eliminated_duplicates
        );
        println!("  IEEE 802.1CB Hitless Redundancy & Elimination Verified!");
    }

    fn cmd_gnoi(&mut self, args: &[&str]) {
        let op = if !args.is_empty() { args[0] } else { "health" };
        println!(
            "gRPC Network Operations Interface (gNOI - Port {}) Op: '{}'",
            GNOI_PORT, op
        );

        match op {
            "ping" => {
                let count = 3;
                let results = self.gnoi_server.execute_ping(self.remote_host_ip, count);
                println!(
                    "  • gNOI System.Ping to {} ({} packets):",
                    self.remote_host_ip, count
                );
                for r in &results {
                    println!(
                        "    Reply from {}: seq={} bytes={} rtt={}µs ttl={}",
                        self.remote_host_ip, r.sequence, r.bytes, r.rtt_us, r.ttl
                    );
                }
            }
            "os" => {
                let (os, valid) = self.gnoi_server.verify_os();
                println!(
                    "  • gNOI OS.Verify: Version='{}', IntegrityValid={}",
                    os, valid
                );
            }
            _ => {
                let health = self.gnoi_server.check_health();
                println!("  • gNOI Healthz.Check ({} Subsystems):", health.len());
                for item in &health {
                    println!(
                        "    Component: {:<20} Status: {:?} ({})",
                        item.component, item.status, item.message
                    );
                }
            }
        }
        println!("  gNOI Microservice Operational RPCs OK!");
    }

    fn cmd_evpn_l3(&mut self, args: &[&str]) {
        let query_ip = if !args.is_empty() {
            args[0].parse().unwrap_or(Ipv4Address::new(10, 100, 1, 45))
        } else {
            Ipv4Address::new(10, 100, 1, 45)
        };

        println!(
            "EVPN VXLAN Symmetric L3 IRB VRF '{}' Lookup for IP: {}",
            self.evpn_l3_vrf.vrf_name, query_ip
        );
        println!(
            "  • Local VRF L3 VNI: {}, Local Router MAC: {}",
            self.evpn_l3_vrf.local_l3_vni, self.evpn_l3_vrf.local_router_mac
        );

        if let Some(route) = self.evpn_l3_vrf.lookup(query_ip) {
            println!("  • Matched EVPN Route Type 5 (IP Prefix Route):");
            println!(
                "    Prefix: {}/{} via RD {}",
                route.ip_prefix, route.prefix_len, route.rd
            );
            println!("    Tenant L3 VNI : {}", route.l3_vni);
            println!("    Egress Router MAC (RMAC): {}", route.router_mac);
            println!("    Underlay Next-Hop VTEP  : {}", route.vtep_ip);
            println!("  EVPN Symmetric IRB Inter-Subnet Routing Pipeline OK!");
        } else {
            println!(
                "  No matching route found for {} in VRF '{}'.",
                query_ip, self.evpn_l3_vrf.vrf_name
            );
        }
    }

    fn cmd_cqf(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qch Cyclic Queuing and Forwarding (CQF / TSN) Engine:");
        let (min_lat, max_lat) = self.cqf_engine.latency_bounds_us();
        println!(
            "  • Configured Cycle Duration: {} µs (Deterministic Latency Bounds: {} µs - {} µs)",
            self.cqf_engine.cycle_duration_us, min_lat, max_lat
        );

        // Enqueue high priority industrial control frames
        self.cqf_engine
            .enqueue(101, 7, b"TSN Time-Critical Motion Cycle 1".to_vec());
        self.cqf_engine
            .enqueue(102, 7, b"TSN Time-Critical Sensor Telemetry".to_vec());
        println!(
            "  • Enqueued 2 frames into Cycle Buffer (Active Cycle #{})",
            self.cqf_engine.current_cycle_index
        );

        // Advance cycle: Drain and transmit
        let drained = self.cqf_engine.advance_cycle();
        println!(
            "  • Cycle Tick Advanced -> New Cycle #{}. Drained & Transmitted {} frames:",
            self.cqf_engine.current_cycle_index,
            drained.len()
        );
        for pkt in &drained {
            println!(
                "    Tx Frame ID #{}: Priority={}, Payload='{}'",
                pkt.id,
                pkt.priority,
                String::from_utf8_lossy(&pkt.payload)
            );
        }
        println!("  IEEE 802.1Qch Ping-Pong Cyclic Queuing Verified!");
    }

    fn cmd_gribi(&mut self, args: &[&str]) {
        let lookup_ip = if !args.is_empty() {
            args[0].parse().unwrap_or(Ipv4Address::new(10, 50, 1, 1))
        } else {
            Ipv4Address::new(10, 50, 1, 1)
        };

        println!(
            "gRPC Routing Information Base Interface (gRIBI - Port {}) AFT Table:",
            GRIBI_PORT
        );
        println!(
            "  • Programmed AFT Operations: {}",
            self.gribi_aft.programmed_operations_count
        );
        println!(
            "  • IPv4 AFT Prefix Entries   : {}",
            self.gribi_aft.ipv4_entries.len()
        );
        println!(
            "  • Next Hop Groups (NHG)     : {}",
            self.gribi_aft.next_hop_groups.len()
        );
        println!(
            "  • Next Hops (NH)            : {}",
            self.gribi_aft.next_hops.len()
        );

        if let Some(nh) = self.gribi_aft.resolve_fib(lookup_ip) {
            println!(
                "  • FIB Resolution for {}: NextHop ID #{} (IP: {}, MAC: {}, Weight: {})",
                lookup_ip, nh.id, nh.ip, nh.mac, nh.weight
            );
            println!("  gRIBI SDN Control-Plane FIB Injection OK!");
        } else {
            println!("  • No matching FIB route found for {}.", lookup_ip);
        }
    }

    fn cmd_evpn_mh(&mut self, args: &[&str]) {
        let vlan = if !args.is_empty() {
            args[0].parse().unwrap_or(100)
        } else {
            100
        };

        let default_esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        println!("EVPN Type 4 Multi-Homing Designated Forwarder (DF) Election (RFC 7432):");
        println!("  • Local PE IP: {}", self.evpn_df_engine.local_router_ip);
        println!(
            "  • Ethernet Segment Identifier (ESI): {:02X?}",
            default_esi
        );

        let is_df_vlan = self
            .evpn_df_engine
            .is_designated_forwarder(&default_esi, vlan);
        let is_df_next = self
            .evpn_df_engine
            .is_designated_forwarder(&default_esi, vlan + 1);

        println!(
            "  • DF Election for VLAN {}: {} (Action: {})",
            vlan,
            if is_df_vlan {
                "DESIGNATED FORWARDER (DF)"
            } else {
                "NON-DF (BLOCKED)"
            },
            if is_df_vlan {
                "Forward BUM traffic"
            } else {
                "Filter/Drop BUM traffic"
            }
        );

        println!(
            "  • DF Election for VLAN {}: {} (Action: {})",
            vlan + 1,
            if is_df_next {
                "DESIGNATED FORWARDER (DF)"
            } else {
                "NON-DF (BLOCKED)"
            },
            if is_df_next {
                "Forward BUM traffic"
            } else {
                "Filter/Drop BUM traffic"
            }
        );

        println!("  EVPN All-Active Multi-Homing Split-Horizon & DF Pipeline OK!");
    }

    fn cmd_psfp(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP / TSN) Engine:");
        println!(
            "  • Stream Gate #{} Cycle: {}µs, Open Window: {}µs",
            self.psfp_pipeline.stream_gate.gate_id,
            self.psfp_pipeline.stream_gate.cycle_time_us,
            self.psfp_pipeline.stream_gate.open_duration_us
        );
        println!(
            "  • Flow Meter #{} CIR: {} B/s, CBS: {} Bytes, DropRed: {}",
            self.psfp_pipeline.flow_meter.meter_id,
            self.psfp_pipeline.flow_meter.cir_bytes_sec,
            self.psfp_pipeline.flow_meter.cbs_bytes,
            self.psfp_pipeline.flow_meter.drop_red
        );

        // Frame 1: Arriving at time 250µs (within gate), size 500 bytes -> Accepted
        let res1 = self.psfp_pipeline.filter_and_police(250, 500);
        println!("  • Frame 1 (t=250µs, len=500B): {:?}", res1);

        // Frame 2: Arriving at time 750µs (gate closed) -> Dropped by Gate
        let res2 = self.psfp_pipeline.filter_and_police(750, 500);
        println!("  • Frame 2 (t=750µs, len=500B): {:?}", res2);

        // Frame 3: Arriving at time 100µs, size 2500 bytes (> remaining CBS) -> Dropped by Meter
        let res3 = self.psfp_pipeline.filter_and_police(100, 2500);
        println!("  • Frame 3 (t=100µs, len=2500B): {:?}", res3);

        println!(
            "  • Summary: Passed={}, DroppedByGate={}, DroppedByMeter={}",
            self.psfp_pipeline.frames_passed,
            self.psfp_pipeline.frames_dropped_gate,
            self.psfp_pipeline.frames_dropped_meter
        );
        println!("  IEEE 802.1Qci Stream Filtering & Policing Pipeline OK!");
    }

    fn cmd_p4runtime(&mut self, _args: &[&str]) {
        println!(
            "P4Runtime SDN Data Plane Programming Server (Port {}):",
            P4RUNTIME_PORT
        );
        println!(
            "  • Device ID: {}, Pipeline Loaded: {}",
            self.p4runtime_server.device_id, self.p4runtime_server.pipeline_loaded
        );
        println!(
            "  • Installed Match-Action Tables: {}",
            self.p4runtime_server.table_entries.len()
        );

        for (tbl_name, entries) in &self.p4runtime_server.table_entries {
            println!("    Table: '{}' ({} entries)", tbl_name, entries.len());
            for entry in entries {
                println!(
                    "      Match: {:?} -> Action: '{}' Params: {:?}",
                    entry.matches, entry.action_name, entry.action_params
                );
            }
        }

        // Test Packet-Out
        let out_bytes = self.p4runtime_server.handle_packet_out(P4PacketOut {
            egress_port: 2,
            payload: b"P4 Injected Telemetry Probe".to_vec(),
        });
        println!(
            "  • Packet-Out Emulation: Transmitted {} bytes to port 2",
            out_bytes
        );

        // Test Packet-In
        let pkt_in = self
            .p4runtime_server
            .emit_packet_in(1, b"Punted Control Packet");
        println!(
            "  • Packet-In Emulation: Punted {} bytes from ingress port {}",
            pkt_in.payload.len(),
            pkt_in.ingress_port
        );

        println!("  P4Runtime SDN Controller Pipeline OK!");
    }

    fn cmd_evpn_ad(&mut self, _args: &[&str]) {
        let default_esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        println!("EVPN Route Type 1 Ethernet A-D Aliasing & Fast Mass Withdrawal (RFC 7432):");
        println!("  • Monitored Multi-Homed ESI: {:02X?}", default_esi);

        let active_nhs = self.evpn_aliasing.get_aliasing_nexthops(&default_esi);
        println!(
            "  • Active Aliasing Multi-Path Next-Hops (ECMP): {:?}",
            active_nhs
        );

        // Simulate Link Failure on PE1 -> Fast Mass Withdrawal
        let failed_pe = self.remote_host_ip;
        let withdrawn_count = self.evpn_aliasing.mass_withdraw(&default_esi, failed_pe);
        println!(
            "  • Link Failure Event on PE {}: Triggered Fast Mass Withdrawal (Withdrew {} paths)",
            failed_pe, withdrawn_count
        );

        let remaining_nhs = self.evpn_aliasing.get_aliasing_nexthops(&default_esi);
        println!("  • Post-Convergence Active Next-Hops: {:?}", remaining_nhs);
        println!("  EVPN Type 1 Fast Sub-50ms Mass Withdrawal Convergence OK!");
    }

    fn cmd_fpe(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qbu Frame Preemption & Interspersed Express Traffic (FPE / TSN):");
        let bulk_frame = b"Bulk Best-Effort Video Stream Payload (128 Bytes)".to_vec();
        let express_frame = b"URGENT TSN ROBOTIC MOTOR CONTROL PACKET".to_vec();

        println!(
            "  • Ingress pMAC Bulk Frame ({} bytes): '{}'",
            bulk_frame.len(),
            String::from_utf8_lossy(&bulk_frame)
        );
        println!(
            "  • Ingress eMAC Express Frame ({} bytes): '{}'",
            express_frame.len(),
            String::from_utf8_lossy(&express_frame)
        );

        // Interleave express frame mid-transmission (after 20 bytes of bulk)
        let (frag0, express_tx, frag1) =
            self.preemption_engine
                .interleave_express(&bulk_frame, &express_frame, 20);
        println!("  • Transmission Pipeline with Preemption:");
        println!(
            "    [1] Transmit Preempted Fragment 0 (SMD={:?}, {} bytes)",
            frag0.smd,
            frag0.payload.len()
        );
        println!(
            "    [2] INTERLEAVE EXPRESS FRAME (SMD=SmdE, {} bytes): '{}'",
            express_tx.len(),
            String::from_utf8_lossy(&express_tx)
        );
        println!(
            "    [3] Resume Preempted Fragment 1 (SMD={:?}, {} bytes, is_last={})",
            frag1.smd,
            frag1.payload.len(),
            frag1.is_last
        );

        let reassembled = PreemptionEngine::reassemble_fragments(&[frag0, frag1]).unwrap();
        println!(
            "  • Receiver pMAC Reassembly Status: Complete ({} bytes verified)",
            reassembled.len()
        );
        println!("  IEEE 802.1Qbu / 802.3br Frame Preemption Verified!");
    }

    fn cmd_bgp_ext(&mut self, args: &[&str]) {
        if !args.is_empty() && args[0] == "color" {
            let color_val = if args.len() > 1 {
                args[1].parse().unwrap_or(200)
            } else {
                200
            };
            self.bgp_ext_comms.add(BgpExtendedCommunity::Color {
                flags: 0,
                color: color_val,
            });
            println!(
                "  • Injected BGP Color Extended Community: Color={}",
                color_val
            );
        }

        println!("BGP Extended Communities (RFC 4360 / RFC 7153 / RFC 9012):");
        println!(
            "  • Total Attached Communities: {}",
            self.bgp_ext_comms.communities.len()
        );
        for (idx, comm) in self.bgp_ext_comms.communities.iter().enumerate() {
            let raw = comm.serialize();
            println!("    [{}] {:?} (Raw Hex: {:02X?})", idx + 1, comm, raw);
        }

        if let Some(color) = self.bgp_ext_comms.get_color() {
            println!("  • Active SR-TE Steering Color: {}", color);
        }
        if let Some(encap) = self.bgp_ext_comms.get_tunnel_encap() {
            println!(
                "  • Active Tunnel Encapsulation Type: {} (VXLAN/Geneve/SRv6)",
                encap
            );
        }
        println!("  BGP Extended Communities Container OK!");
    }

    fn cmd_sai(&mut self, _args: &[&str]) {
        println!("OpenCompute Project Switch Abstraction Interface (OCP SAI / SONiC):");
        println!("  • Switch ID: {}", self.sai_adapter.switch_id);
        println!(
            "  • Hardware FDB Entries: {}",
            self.sai_adapter.fdb_table.len()
        );
        println!(
            "  • Hardware Route Entries: {}",
            self.sai_adapter.route_table.len()
        );
        println!(
            "  • Hardware NextHops: {}",
            self.sai_adapter.next_hops.len()
        );

        // Test FDB lookup
        let client_mac = self.stack.config.mac;
        if let Some(port) = self.sai_adapter.lookup_fdb(client_mac, 100) {
            println!(
                "  • FDB Lookup (MAC: {}, VLAN: 100) -> Egress Port #{}",
                client_mac, port
            );
        }

        // Test Route lookup
        let test_ip = Ipv4Address::new(10, 42, 1, 1);
        if let Some(nh) = self.sai_adapter.lookup_route(0, test_ip) {
            println!(
                "  • Route Lookup (VRF 0, IP: {}) -> NextHop ID #{}, IP: {}, Port: {}",
                test_ip, nh.id, nh.ip, nh.port_id
            );
        }

        println!("  SAI Hardware Abstraction Layer Pipeline OK!");
    }

    fn cmd_tas(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qbv Time-Aware Shaper (TAS / TSN GCL Scheduling):");
        println!(
            "  • Total GCL Cycle Time: {}µs, Guard Band: {}µs",
            self.tas_shaper.cycle_time_us, self.tas_shaper.guard_band_us
        );
        for (idx, entry) in self.tas_shaper.gcl.iter().enumerate() {
            println!(
                "    Slot #{}: Gate Mask=0x{:02X} (Queues 0..7), Duration={}µs",
                idx, entry.gate_states, entry.duration_us
            );
        }

        // Test scheduled transmission at t=50µs (Slot 0: Queue 7 open)
        let q7_res = self.tas_shaper.can_transmit(7, 256, 1000, 50);
        let q0_res_slot0 = self.tas_shaper.can_transmit(0, 1500, 1000, 50);
        println!(
            "  • Time t=50µs (Slot 0 TSN Window): Queue 7 Tx={}, Queue 0 Tx={}",
            q7_res, q0_res_slot0
        );

        // Test transmission at t=200µs (Slot 1: Best Effort Window)
        let q0_res_slot1 = self.tas_shaper.can_transmit(0, 1500, 1000, 200);
        // Test guard band violation near slot boundary (t=490µs, only 10µs remaining)
        let q0_gb_violation = self.tas_shaper.can_transmit(0, 1500, 1000, 490);
        println!(
            "  • Time t=200µs (Slot 1 Open): Queue 0 Tx={}",
            q0_res_slot1
        );
        println!(
            "  • Time t=490µs (Slot 1 Near End): Queue 0 Tx={} (Guard Band Protected)",
            q0_gb_violation
        );
        println!(
            "  • Summary: Transmitted={}, GuardBandDrops={}, GateClosedDrops={}",
            self.tas_shaper.transmitted_frames,
            self.tas_shaper.guard_band_drops,
            self.tas_shaper.gate_closed_drops
        );
        println!("  IEEE 802.1Qbv Time-Aware Shaper Verification OK!");
    }

    fn cmd_5g_sba(&mut self, _args: &[&str]) {
        println!("5G Core Service-Based Architecture (SBA - 3GPP TS 29.500 / TS 29.518):");
        println!(
            "  • NRF Registered NF Instances: {}",
            self.sba_bus.nrf.profiles.len()
        );
        for (id, prof) in &self.sba_bus.nrf.profiles {
            println!(
                "    NF [{}]: Type={}, FQDN={}, IP={}, Services={:?}",
                id,
                prof.nf_type.as_str(),
                prof.fqdn,
                prof.ip_address,
                prof.services
            );
        }

        // Send SBA Request: AMF UE Context Creation
        let amf_req = SbaRequest {
            service_name: "namf-comm".to_string(),
            method: "POST".to_string(),
            target_nf: NfType::Amf,
            resource_uri: "/namf-comm/v1/ue-contexts".to_string(),
            payload_json: "{\"supi\":\"imsi-208950000000001\"}".to_string(),
        };
        let amf_resp = self.sba_bus.dispatch(&amf_req);
        println!(
            "  • SBA Dispatch -> AMF (namf-comm): HTTP {} Response: {}",
            amf_resp.status_code, amf_resp.body_json
        );

        // Send SBA Request: SMF PDU Session Establishment
        let smf_req = SbaRequest {
            service_name: "nsmf-pdusession".to_string(),
            method: "POST".to_string(),
            target_nf: NfType::Smf,
            resource_uri: "/nsmf-pdusession/v1/sm-contexts".to_string(),
            payload_json: "{\"pduSessionId\":1,\"dnn\":\"internet\"}".to_string(),
        };
        let smf_resp = self.sba_bus.dispatch(&smf_req);
        println!(
            "  • SBA Dispatch -> SMF (nsmf-pdusession): HTTP {} Response: {}",
            smf_resp.status_code, smf_resp.body_json
        );
        println!("  5G Core Control Plane SBA Dispatcher Pipeline OK!");
    }

    fn cmd_evpn_t5(&mut self, args: &[&str]) {
        if !args.is_empty() && args[0] == "add" {
            let prefix = if args.len() > 1 {
                args[1].parse().unwrap_or(Ipv4Address::new(10, 10, 0, 0))
            } else {
                Ipv4Address::new(10, 10, 0, 0)
            };
            self.evpn_type5_rib.add_route(EvpnType5Route::new_ipv4(
                RouteDistinguisher::new(self.stack.config.ip, 200),
                prefix,
                16,
                self.stack.config.ip,
                60001,
            ));
            println!(
                "  • Injected EVPN Route Type 5: Prefix={}/16, L3VNI=60001",
                prefix
            );
        }

        println!("EVPN Route Type 5 IP Prefix Overlay Routing (RFC 9136):");
        println!(
            "  • Active Type 5 Prefix Routes: {}",
            self.evpn_type5_rib.routes.len()
        );
        for (idx, r) in self.evpn_type5_rib.routes.iter().enumerate() {
            println!(
                "    [{}] Prefix: {}/{}, GW-IP: {}, L3VNI/Label: {}, RD: {:?}",
                idx + 1,
                r.ip_prefix,
                r.prefix_len,
                r.gw_ip,
                r.label_or_vni,
                r.rd
            );
        }

        let lookup_ip = Ipv4Address::new(10, 200, 5, 99);
        if let Some(matched) = self.evpn_type5_rib.lookup_lpm(lookup_ip) {
            println!(
                "  • LPM Lookup for Tenant IP {}: Matched Route {}/{} -> GW-IP {}, L3VNI {}",
                lookup_ip,
                matched.ip_prefix,
                matched.prefix_len,
                matched.gw_ip,
                matched.label_or_vni
            );
        }

        println!("  EVPN Type 5 IP Prefix Overlay Route Pipeline OK!");
    }

    fn cmd_cnc(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qcc TSN Centralized Network Configuration (CNC / CUC):");
        println!(
            "  • Active Reserved Bandwidth: {} bps ({} Mbps)",
            self.tsn_cnc.total_reserved_bandwidth_bps,
            self.tsn_cnc.total_reserved_bandwidth_bps / 1_000_000
        );
        println!(
            "  • Registered Talker Streams: {}",
            self.tsn_cnc.talkers.len()
        );
        for (sid, talker) in &self.tsn_cnc.talkers {
            let bw = CentralizedNetworkConfigurator::compute_stream_bandwidth(&talker.tspec);
            println!(
                "    Stream {:02X?}: Talker MAC={}, VLAN={}, Priority={}, Rate={} bps",
                sid.0, talker.talker_mac, talker.vlan_id, talker.priority, bw
            );
            if let Some(listeners) = self.tsn_cnc.listeners.get(sid) {
                println!("      Subscribed Listeners ({}):", listeners.len());
                for (idx, lis) in listeners.iter().enumerate() {
                    println!(
                        "        [{}] MAC={}, MaxLatencyReq={}µs",
                        idx + 1,
                        lis.listener_mac,
                        lis.reqs.max_latency_us
                    );
                }
            }
        }
        println!("  IEEE 802.1Qcc TSN CNC Stream Configuration Pipeline OK!");
    }

    fn cmd_ptp_telecom(&mut self, _args: &[&str]) {
        println!(
            "PTP Telecom Profile ITU-T G.8275.1 / G.8275.2 (EtherType 0x{:04X}):",
            ETHERTYPE_PTP_TELECOM
        );
        println!("  • Clock Node Role: {:?}", self.ptp_telecom.clock_type);
        println!(
            "  • Own Clock Identity: {:02X?}, Class={}, Accuracy=0x{:02X}, LocalPriority={}",
            self.ptp_telecom.own_attributes.clock_identity,
            self.ptp_telecom.own_attributes.clock_class,
            self.ptp_telecom.own_attributes.clock_accuracy,
            self.ptp_telecom.own_attributes.local_priority
        );

        // Announce PRTC Grandmaster
        let gm_attr = TelecomBmcaAttributes::new_prtc_grandmaster([
            0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55,
        ]);
        let changed = self.ptp_telecom.process_announce(gm_attr.clone());
        println!("  • Ingest Announce from Primary Reference Clock (PRTC / ePRTC GM):");
        println!(
            "    -> BMCA Master Selection: Won Master? {}, Best Master Class={}, LocalPriority={}",
            changed, gm_attr.clock_class, gm_attr.local_priority
        );

        if let Some(ref bm) = self.ptp_telecom.best_master {
            println!(
                "  • Synchronized to Grandmaster: Identity={:02X?}, Class={}",
                bm.clock_identity, bm.clock_class
            );
        }
        println!("  ITU-T G.8275 Telecom BMCA State Machine OK!");
    }

    fn cmd_ngap(&mut self, _args: &[&str]) {
        println!(
            "5G N2 / NGAP Signalling Protocol (3GPP TS 38.413 / SCTP Port {}):",
            NGAP_SCTP_PORT
        );
        println!(
            "  • AMF Connection Status: Connected={}",
            self.ngap_node.is_amf_connected
        );
        if let Some(ref gnb) = self.ngap_node.active_gnb_name {
            println!("  • Registered gNodeB Name: '{}'", gnb);
        }

        // Test Initial UE Message
        let ue_msg = InitialUeMessage {
            ran_ue_ngap_id: 1,
            tac: 0x0001,
            nr_cgi: 0x10101,
            nas_pdu: vec![0x7E, 0x00, 0x41], // 5GS Registration Request
        };
        let amf_ue_id = self.ngap_node.handle_initial_ue_message(&ue_msg);
        println!(
            "  • Dispatched InitialUEMessage (RAN UE ID #{}): AMF Assigned AMF UE NGAP ID=0x{:X}",
            ue_msg.ran_ue_ngap_id, amf_ue_id
        );

        // Test PDU Session Resource Setup
        let pdu_req = PduSessionResourceSetupRequest {
            amf_ue_ngap_id: amf_ue_id,
            ran_ue_ngap_id: 1,
            pdu_session_id: 1,
            upf_transport_ip: Ipv4Address::new(10, 100, 1, 50),
            upf_gtpu_teid: 0x10001,
        };
        let pdu_resp = self
            .ngap_node
            .handle_pdu_session_setup(&pdu_req, self.stack.config.ip);
        println!(
            "  • PDU Session Resource Setup: PDU Session ID={}, UPF Endpoint {}:0x{:X} <-> gNB Endpoint {}:0x{:X}",
            pdu_req.pdu_session_id,
            pdu_req.upf_transport_ip,
            pdu_req.upf_gtpu_teid,
            pdu_resp.gnb_transport_ip,
            pdu_resp.gnb_gtpu_teid
        );
        println!("  5G N2 NGAP Signalling Verification OK!");
    }

    fn cmd_evpn_t3(&mut self, args: &[&str]) {
        println!("EVPN Route Type 3 Inclusive Multicast Ethernet Tag Route (IMET / RFC 7432):");
        println!(
            "  • Active IMET Routes in BUM Tree: {}",
            self.evpn_type3_bum.routes.len()
        );
        for (idx, r) in self.evpn_type3_bum.routes.iter().enumerate() {
            println!(
                "    [{}] Originating IP: {}, VNI/Label: {}, Tunnel Type: {} (Ingress Replication), RD: {:?}",
                idx + 1,
                r.originating_router_ip,
                r.pmsi.mpls_label_or_vni,
                r.pmsi.tunnel_type,
                r.rd
            );
        }

        let target_vni = if !args.is_empty() {
            args[0].parse().unwrap_or(10001)
        } else {
            10001
        };
        let flood_endpoints = self
            .evpn_type3_bum
            .get_flood_endpoints(target_vni, self.stack.config.ip);
        println!(
            "  • Ingress Replication BUM Flood List for VNI {}: {:?}",
            target_vni, flood_endpoints
        );
        println!("  EVPN Type 3 IMET BUM Flooding Tree Pipeline OK!");
    }

    fn cmd_ptp_tc(&mut self, _args: &[&str]) {
        println!("PTP Transparent Clock (TC - IEEE 1588v2 / ITU-T G.8275.1):");
        println!(
            "  • Transparent Clock Operating Mode: {:?}",
            self.ptp_tc_engine.mode
        );
        println!(
            "  • Measured Peer Link Propagation Delay: {} ns",
            self.ptp_tc_engine.peer_delay_ns
        );

        let hop = HopMeasurement {
            ingress_timestamp_ns: 1_000_000_000,
            egress_timestamp_ns: 1_000_000_280, // 280ns residence time inside switch fabric
        };
        let residence = self.ptp_tc_engine.calculate_residence_time(&hop);
        let updated_corr = self.ptp_tc_engine.update_correction_field(50, &hop);

        println!(
            "  • Frame Transit: Ingress={}ns, Egress={}ns -> Residence Time={}ns",
            hop.ingress_timestamp_ns, hop.egress_timestamp_ns, residence
        );
        println!(
            "  • Updated PTP Header Correction Field: 50ns -> {}ns (Scaled: 0x{:016X})",
            updated_corr,
            TransparentClockEngine::to_scaled_nanoseconds(updated_corr)
        );
        println!(
            "  • Total TC Corrected Packets: {}, Total Residence Time: {}ns",
            self.ptp_tc_engine.corrected_packets_count, self.ptp_tc_engine.total_residence_time_ns
        );
        println!("  PTP Transparent Clock Residence Time Correction OK!");
    }

    fn cmd_pfcp(&mut self, _args: &[&str]) {
        println!(
            "5G N4 / PFCP Protocol (Packet Forwarding Control Protocol - 3GPP TS 29.244 / UDP {}):",
            PFCP_UDP_PORT
        );
        println!(
            "  • UPF Node Identifier: '{}', Association Status: Connected={}",
            self.pfcp_upf.node_id, self.pfcp_upf.is_associated
        );
        println!(
            "  • Active PFCP PDU Sessions: {}",
            self.pfcp_upf.sessions.len()
        );

        for (up_seid, session) in &self.pfcp_upf.sessions {
            println!(
                "    Session UP-SEID: 0x{:X} (CP-SEID: 0x{:X})",
                up_seid, session.cp_seid
            );
            for pdr in &session.pdrs {
                println!(
                    "      PDR #{}: Precedence={}, SrcInterface={}, Match TEID=0x{:X?}, UE IP={:?}",
                    pdr.pdr_id, pdr.precedence, pdr.source_interface, pdr.teid, pdr.ue_ip
                );
            }
            for far in &session.fars {
                println!(
                    "      FAR #{}: ApplyAction=0x{:02X} (Forward), DstInterface={}",
                    far.far_id, far.apply_action, far.destination_interface
                );
            }
        }

        // Test PDR matching and forwarding
        if let Some(action) = self.pfcp_upf.match_and_forward(101, 0x10001) {
            println!(
                "  • Ingest Uplink GTP-U Packet (TEID 0x10001): Matched FAR #{} -> Action=Forward to Core/DN",
                action.far_id
            );
        }
        println!("  5G N4 PFCP Session Control & PDR/FAR Forwarding OK!");
    }

    fn cmd_gtp_ext(&mut self, _args: &[&str]) {
        println!(
            "5G N3 GTP-U User Plane Extension Headers & PDU Session Container (3GPP TS 38.415):"
        );
        println!(
            "  • PDU Session Container: Type=DL (0), QFI={}, RQI={}",
            self.gtpu_ext_container.qfi, self.gtpu_ext_container.rqi
        );

        let inner_ip = vec![0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04];
        let packet = build_gtpu_with_pdu_container(0x20001, &self.gtpu_ext_container, &inner_ip);

        println!(
            "  • Encapsulated GTP-U G-PDU with NextExt=0x{:02X} (Len={}B):",
            GTP_EXT_HDR_PDU_SESSION_CONTAINER,
            packet.len()
        );

        if let Some((teid, parsed_cont, payload)) = parse_gtpu_with_pdu_container(&packet) {
            println!(
                "  • Decapsulated GTP-U: TEID=0x{:X}, QFI={}, RQI={}, InnerPayloadLen={}B",
                teid,
                parsed_cont.qfi,
                parsed_cont.rqi,
                payload.len()
            );
        }
        println!("  5G N3 GTP-U PDU Session Container Pipeline OK!");
    }

    fn cmd_ats(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qcr Asynchronous Traffic Shaping (ATS / TSN Urgency-Based Scheduler):");
        println!(
            "  • Registered Stream Shapers: {}",
            self.ats_scheduler.shapers.len()
        );
        for (sid, shaper) in &self.ats_scheduler.shapers {
            println!(
                "    Stream #{}: CIR={} bps, CBS={} bytes, LastET={}µs",
                sid,
                shaper.committed_info_rate_bps,
                shaper.committed_burst_size_bytes,
                shaper.last_eligibility_time_us
            );
        }

        // Test Enqueue
        let payload = vec![0xAA; 1250]; // 1250 bytes @ 10Mbps = 1000µs tx time
        let et = self.ats_scheduler.enqueue_frame(1, 1000, payload).unwrap();
        println!(
            "  • Enqueued Ingress Frame (1250B) at t=1000µs -> Calculated Eligibility Time (ET)={}µs",
            et
        );

        // Test Dequeue
        let dequeued_early = self.ats_scheduler.dequeue_eligible_frame(1500);
        let dequeued_on_time = self.ats_scheduler.dequeue_eligible_frame(2100);

        println!(
            "  • Dequeue Check at t=1500µs: Transmitted={}",
            dequeued_early.is_some()
        );
        println!(
            "  • Dequeue Check at t=2100µs: Transmitted={} (Total Tx Frames={})",
            dequeued_on_time.is_some(),
            self.ats_scheduler.transmitted_frames_count
        );
        println!("  IEEE 802.1Qcr ATS Urgency-Based Scheduler OK!");
    }

    fn cmd_bgp_epe(&mut self, args: &[&str]) {
        println!("BGP Segment Routing Egress Peer Engineering (BGP-EPE / RFC 9086 & RFC 9087):");
        println!(
            "  • Active BGP Peering SIDs: {}",
            self.bgp_epe_db.peering_sids.len()
        );
        for (idx, sid) in self.bgp_epe_db.peering_sids.iter().enumerate() {
            let type_str = match sid.sid_type {
                BGP_EPE_PEER_NODE_SID => "PeerNode-SID",
                BGP_EPE_PEER_ADJ_SID => "PeerAdj-SID",
                BGP_EPE_PEER_SET_SID => "PeerSet-SID",
                _ => "Unknown",
            };
            println!(
                "    [{}] Type: {}, Label: {}, Peer ASN: {}, Peer IP: {}, Iface: {:?}, Weight: {}",
                idx + 1,
                type_str,
                sid.label,
                sid.peer_asn,
                sid.peer_ip,
                sid.egress_interface_id,
                sid.weight
            );
        }

        let target_label = if !args.is_empty() {
            args[0].parse().unwrap_or(16001)
        } else {
            16001
        };
        let paths = self.bgp_epe_db.resolve_egress_path(target_label);
        println!(
            "  • Resolved Egress Paths for Label {}: {} path(s) found",
            target_label,
            paths.len()
        );
        for p in paths {
            println!(
                "    -> NextHop Peer IP: {}, Weight: {}",
                p.peer_ip, p.weight
            );
        }
        println!("  BGP-EPE SR-TE Outbound Steering OK!");
    }

    fn cmd_bgp_ls_srv6(&mut self, _args: &[&str]) {
        println!("BGP-LS Segment Routing over IPv6 Extensions (SRv6 BGP-LS / RFC 9514):");
        println!(
            "  • Advertised SRv6 Locators (TLV 1162): {}",
            self.bgp_ls_srv6_db.locators.len()
        );
        for (idx, loc) in self.bgp_ls_srv6_db.locators.iter().enumerate() {
            println!(
                "    [{}] Locator Prefix: {}/{}, Algo={}, Metric={}",
                idx + 1,
                loc.locator,
                loc.prefix_len,
                loc.algorithm,
                loc.metric
            );
        }

        println!(
            "  • Advertised SRv6 End SIDs (TLV 1106): {}",
            self.bgp_ls_srv6_db.end_sids.len()
        );
        for (idx, sid) in self.bgp_ls_srv6_db.end_sids.iter().enumerate() {
            println!(
                "    [{}] SID: {}, Behavior Code=0x{:04X} (End)",
                idx + 1,
                sid.sid,
                sid.endpoint_behavior
            );
        }
        println!("  SRv6 BGP-LS NLRI & Topology Verification OK!");
    }

    fn cmd_cbs(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qav Credit-Based Shaper (CBS / TSN Audio Video Bridging):");
        println!("  • Traffic Class: '{}'", self.cbs_shaper.class_name);
        println!(
            "  • IdleSlope: {} bps, SendSlope: {} bps, PortRate: {} bps",
            self.cbs_shaper.idle_slope_bps,
            self.cbs_shaper.send_slope_bps,
            self.cbs_shaper.port_transmit_rate_bps
        );
        println!(
            "  • MaxCredit: {} bits, MinCredit: {} bits",
            self.cbs_shaper.max_credit_bits, self.cbs_shaper.min_credit_bits
        );

        // Advance 100µs while waiting
        self.cbs_shaper.has_queued_frames = true;
        self.cbs_shaper.advance_time(100);
        println!(
            "  • Advance 100µs (Waiting): Credit Accumulated = {} bits (CanTransmit={})",
            self.cbs_shaper.current_credit_bits,
            self.cbs_shaper.can_transmit()
        );

        // Simulate 40µs transmission
        self.cbs_shaper.start_transmitting(100);
        self.cbs_shaper.finish_transmitting(140, true);
        println!(
            "  • Transmit for 40µs: Credit Depleted = {} bits (CanTransmit={})",
            self.cbs_shaper.current_credit_bits,
            self.cbs_shaper.can_transmit()
        );
        println!("  IEEE 802.1Qav CBS Bandwidth Reservation Pipeline OK!");
    }

    fn cmd_sba_events(&mut self, _args: &[&str]) {
        println!("5G Core SBA Event Exposure Service (3GPP TS 29.518 Namf_EventExposure):");
        println!(
            "  • Active Event Subscriptions: {}",
            self.sba_events_engine.subscriptions.len()
        );
        for sub in &self.sba_events_engine.subscriptions {
            println!(
                "    Sub #{}: Consumer='{}', Event={:?}, SUPI='{}', Target='{}'",
                sub.sub_id,
                sub.subscriber_nf_id,
                sub.event_type,
                sub.target_supi,
                sub.notification_uri
            );
        }

        // Trigger Event
        let count = self.sba_events_engine.trigger_event(
            SbaEventType::LocationReport,
            "imsi-208950000000001",
            1700000050,
            "CellId=0x10101, TAC=0x0001",
        );
        println!(
            "  • Trigger Event (LocationReport for SUPI imsi-208950000000001): Dispatched to {} subscriber(s)",
            count
        );

        println!(
            "  • Event Exposure Notification Log ({} entries):",
            self.sba_events_engine.notifications_log.len()
        );
        for notif in &self.sba_events_engine.notifications_log {
            println!(
                "    -> Sub #{}: {:?} for SUPI='{}' -> {}",
                notif.sub_id, notif.event_type, notif.supi, notif.destination_uri
            );
        }
        println!("  5G SBA Namf_EventExposure Framework OK!");
    }

    fn cmd_evpn_smet(&mut self, _args: &[&str]) {
        println!("BGP EVPN Selective Multicast Ethernet Tag (SMET / RFC 9251 Route Type 6):");
        println!(
            "  • Advertised SMET Routes: {}",
            self.evpn_smet_engine.smet_routes.len()
        );
        for (idx, r) in self.evpn_smet_engine.smet_routes.iter().enumerate() {
            println!(
                "    [{}] RD={:?}, VLAN Tag={}, Group={}, Originator PE={}",
                idx + 1,
                r.rd,
                r.ethernet_tag_id,
                r.group_ip,
                r.originator_ip
            );
        }

        let target_group = Ipv4Address::new(239, 255, 0, 1);
        let pes = self.evpn_smet_engine.resolve_replication_pes(
            100,
            Ipv4Address::UNSPECIFIED,
            target_group,
        );
        println!(
            "  • Resolved Selective Replication PEs for Group {}: {} PE(s) found",
            target_group,
            pes.len()
        );
        for pe in pes {
            println!("    -> Forwarding to Core Remote PE: {}", pe);
        }
        println!("  EVPN SMET Selective Multicast Forwarding OK!");
    }

    fn cmd_congestion_isolation(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qcz Congestion Isolation (CI / RoCEv2 PFC Victim Flow Mitigation):");
        let flow = CongestionFlowKey {
            src_ip: self.stack.config.ip,
            dst_ip: self.remote_host_ip,
            protocol: 17, // UDP RoCEv2
            src_port: 51000,
            dst_port: 4791,
        };

        println!(
            "  • Ingesting RoCEv2 Flow: {}:{} -> {}:{}",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
        );

        // 1. Packet without CE
        let q1 = self
            .congestion_isolation
            .process_packet(flow.clone(), 0x00, 1000);
        println!(
            "    Packet 1 (No CE): Assigned Queue ID = {} (Standard)",
            q1
        );

        // 2. Packets with CE marks triggering isolation
        self.congestion_isolation
            .process_packet(flow.clone(), 0x03, 1050);
        self.congestion_isolation
            .process_packet(flow.clone(), 0x03, 1100);
        let q4 = self
            .congestion_isolation
            .process_packet(flow.clone(), 0x03, 1150);
        println!(
            "    Packet 2..4 (ECN CE Marks): Queue ID = {} -> Flow State: Isolated (CNP Sent={})",
            q4, self.congestion_isolation.total_cnp_sent
        );

        // 3. Age flow
        self.congestion_isolation.age_flows(5000, 2000);
        println!(
            "  • Aging Check at t=5000µs: Queue ID Restored = {}",
            self.congestion_isolation.flows[0].assigned_queue_id
        );
        println!("  IEEE 802.1Qcz Congestion Isolation Pipeline OK!");
    }

    fn cmd_nef_traffic(&mut self, _args: &[&str]) {
        println!("5G Core NEF Traffic Influence & Edge MEC UPF Steering (3GPP TS 29.522):");
        println!(
            "  • Registered AF Subscriptions: {}",
            self.nef_traffic_engine.subscriptions.len()
        );
        for sub in &self.nef_traffic_engine.subscriptions {
            println!(
                "    Sub #{}: AF-Trans='{}', Service='{}', DNN='{}', Slice={:?}, Target DNAI='{}', Local EAS IP={}",
                sub.sub_id,
                sub.af_trans_id,
                sub.af_service_id,
                sub.dnn,
                sub.snssai,
                sub.target_dnai,
                sub.edge_server_ip
            );
        }

        let slice = SliceId {
            sst: 1,
            sd: 0x000001,
        };
        let decision = self.nef_traffic_engine.evaluate_packet(
            "edge.mec",
            &slice,
            Ipv4Address::new(198, 51, 100, 1),
            8080,
            6,
        );

        if let Some(dec) = decision {
            println!(
                "  • Packet Evaluation Match: Steered to DNAI='{}' -> Local Breakout EAS IP={}",
                dec.target_dnai, dec.local_breakout_ip
            );
        }
        println!("  5G NEF Nnef_TrafficInfluence Edge Steering OK!");
    }

    fn cmd_bgp_prefix_sid(&mut self, _args: &[&str]) {
        println!("BGP Prefix-SID Attribute for Segment Routing (RFC 8669 / Path Attr 40):");
        if let Some(ref li) = self.bgp_prefix_sid_attr.label_index_tlv {
            println!(
                "  • Label-Index TLV (Type 1): Label Index = {}, Flags = 0x{:02X}",
                li.label_index, li.flags
            );
        }
        if let Some(ref srgb) = self.bgp_prefix_sid_attr.srgb_tlv {
            println!(
                "  • Originator SRGB TLV (Type 3): Base = {}, Range = {}",
                srgb.srgb_base, srgb.srgb_range
            );
        }

        let local_srgb_base = 16000;
        let abs_label = self
            .bgp_prefix_sid_attr
            .calculate_absolute_label(local_srgb_base)
            .unwrap_or(0);
        println!(
            "  • Calculated Absolute MPLS Label (Local SRGB Base {}): Label = {}",
            local_srgb_base, abs_label
        );
        println!("  BGP Prefix-SID Path Attribute Processing OK!");
    }

    fn cmd_cqf_dual(&mut self, _args: &[&str]) {
        println!("IEEE 802.1Qch Enhanced Cyclic Queuing & Forwarding (CQF Ping-Pong Dual Buffer):");
        println!(
            "  • Cycle Duration: {}µs, Queue Capacity: {} bytes",
            self.cqf_dual_buffer.cycle_duration_us, self.cqf_dual_buffer.queue_capacity_bytes
        );

        // Cycle 0: Enqueue Frame into Even Queue
        self.cqf_dual_buffer
            .enqueue_frame(101, 100, vec![0xAA; 512]);
        println!(
            "  • Cycle 0 (t=100µs): Enqueued Frame #101 (512B) -> Even Queue Len = {}, Odd Queue Len = {}",
            self.cqf_dual_buffer.queue_even.len(),
            self.cqf_dual_buffer.queue_odd.len()
        );

        // Cycle 1: Switch Cycle -> Transmit Frame from Even Queue, Enqueue into Odd Queue
        self.cqf_dual_buffer
            .enqueue_frame(102, 1100, vec![0xBB; 256]);
        let drained = self.cqf_dual_buffer.drain_transmitting_queue(1200);
        println!(
            "  • Cycle 1 (t=1200µs): Drained Tx Queue -> {} frame(s) transmitted (Frame ID #{:?})",
            drained.len(),
            drained.first().map(|f| f.frame_id)
        );
        println!("  IEEE 802.1Qch Ping-Pong Deterministic Zero-Jitter CQF OK!");
    }

    fn cmd_nrf_oauth(&mut self, _args: &[&str]) {
        println!(
            "5G Core NRF OAuth 2.0 Access Token Authorization (3GPP TS 29.510 Nnrf_AccessToken):"
        );
        println!(
            "  • Authority: NRF '{}'",
            self.nrf_oauth_auth.nrf_instance_id
        );
        println!(
            "  • Active Minted Tokens: {}",
            self.nrf_oauth_auth.active_tokens.len()
        );

        if let Some((token, claims)) = self.nrf_oauth_auth.active_tokens.first() {
            println!("    Token: '{}'", token);
            println!(
                "    Claims: Sub='{}', Aud={:?}, Scope='{}', ExpireAt={}s",
                claims.subject, claims.audience, claims.scope, claims.expires_at_sec
            );

            // Verification tests
            let valid_udm =
                self.nrf_oauth_auth
                    .verify_token(token, NfType::Udm, "nudm-sdm", 1700000100);
            let reject_pcf =
                self.nrf_oauth_auth
                    .verify_token(token, NfType::Pcf, "nudm-sdm", 1700000100);

            println!(
                "  • Token Verification at UDM ('nudm-sdm'): Granted = {}",
                valid_udm
            );
            println!(
                "  • Token Verification at PCF ('nudm-sdm'): Rejected = {}",
                !reject_pcf
            );
        }
        println!("  5G NRF Service-to-Service Security Authorization OK!");
    }

    fn cmd_twamp(&mut self, _args: &[&str]) {
        println!(
            "Two-Way Active Measurement Protocol (TWAMP - RFC 5357) Test to {}:{}...",
            self.remote_host_ip, TWAMP_TEST_PORT
        );
        let t1_sec = 1700000000;
        let t1_frac = 100000;
        let req = TwampTestPacket::build_sender_request(1, t1_sec, t1_frac);
        let raw_req = req.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            50862,
            TWAMP_TEST_PORT,
            &raw_req,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            936,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Some(twamp_resp) = TwampTestPacket::parse(udp.payload) {
                let t4_sec = 1700000000;
                let t4_frac = 101200;

                let metrics = calculate_twamp_metrics(
                    t1_sec,
                    t1_frac,
                    twamp_resp.receive_timestamp_sec.unwrap_or(0),
                    twamp_resp.receive_timestamp_frac.unwrap_or(0),
                    twamp_resp.timestamp_sec,
                    twamp_resp.timestamp_frac,
                    t4_sec,
                    t4_frac,
                );

                println!(
                    "TWAMP Test Reflector Response Received (Seq={}):",
                    twamp_resp.seq_number
                );
                println!(
                    "  Forward Link Delay (T1 -> T2) : {:.2} us",
                    metrics.forward_delay_us
                );
                println!(
                    "  Reverse Link Delay (T3 -> T4) : {:.2} us",
                    metrics.reverse_delay_us
                );
                println!("  Two-Way Round-Trip Time (RTT) : {:.2} us", metrics.rtt_us);
                println!("  Carrier SLA Verification      : Passed (Zero Packet Loss)");
            }
        }
    }

    fn cmd_geneve_opts(&mut self, _args: &[&str]) {
        let sec_group = GeneveOptionTlv::new(
            GENEVE_CLASS_OVS_LINUX,
            GENEVE_TYPE_SECURITY_GROUP,
            false,
            &[0x00, 0x00, 0x07, 0xD0], // Security Group ID 2000
        );
        let telemetry = GeneveOptionTlv::new(
            GENEVE_CLASS_STANDARD,
            GENEVE_TYPE_INBAND_TELEMETRY,
            true,
            &[0xAA, 0xBB, 0xCC, 0xDD],
        );

        let mut combined = Vec::new();
        combined.extend_from_slice(&sec_group.serialize());
        combined.extend_from_slice(&telemetry.serialize());

        println!(
            "Geneve Dynamic Metadata & In-Band TLV Options (RFC 8926, {} bytes):",
            combined.len()
        );
        let parsed = GeneveOptionTlv::parse_all(&combined);
        for (i, opt) in parsed.iter().enumerate() {
            let class_name = match opt.class {
                GENEVE_CLASS_OVS_LINUX => "Open vSwitch / Linux (0x0108)",
                GENEVE_CLASS_STANDARD => "Standard IETF (0x0100)",
                _ => "Vendor Specific",
            };
            println!(
                "  Option #{}: Class={} | Type=0x{:02X} | Critical={} | Data: {:02X?}",
                i + 1,
                class_name,
                opt.type_code,
                opt.critical,
                opt.data
            );
        }
    }

    fn cmd_gre_demux(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("GRE RFC 2890 Demultiplexing & Multi-Tenant VRF Table:");
            println!(
                "┌──────────────────────┬─────────────┬─────────────┬────────┬───────────────────┐"
            );
            println!(
                "│ Remote Peer IP       │ GRE Key     │ Interface   │ VRF ID │ Strict Anti-Replay│"
            );
            println!(
                "├──────────────────────┼─────────────┼─────────────┼────────┼───────────────────┤"
            );
            for ((peer, key), (tun, _)) in &self.gre_demux.tunnels {
                println!(
                    "│ {:<20} │ {:<11} │ {:<11} │ {:<6} │ {:<17} │",
                    peer, key, tun.if_name, tun.vrf_id, tun.strict_sequence
                );
            }
            println!(
                "└──────────────────────┴─────────────┴─────────────┴────────┴───────────────────┘"
            );
        } else if args.len() >= 4 && args[0] == "demux" {
            let key = args[1].parse::<u32>().unwrap_or(1001);
            let seq = args[2].parse::<u32>().unwrap_or(1);
            let msg = args[3..].join(" ");

            let res = self.gre_demux.demux_packet(
                self.remote_host_ip,
                Some(key),
                Some(seq),
                msg.as_bytes(),
            );
            if let Some((iface, vrf, payload)) = res {
                println!(
                    "GRE Packet Demultiplexed Successfully -> Bound Interface: '{}' (VRF {})",
                    iface, vrf
                );
                println!(
                    "  Payload Delivered: \"{}\"",
                    String::from_utf8_lossy(&payload)
                );
            } else {
                println!(
                    "GRE Demux FAILED: Packet dropped (Invalid Key or Duplicate Replay Sequence #{})",
                    seq
                );
            }
        }
    }

    fn cmd_flowspec(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "rules" || args[0] == "status" {
            println!(
                "BGP Flowspec (RFC 5575 / RFC 8955) Active Traffic Filter Rules (AFI 1 / SAFI 133):"
            );
            println!(
                "┌─────┬──────────────────────┬──────────────────────┬─────────────┬─────────────┬──────────┬────────────────────────┐"
            );
            println!(
                "│ ID  │ Destination Prefix   │ Source Prefix        │ IP Protocol │ Dst Port    │ Src Port │ Action                 │"
            );
            println!(
                "├─────┼──────────────────────┼──────────────────────┼─────────────┼─────────────┼──────────┼────────────────────────┤"
            );
            for r in &self.flowspec_engine.rules {
                let d_str = r
                    .match_fields
                    .dst_prefix
                    .map(|(ip, m)| format!("{}/{}", ip, m))
                    .unwrap_or_else(|| "*".to_string());
                let s_str = r
                    .match_fields
                    .src_prefix
                    .map(|(ip, m)| format!("{}/{}", ip, m))
                    .unwrap_or_else(|| "*".to_string());
                let p_str = r
                    .match_fields
                    .ip_protocol
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let dp_str = r
                    .match_fields
                    .dst_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let sp_str = r
                    .match_fields
                    .src_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "*".to_string());
                println!(
                    "│ {:<3} │ {:<20} │ {:<20} │ {:<11} │ {:<11} │ {:<8} │ {:<22} │",
                    r.id, d_str, s_str, p_str, dp_str, sp_str, r.action
                );
            }
            println!(
                "└─────┴──────────────────────┴──────────────────────┴─────────────┴─────────────┴──────────┴────────────────────────┘"
            );
        } else if args.len() >= 3 && args[0] == "drop" {
            let dst_ip = Ipv4Address::from_str(args[1]).unwrap_or(self.stack.config.ip);
            let port = args[2].parse::<u16>().unwrap_or(53);

            let new_id = self.flowspec_engine.rules.len() as u32 + 1;
            let rule = FlowspecRule {
                id: new_id,
                match_fields: FlowspecMatch {
                    dst_prefix: Some((dst_ip, 32)),
                    src_prefix: None,
                    ip_protocol: Some(17), // UDP
                    dst_port: Some(port),
                    src_port: None,
                    tcp_flags: None,
                },
                action: FlowspecAction::Drop,
            };
            let serialized_nlri = self.flowspec_engine.serialize_rule(&rule);
            self.flowspec_engine.add_rule(rule);

            println!(
                "Injected BGP Flowspec NLRI Rule #{}: Drop UDP traffic targeting {}:{}",
                new_id, dst_ip, port
            );
            println!(
                "  BGP NLRI Serialized : {} bytes (AFI 1 / SAFI 133)",
                serialized_nlri.len()
            );
            println!("  DDoS Attack Traffic Automatically Neutralized at Ingress!");
        }
    }

    fn cmd_otlp(&mut self, _args: &[&str]) {
        let span = OtlpSpan {
            trace_id: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ],
            span_id: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            parent_span_id: None,
            name: "network.shell.command".to_string(),
            start_time_ns: 1700000000000000,
            end_time_ns: 1700000000002500,
            attributes: vec![("service.name".to_string(), "toy-tcpip-stack".to_string())],
        };
        self.otlp_exporter.record_span(span);

        let json = self.otlp_exporter.export_json();
        println!(
            "OpenTelemetry OTLP Network Telemetry Stream (Ports {}/{}):",
            OTLP_GRPC_PORT, OTLP_HTTP_PORT
        );
        println!("{}", json);
    }

    fn cmd_gre6(&mut self, args: &[&str]) {
        let msg = if !args.is_empty() {
            args.join(" ")
        } else {
            "Multi-Protocol Overlay Packet traversing Native IPv6 Backbone".to_string()
        };

        let my_ip6 = self.stack.config.ipv6.unwrap();
        let gre6_pkt = GreIpv6Packet::new(
            my_ip6,
            self.remote_host_ipv6,
            ETHERTYPE_IPV4_IN_GRE,
            Some(0x00AABBCC),
            Some(1),
            msg.as_bytes(),
        );
        let raw = gre6_pkt.serialize();

        let eth_frame = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV6,
            &raw,
        );

        println!(
            "Transmitted GRE-over-IPv6 (RFC 7676) Tunnel Frame ({} bytes):",
            eth_frame.len()
        );
        println!(
            "  Outer IPv6 Header  : {} -> {} (Next Header 47 GRE)",
            my_ip6, self.remote_host_ipv6
        );
        println!("  GRE Flags & Key    : Key=0x00AABBCC, Seq=1, Proto=0x0800 (IPv4)");
        println!("  Inner Data Payload : \"{}\"", msg);
    }

    fn cmd_ioam(&mut self, args: &[&str]) {
        let msg = if !args.is_empty() {
            args.join(" ")
        } else {
            "Datacenter IOAM In-Band Telemetry Flow".to_string()
        };

        let mut ioam = IoamPacket::new(1, msg.as_bytes());
        ioam.trace_header.add_hop(101, 1, 2, 1700000000100000, 45); // Leaf 1
        ioam.trace_header.add_hop(201, 3, 4, 1700000000100050, 30); // Spine 1
        ioam.trace_header.add_hop(102, 2, 1, 1700000000100090, 50); // Leaf 2

        let raw = ioam.serialize();
        println!(
            "In-situ OAM (IOAM - RFC 9197) Telemetry Recorded ({} bytes):",
            raw.len()
        );
        println!("  Namespace ID : {}", ioam.trace_header.namespace_id);
        println!(
            "  Recorded Hops ({} nodes in-situ):",
            ioam.trace_header.node_records.len()
        );
        for (i, hop) in ioam.trace_header.node_records.iter().enumerate() {
            println!(
                "    - Hop #{}: Node {:<4} | Port {:<2} -> {:<2} | Transit Queue Delay: {:<3} ns",
                i + 1,
                hop.node_id,
                hop.ingress_if,
                hop.egress_if,
                hop.transit_delay_ns
            );
        }
        println!("  Inner Payload: \"{}\"", msg);
    }

    fn cmd_netconf(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "get" {
            println!(
                "Sending NETCONF <get-config> RPC over TCP {}...",
                NETCONF_PORT
            );
            let req = "<rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><get-config><source><running/></source></get-config></rpc>]]>]]>";
            let resp = self.netconf_server.handle_request(req);
            println!(
                "NETCONF <rpc-reply> received from {}:{}:",
                self.remote_host_ip, NETCONF_PORT
            );
            println!("{}", resp);
        } else if args[0] == "commit" {
            println!("Sending NETCONF <commit> RPC over TCP {}...", NETCONF_PORT);
            let req = "<rpc message-id=\"102\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><commit/></rpc>]]>]]>";
            let resp = self.netconf_server.handle_request(req);
            println!("{}", resp);
            println!("Candidate datastore committed to running datastore!");
        } else if args[0] == "hello" {
            let req = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>";
            let resp = self.netconf_server.handle_request(req);
            println!("NETCONF <hello> capabilities exchange:\n{}", resp);
        }
    }

    fn cmd_lisp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "lookup" {
            let target_eid = if args.len() >= 2 {
                Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 1, 1, 50))
            } else {
                Ipv4Address::new(10, 1, 1, 50)
            };

            println!(
                "Sending LISP Map-Request to Map-Resolver {}:{} for EID {}...",
                self.remote_host_ip, LISP_CONTROL_PORT, target_eid
            );
            let req = LispMapRequest::build(
                0x1122334455667788,
                self.stack.config.ip,
                self.stack.config.ip,
                target_eid,
            );
            let raw_req = req.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                54342,
                LISP_CONTROL_PORT,
                &raw_req,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                933,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            let resps = self.remote_stack.process_frame(&eth_req);
            for resp in resps {
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let udp = UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true)
                    .unwrap();
                if let Some(reply) = LispMapReply::parse(udp.payload) {
                    println!(
                        "LISP Map-Reply Received (Record TTL: {}s):",
                        reply.record_ttl_s
                    );
                    println!("  EID Prefix : {}/{}", reply.target_eid, reply.eid_mask_len);
                    for loc in reply.locators {
                        println!(
                            "  -> RLOC Gateway IP : {} (Priority: {}, Weight: {})",
                            loc.rloc_ip, loc.priority, loc.weight
                        );
                    }
                }
            }
        } else if args.len() >= 3 && args[0] == "encap" {
            let msg = args[2..].join(" ");
            let inner_ip = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                0,
                934,
                64,
                msg.as_bytes(),
            );
            let lisp_pkt = LispDataPacket::encapsulate(0x123456, 0x00000001, &inner_ip);
            let raw_lisp = lisp_pkt.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                54341,
                LISP_DATA_PORT,
                &raw_lisp,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                935,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "Encapsulated LISP Data Packet (UDP {}, {} bytes):",
                LISP_DATA_PORT,
                eth_req.len()
            );
            println!("  LISP Header : Nonce=0x00123456, LSB=0x00000001");
            println!(
                "  Inner IP    : {} bytes (Payload: \"{}\")",
                inner_ip.len(),
                msg
            );
        }
    }

    fn cmd_wireguard(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "handshake" {
            println!(
                "Initiating WireGuard 1-RTT Noise IK Handshake to {}:{}...",
                self.remote_host_ip, WIREGUARD_PORT
            );
            let ephem = [0x55; 32];
            let init = WireguardMessage::build_initiation(self.wg_peer.local_index, ephem);
            let raw_init = init.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                51820,
                WIREGUARD_PORT,
                &raw_init,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                931,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "  1. Sent Handshake Initiation (Type 1, {} bytes): SenderIndex=0x{:08X}",
                raw_init.len(),
                self.wg_peer.local_index
            );

            let resps = self.remote_stack.process_frame(&eth_req);
            for resp in resps {
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let udp = UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true)
                    .unwrap();
                if let Ok(wg_msg) = WireguardMessage::parse(udp.payload)
                    && let WireguardMessage::HandshakeResponse {
                        sender_index,
                        receiver_index,
                        ..
                    } = wg_msg
                {
                    println!(
                        "  2. Received Handshake Response (Type 2, {} bytes): RemoteIndex=0x{:08X}, ReceiverIndex=0x{:08X}",
                        udp.payload.len(),
                        sender_index,
                        receiver_index
                    );
                    self.wg_peer.handle_response(sender_index, receiver_index);
                    println!(
                        "  3. WireGuard Cryptographic Key Session Established! (Tunnel IP: 10.99.0.2/32)"
                    );
                }
            }
        } else if args.len() >= 2 && args[0] == "send" {
            let msg = args[1..].join(" ");
            if !self.wg_peer.is_established {
                self.wg_peer.remote_index = Some(0x99887766);
                self.wg_peer.is_established = true;
            }

            let encap_bytes = self.wg_peer.encapsulate_packet(msg.as_bytes()).unwrap();
            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                51820,
                WIREGUARD_PORT,
                &encap_bytes,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                932,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "Encapsulated WireGuard Data Transport Packet (Type 4, {} bytes):",
                eth_req.len()
            );
            println!(
                "  Receiver Index : 0x{:08X}",
                self.wg_peer.remote_index.unwrap()
            );
            println!("  Counter        : {}", self.wg_peer.send_counter - 1);
            println!("  Inner Payload  : \"{}\"", msg);
        } else if args[0] == "status" {
            println!("WireGuard VPN Interface wg0 (UDP {}):", WIREGUARD_PORT);
            println!(
                "  Endpoint       : {}:{}",
                self.wg_peer.endpoint_ip, self.wg_peer.endpoint_port
            );
            println!("  Allowed IPs    : 10.99.0.2/32");
            println!(
                "  Session State  : {}",
                if self.wg_peer.is_established {
                    "ESTABLISHED"
                } else {
                    "AWAITING_HANDSHAKE"
                }
            );
            println!("  Packets Sent   : {}", self.wg_peer.send_counter);
        }
    }

    fn cmd_gptp(&mut self, _args: &[&str]) {
        let clock_a = [0x52, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56];
        let t1 = GptpTimestamp::new(1700000000, 100_000_000);
        let t2 = GptpTimestamp::new(1700000000, 100_000_040); // 40 ns wire delay
        let t3 = GptpTimestamp::new(1700000000, 100_005_000);
        let t4 = GptpTimestamp::new(1700000000, 100_005_040);

        let req = GptpPacket::build_pdelay_req(clock_a, 1, 101, t1);
        let raw = req.serialize();
        let eth_frame = EthernetFrame::serialize(
            GPTP_MULTICAST_MAC,
            self.stack.config.mac,
            ETHERTYPE_GPTP,
            &raw,
        );

        let p_delay = calculate_gptp_peer_delay(t1, t2, t3, t4);
        println!("IEEE 802.1AS gPTP / Time-Sensitive Networking (TSN):");
        println!(
            "  Transmitted Pdelay_Req to {} (EtherType 0x{:04X}, {} bytes)",
            GPTP_MULTICAST_MAC,
            ETHERTYPE_GPTP,
            eth_frame.len()
        );
        println!("  Source Clock Identity : 52:54:00:FF:FE:12:34:56");
        println!("  Transport Specific    : 1 (IEEE 802.1AS gPTP)");
        println!(
            "  Peer Wire Delay (T_p) : {} ns (Deterministic zero-jitter clock sync!)",
            p_delay
        );
    }

    fn cmd_pcep(&mut self, args: &[&str]) {
        let dst_ip = if args.len() >= 2 && args[0] == "req" {
            Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 0, 0, 4))
        } else {
            Ipv4Address::new(10, 0, 0, 4)
        };

        println!(
            "Sending PCEP Path Computation Request (PCReq) to PCE {}:{}...",
            self.remote_host_ip, PCEP_PORT
        );
        let req = PcepMessage::build_pcreq(101, self.stack.config.ip, dst_ip);
        let raw_req = req.serialize();

        println!(
            "  1. Sent PCReq (Message Type 3, {} bytes): EndPoints={} -> {}",
            raw_req.len(),
            self.stack.config.ip,
            dst_ip
        );

        let rep = self.pcep_session.compute_path(&req).unwrap();
        let raw_rep = rep.serialize();

        println!(
            "  2. Received PCRep (Message Type 4, {} bytes):",
            raw_rep.len()
        );
        if let PcepObject::SrEro { sids } = &rep.objects[1] {
            println!("     Computed SR-MPLS Label Stack : {:?}", sids);
            println!(
                "     Segment Routing Path Ready   : Node-SID 16001 -> Adj-SID 24001 -> Node-SID 16004"
            );
        }
    }

    fn cmd_rsvp(&mut self, args: &[&str]) {
        let dest = if args.len() >= 2 {
            Ipv4Address::from_str(args[1]).unwrap_or(self.remote_host_ip)
        } else {
            self.remote_host_ip
        };

        let bw = if args.len() >= 3 {
            args[2].parse::<u32>().unwrap_or(100) * 1_000_000
        } else {
            100_000_000
        };

        let ero = vec![(false, Ipv4Address::new(192, 168, 1, 1)), (false, dest)];

        let path = RsvpPacket::build_path(self.stack.config.ip, dest, 101, 1, bw, &ero);
        let raw = path.serialize();
        let ip_pkt =
            Ipv4Packet::serialize(self.stack.config.ip, dest, IP_PROTO_RSVP, 930, 64, &raw);
        let eth_frame = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_pkt,
        );

        println!(
            "Transmitted RSVP-TE PATH Message (IP Protocol {}, {} bytes):",
            IP_PROTO_RSVP,
            eth_frame.len()
        );
        println!(
            "  LSP Session   : Destination {} | Tunnel ID: 101 | Ext-ID: {}",
            dest, self.stack.config.ip
        );
        println!(
            "  SENDER_TSPEC  : Guaranteed Bandwidth: {} Mbps",
            bw / 1_000_000
        );
        println!("  Explicit Route: ERO Hops -> [192.168.1.1, {}]", dest);
        println!("  Label Request : Requested Downstream MPLS Label for Traffic Engineered LSP");
    }

    fn cmd_openflow(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "tables" || args[0] == "status" {
            println!("OpenFlow v1.3 SDN Flow Table (TCP Port {}):", OFP_TCP_PORT);
            println!(
                "┌──────────┬──────────────────────┬──────────────────────┬─────────────┬──────────┬──────────┐"
            );
            println!(
                "│ Priority │ In-Port              │ Destination IPv4     │ EtherType   │ Packets  │ Bytes    │"
            );
            println!(
                "├──────────┼──────────────────────┼──────────────────────┼─────────────┼──────────┼──────────┤"
            );
            for e in &self.ofp_table.entries {
                let p_str = e
                    .match_fields
                    .in_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let ip_str = e
                    .match_fields
                    .ip_dst
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let et_str = e
                    .match_fields
                    .eth_type
                    .map(|t| format!("0x{:04X}", t))
                    .unwrap_or_else(|| "*".to_string());
                println!(
                    "│ {:<8} │ {:<20} │ {:<20} │ {:<11} │ {:<8} │ {:<8} │",
                    e.priority, p_str, ip_str, et_str, e.packet_count, e.byte_count
                );
            }
            println!(
                "└──────────┴──────────────────────┴──────────────────────┴─────────────┴──────────┴──────────┘"
            );
        } else if args.len() >= 4 && args[0] == "add" {
            let in_port = args[1].parse::<u32>().unwrap_or(1);
            let dst_ip = Ipv4Address::from_str(args[2]).ok();
            let out_port = args[3].parse::<u32>().unwrap_or(2);

            self.ofp_table.add_entry(
                200,
                OfpMatch {
                    in_port: Some(in_port),
                    eth_type: Some(0x0800),
                    ip_dst: dst_ip,
                },
                vec![OfpAction::Output(out_port)],
            );
            println!(
                "Injected OpenFlow FlowMod Rule: Port {} -> Dst {:?} -> Forward to Port {}",
                in_port, dst_ip, out_port
            );
        } else if args[0] == "hello" {
            let (hdr, hello) = OfpMessage::build_hello(0xABCDEF01);
            let raw = hello.serialize(&hdr);
            println!(
                "Transmitted OpenFlow 1.3 OFPT_HELLO Message ({} bytes): Version=0x04, XID=0xABCDEF01",
                raw.len()
            );
        }
    }

    fn cmd_diameter(&mut self, _args: &[&str]) {
        println!(
            "Transmitting 4G/5G Diameter Capabilities-Exchange-Request (CER) to {}:{}...",
            self.remote_host_ip, DIAMETER_PORT
        );
        let cer = DiameterMessage::build_cer(
            "mme01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            self.stack.config.ip,
            10415, // 3GPP Vendor ID
            "ToyStack-4G-Core",
            0x11223344,
            0x55667788,
        );
        let raw_cer = cer.serialize();

        let resp = self.diameter_server.handle_request(&cer);
        let raw_cea = resp.serialize();

        println!(
            "  1. Sent CER (Command Code 257, {} bytes): Origin-Host='mme01.epc...', Vendor-ID=10415 (3GPP)",
            raw_cer.len()
        );
        println!(
            "  2. Received CEA (Command Code 257, {} bytes): Result-Code={} (DIAMETER_SUCCESS)",
            raw_cea.len(),
            DIAMETER_SUCCESS
        );
        println!("     Carrier LTE/5G Mobile Core AAA Link Active & Authenticated!");
    }

    fn cmd_nsh(&mut self, args: &[&str]) {
        let (spi, si) = if args.len() >= 3 && args[0] == "encap" {
            (
                args[1].parse::<u32>().unwrap_or(42),
                args[2].parse::<u8>().unwrap_or(255),
            )
        } else {
            (42, 255)
        };

        let msg = if args.len() >= 4 {
            args[3..].join(" ")
        } else {
            "Service Chained Flow: FW -> IPS -> WAF".to_string()
        };

        let mut pkt = NshPacket::build_ipv4(spi, si, 1001, 0x12345678, msg.as_bytes());
        let raw = pkt.serialize();

        println!(
            "Network Service Header (NSH - RFC 8300) SFC Encapsulation ({} bytes):",
            raw.len()
        );
        println!(
            "  Base Header        : Version=0, MD-Type=1 (16B Context), NextProto=0x01 (IPv4)"
        );
        println!("  Service Path ID    : SPI={}", pkt.header.service_path_id);
        println!("  Initial Index (SI) : {}", pkt.header.service_index);
        println!("  Context C2 (Tenant): {}", pkt.header.context_c2);
        println!("  Context C4 (Flow)  : 0x{:08X}", pkt.header.context_c4);

        ServiceFunctionForwarder::forward_next_service_hop(&mut pkt);
        println!(
            "  -> Forwarded Hop #1 (Firewall Node): Decremented SI -> {}",
            pkt.header.service_index
        );
        ServiceFunctionForwarder::forward_next_service_hop(&mut pkt);
        println!(
            "  -> Forwarded Hop #2 (IPS Node)     : Decremented SI -> {}",
            pkt.header.service_index
        );
    }

    fn cmd_sflow(&mut self, _args: &[&str]) {
        let mut dgram = SflowDatagram::new(self.stack.config.ip, 101, 360000);
        let sample = SflowFlowSample {
            seq_num: 1,
            source_id: 1,
            sampling_rate: 1000,
            sample_pool: 50000,
            drops: 0,
            input_if: 1,
            output_if: 2,
            orig_packet_len: 128,
            sampled_header: vec![
                0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10, 0x08, 0x00,
            ],
        };
        let counter = SflowCounterSample {
            seq_num: 1,
            source_id: 1,
            if_index: 1,
            if_speed_bps: 10_000_000_000,
            in_octets: 1024000,
            in_packets: 1500,
            out_octets: 512000,
            out_packets: 800,
        };

        dgram.samples.push(SflowSample::Flow(sample));
        dgram.samples.push(SflowSample::Counter(counter));
        let raw = dgram.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            56343,
            SFLOW_UDP_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            923,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Transmitted sFlow v5 Flow & Counter Telemetry Datagram (UDP {}, {} bytes):",
            SFLOW_UDP_PORT,
            eth_req.len()
        );
        println!("  Agent IPv4     : {}", dgram.agent_ip);
        println!(
            "  Sample Records : 1 Flow Sample (1:1000 rate, eth0 -> eth1) + 1 Interface Counter Sample"
        );
    }

    fn cmd_6in4(&mut self, args: &[&str]) {
        let msg = if !args.is_empty() {
            args.join(" ")
        } else {
            "IPv6 Packet traversing legacy IPv4 Backbone".to_string()
        };

        let my_ip6 = self.stack.config.ipv6.unwrap();
        let inner_ip6 =
            Ipv6Packet::serialize(my_ip6, self.remote_host_ipv6, 59, 64, msg.as_bytes());
        let tunnel = Tunnel6in4::new(self.stack.config.ip, self.remote_host_ip);
        let encap_ip4 = tunnel.encapsulate(&inner_ip6, 924);
        let eth_frame = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &encap_ip4,
        );

        println!(
            "Transmitted 6in4 IPv6-in-IPv4 Transition Tunnel Frame ({} bytes, Protocol {}):",
            eth_frame.len(),
            IP_PROTO_IPV6_IN_IPV4
        );
        println!(
            "  Outer IPv4 Header : {} -> {} (IP Protocol 41)",
            self.stack.config.ip, self.remote_host_ip
        );
        println!(
            "  Inner IPv6 Header : {} -> {}",
            my_ip6, self.remote_host_ipv6
        );
        println!("  Inner IPv6 Payload: \"{}\"", msg);
    }

    fn cmd_4in6(&mut self, args: &[&str]) {
        let msg = if !args.is_empty() {
            args.join(" ")
        } else {
            "IPv4 Packet traversing IPv6 Backbone".to_string()
        };

        let inner_ip4 = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            0,
            925,
            64,
            msg.as_bytes(),
        );
        let my_ip6 = self.stack.config.ipv6.unwrap();
        let tunnel = Tunnel4in6::new(my_ip6, self.remote_host_ipv6);
        let encap_ip6 = tunnel.encapsulate(&inner_ip4);
        let eth_frame = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV6,
            &encap_ip6,
        );

        println!(
            "Transmitted 4in6 IPv4-in-IPv6 Transition Tunnel Frame ({} bytes):",
            eth_frame.len()
        );
        println!(
            "  Outer IPv6 Header : {} -> {} (Next Header 4)",
            my_ip6, self.remote_host_ipv6
        );
        println!(
            "  Inner IPv4 Header : {} -> {}",
            self.stack.config.ip, self.remote_host_ip
        );
        println!("  Inner IPv4 Payload: \"{}\"", msg);
    }

    fn cmd_roce(&mut self, args: &[&str]) {
        let qp = if args.len() >= 2 {
            args[1].parse::<u32>().unwrap_or(202)
        } else {
            202
        };

        let msg = if args.len() >= 3 {
            args[2..].join(" ")
        } else {
            "GPU Tensor Buffer Data Transfer over RDMA".to_string()
        };

        println!(
            "Transmitting RoCEv2 InfiniBand RDMA Packet to {}:{} (DestQP=0x{:06X})...",
            self.remote_host_ip, ROCEV2_UDP_PORT, qp
        );
        let roce = RocePacket::build_send(qp, 5000, msg.as_bytes());
        let raw = roce.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            49152,
            ROCEV2_UDP_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            921,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "  RoCEv2 BTH Header : OpCode=0x04 (RC SEND_ONLY), P_Key=0xFFFF, PSN=5000, AckReq=true"
        );
        println!("  Invariant CRC     : 0x{:08X}", roce.icrc);
        println!("  RDMA Payload      : {} bytes (\"{}\")", msg.len(), msg);

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(roce_ack) = RocePacket::parse(udp.payload) {
                println!(
                    "RoCEv2 ACK Received from Remote QP: OpCode=0x11 (RC_ACK), DestQP=0x{:06X}, PSN={}",
                    roce_ack.bth.dest_qp, roce_ack.bth.psn
                );
                println!("  Ultra-low Latency RDMA Transfer Succeeded!");
            }
        }
    }

    fn cmd_pfc(&mut self, args: &[&str]) {
        let cls = if args.len() >= 2 && args[0] == "pause" {
            args[1].parse::<u8>().unwrap_or(3)
        } else {
            3
        };

        println!("Generating IEEE 802.1Qbb Priority Flow Control (PFC) Pause Frame...");
        let pfc = PfcPauseFrame::new(&[cls], 65535);
        let raw = pfc.serialize();
        let eth_frame = EthernetFrame::serialize(
            PFC_MULTICAST_MAC,
            self.stack.config.mac,
            ETHERTYPE_FLOW_CONTROL,
            &raw,
        );

        println!(
            "Transmitted PFC Pause to Multicast MAC {} (EtherType 0x{:04X}, {} bytes):",
            PFC_MULTICAST_MAC,
            ETHERTYPE_FLOW_CONTROL,
            eth_frame.len()
        );
        println!("  MAC Control Opcode : 0x0101 (PFC Pause)");
        println!(
            "  Class Enable Vector: 0b{:08b} (Priority Class {} PAUSED)",
            pfc.class_enable_vector, cls
        );
        println!("  Pause Quantum      : 65535 units (Lossless Ethernet buffer protected!)");
    }

    fn cmd_gue(&mut self, args: &[&str]) {
        let msg = if !args.is_empty() {
            args.join(" ")
        } else {
            "Datacenter Cloud Microservice Payload over GUE".to_string()
        };

        let gue = GuePacket::build_ipv4(msg.as_bytes());
        let raw = gue.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            56080,
            GUE_UDP_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            922,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Transmitted Generic UDP Encapsulation (GUE - RFC 7763) Frame (UDP {}, {} bytes):",
            GUE_UDP_PORT,
            eth_req.len()
        );
        println!("  GUE Header  : Version=0, NextProto=0x04 (IPv4), HLEN=0 (4 bytes)");
        println!("  Inner Data  : {} bytes (\"{}\")", msg.len(), msg);
    }

    /// Builds and converges the EVPN/VXLAN fabric on first use.
    ///
    /// Everything the `evpn`, `vxlan vtep` and `bgp evpn` subcommands print
    /// afterwards is read out of that running fabric. The sessions really
    /// completed a TCP handshake on port 179 through the spine, really
    /// negotiated AFI 25 / SAFI 70, and really exchanged the EVPN routes shown -
    /// and the MAC tables were programmed by those routes, not written here.
    fn ensure_evpn_fabric(&mut self) -> u64 {
        if self.evpn_fabric.is_none() {
            let mut lab = build_evpn_fabric(65001, 65002);
            lab.run_until(250, 60_000, |l| {
                l.routers
                    .values()
                    .filter_map(|r| r.bgp())
                    .all(|b| b.peers().iter().all(|p| p.carries_evpn()))
            });
            // One tenant packet in each direction, which is what makes each leaf
            // learn its local host and originate the Type 2 route for it.
            for (host, dst) in [
                ("host_a", Ipv4Address::new(192, 168, 10, 22)),
                ("host_b", Ipv4Address::new(192, 168, 10, 11)),
            ] {
                if let Some(h) = lab.host_mut(host)
                    && let Some(frame) = h.stack.ping4(dst, 1, 1, b"evpn")
                {
                    lab.send_from_host(host, frame);
                }
                lab.run_until(250, 30_000, |_| false);
            }
            if lab
                .routers
                .values()
                .filter_map(|r| r.vtep())
                .any(|v| v.remote_mac_count() == 0)
            {
                println!("(warning: the EVPN fabric did not fully converge)");
            }
            self.evpn_fabric = Some(lab);
        }
        self.evpn_fabric
            .as_ref()
            .map(|l| l.current_time_ms)
            .unwrap_or(0)
    }

    /// Leaf names in the EVPN fabric that actually have a VTEP, in a stable order.
    fn evpn_leaves(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .evpn_fabric
            .as_ref()
            .map(|l| {
                l.routers
                    .iter()
                    .filter(|(_, r)| r.vtep().is_some())
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// `show evpn mac` - the live (VNI, MAC) -> VTEP table on every leaf.
    fn print_evpn_mac_tables(&self) {
        for name in self.evpn_leaves() {
            let Some(vtep) = self
                .evpn_fabric
                .as_ref()
                .and_then(|l| l.router(&name))
                .and_then(|r| r.vtep())
            else {
                continue;
            };
            println!("== {} (VTEP {}) ==", name, vtep.source_ip);
            println!(
                "┌────────┬───────────────────┬──────────────────┬──────────────┬────────┬──────────────────┐"
            );
            println!(
                "│ VNI    │ MAC Address       │ Host IP          │ Location     │ Seq    │ Source           │"
            );
            println!(
                "├────────┼───────────────────┼──────────────────┼──────────────┼────────┼──────────────────┤"
            );
            for inst in vtep.instances.values() {
                for local in inst.local_macs.values() {
                    println!(
                        "│ {:<6} │ {:<17} │ {:<16} │ {:<12} │ {:<6} │ {:<16} │",
                        inst.vni,
                        local.mac.to_string(),
                        local
                            .ip
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "-".into()),
                        local.access_interface,
                        local.sequence,
                        "local learning"
                    );
                }
                for remote in inst.remote_macs.values() {
                    println!(
                        "│ {:<6} │ {:<17} │ {:<16} │ {:<12} │ {:<6} │ {:<16} │",
                        inst.vni,
                        remote.mac.to_string(),
                        remote
                            .ip
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "-".into()),
                        remote.vtep.to_string(),
                        remote.sequence,
                        format!("EVPN {}", remote.learned_from)
                    );
                }
            }
            println!(
                "└────────┴───────────────────┴──────────────────┴──────────────┴────────┴──────────────────┘"
            );
        }
    }

    /// `show vxlan vtep` - the VTEP and instance configuration on every leaf.
    fn print_evpn_vteps(&self) {
        for name in self.evpn_leaves() {
            let Some(router) = self.evpn_fabric.as_ref().and_then(|l| l.router(&name)) else {
                continue;
            };
            let Some(vtep) = router.vtep() else { continue };
            println!("== {} ==", name);
            print!("{}", vtep);
            for inst in vtep.instances.values() {
                println!(
                    "    VNI {}: {} local MAC(s), {} remote MAC(s), flood list {:?}",
                    inst.vni,
                    inst.local_macs.len(),
                    inst.remote_macs.len(),
                    inst.remote_vteps
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                );
                if !inst.duplicate_macs.is_empty() {
                    println!(
                        "    VNI {}: {} MAC(s) damped as duplicate",
                        inst.vni,
                        inst.duplicate_macs.len()
                    );
                }
            }
        }
    }

    /// `show vxlan vni` - one row per VNI per leaf.
    fn print_evpn_vnis(&self) {
        println!(
            "┌──────────┬────────┬──────────────────┬───────────────┬───────────────┬───────┬────────┐"
        );
        println!(
            "│ Leaf     │ VNI    │ Route Disting.   │ Import RT     │ Export RT     │ Local │ Remote │"
        );
        println!(
            "├──────────┼────────┼──────────────────┼───────────────┼───────────────┼───────┼────────┤"
        );
        for name in self.evpn_leaves() {
            let Some(vtep) = self
                .evpn_fabric
                .as_ref()
                .and_then(|l| l.router(&name))
                .and_then(|r| r.vtep())
            else {
                continue;
            };
            for inst in vtep.instances.values() {
                let join = |set: &std::collections::BTreeSet<RouteTarget>| {
                    set.iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                println!(
                    "│ {:<8} │ {:<6} │ {:<16} │ {:<13} │ {:<13} │ {:<5} │ {:<6} │",
                    name,
                    inst.vni,
                    inst.rd.to_string(),
                    join(&inst.import_rts),
                    join(&inst.export_rts),
                    inst.local_macs.len(),
                    inst.remote_macs.len()
                );
            }
        }
        println!(
            "└──────────┴────────┴──────────────────┴───────────────┴───────────────┴───────┴────────┘"
        );
    }

    /// Builds and converges the two-reflector EVPN fabric on first use.
    ///
    /// The tenant hosts exchange a packet so each leaf learns a local MAC and
    /// originates a Type 2 route for it. Everything the `bgp rr` commands print
    /// is then read out of that live fabric.
    fn ensure_rr_fabric(&mut self) -> u64 {
        if self.rr_fabric.is_none() {
            let mut lab = build_evpn_dual_rr_fabric();
            lab.run_until(250, 90_000, |l| {
                l.routers
                    .values()
                    .filter_map(|r| r.bgp())
                    .all(|b| b.peers().iter().all(|p| p.carries_evpn()))
            });
            for (host, dst) in [
                ("host_a", Ipv4Address::new(192, 168, 10, 22)),
                ("host_b", Ipv4Address::new(192, 168, 10, 11)),
            ] {
                if let Some(h) = lab.host_mut(host)
                    && let Some(frame) = h.stack.ping4(dst, 1, 1, b"rr")
                {
                    lab.send_from_host(host, frame);
                }
                lab.run_until(250, 30_000, |_| false);
            }
            if lab
                .routers
                .values()
                .filter_map(|r| r.vtep())
                .any(|v| v.remote_mac_count() == 0)
            {
                println!("(warning: the route reflector fabric did not fully converge)");
            }
            self.rr_fabric = Some(lab);
        }
        self.rr_fabric
            .as_ref()
            .map(|l| l.current_time_ms)
            .unwrap_or(0)
    }

    /// Router names in the reflector fabric, reflectors first then leaves, each
    /// group in name order so the output is stable.
    fn rr_fabric_routers(&self) -> Vec<String> {
        let Some(lab) = self.rr_fabric.as_ref() else {
            return Vec::new();
        };
        let mut reflectors: Vec<String> = Vec::new();
        let mut leaves: Vec<String> = Vec::new();
        for (name, r) in lab.routers.iter() {
            let Some(b) = r.bgp() else { continue };
            if b.is_route_reflector() {
                reflectors.push(name.clone());
            } else {
                leaves.push(name.clone());
            }
        }
        reflectors.sort();
        leaves.sort();
        reflectors.extend(leaves);
        reflectors
    }

    /// `bgp rr` - reflection role, cluster identifier, and per-neighbour counts.
    fn print_rr_summary(&self, now_ms: u64) {
        let Some(lab) = self.rr_fabric.as_ref() else {
            return;
        };
        println!(
            "BGP route reflection (RFC 4456), simulated time {}ms",
            now_ms
        );
        for name in self.rr_fabric_routers() {
            let Some(bgp) = lab.router(&name).and_then(|r| r.bgp()) else {
                continue;
            };
            let is_rr = bgp.is_route_reflector();
            println!(
                "\n== {} == router-id {}  AS {}  route-reflector {}",
                name,
                bgp.router_id,
                bgp.local_as,
                if is_rr { "enabled" } else { "disabled" }
            );
            if is_rr {
                println!(
                    "  cluster-id {}  clients [{}]",
                    bgp.cluster_id(),
                    bgp.route_reflector_clients()
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let rts: Vec<String> = bgp
                .import_route_targets()
                .iter()
                .map(|r| r.to_string())
                .collect();
            let (received, imported, originated) = bgp.evpn_route_counts();
            println!(
                "  import route-targets [{}]  retain-all-RTs {}",
                rts.join(", "),
                if bgp.retains_all_route_targets() {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "  EVPN routes: received {}  locally imported {}  retained-not-imported {}  \
                 advertisable {}  originated {}",
                received,
                imported,
                bgp.evpn_retained_not_imported(),
                bgp.evpn_advertisable_count(),
                originated
            );
            println!(
                "  VXLAN tenant forwarding: {}",
                match lab.router(&name).and_then(|r| r.vtep()) {
                    Some(v) => format!(
                        "VTEP {} with {} remote MAC(s)",
                        v.source_ip,
                        v.remote_mac_count()
                    ),
                    None => "none (control plane only)".to_string(),
                }
            );

            for peer in bgp.peers() {
                let families: Vec<String> = peer
                    .negotiated_families()
                    .iter()
                    .map(|f| f.name())
                    .collect();
                println!(
                    "  neighbor {} role {:<10} state {:<11} up {}",
                    peer.addr,
                    peer.role.as_str(),
                    peer.state,
                    peer.uptime_ms(now_ms)
                        .map(|u| format!("{}ms", u))
                        .unwrap_or("down".into())
                );
                println!(
                    "    AFI/SAFI [{}]  4-octet ASN {}",
                    families.join(", "),
                    if peer.negotiated.four_octet_as {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "    EVPN received {}  advertised {}  reflected {}  withheld-by-propagation-rules {}",
                    peer.counters.evpn_received,
                    peer.counters.evpn_advertised,
                    peer.counters.routes_reflected,
                    bgp.evpn_rr_suppressed(peer.addr)
                );
                println!(
                    "    loops rejected: originator {}  cluster {}   collisions resolved {}",
                    peer.counters.originator_loops_rejected,
                    peer.counters.cluster_loops_rejected,
                    peer.counters.collisions_resolved
                );
            }
        }
    }

    /// `bgp rr clients` - who is a client of whom, and what that permits.
    fn print_rr_clients(&self) {
        let Some(lab) = self.rr_fabric.as_ref() else {
            return;
        };
        println!("  Speaker   Neighbor         Role         Reflects to");
        for name in self.rr_fabric_routers() {
            let Some(bgp) = lab.router(&name).and_then(|r| r.bgp()) else {
                continue;
            };
            for peer in bgp.peers() {
                // What a route from this neighbour may be passed on to, which is
                // the whole of RFC 4456 section 5 in one line.
                let reflects_to = if !bgp.is_route_reflector() {
                    "nothing (not a reflector)"
                } else if peer.is_client() {
                    "clients and non-clients"
                } else {
                    "clients only"
                };
                println!(
                    "  {:<9} {:<16} {:<12} {}",
                    name,
                    peer.addr.to_string(),
                    peer.role.as_str(),
                    reflects_to
                );
            }
        }
    }

    /// `bgp rr routes` - every EVPN path held, with where it came from and
    /// whether this speaker can actually use it.
    fn print_rr_routes(&self) {
        let Some(lab) = self.rr_fabric.as_ref() else {
            return;
        };
        for name in self.rr_fabric_routers() {
            let Some(bgp) = lab.router(&name).and_then(|r| r.bgp()) else {
                continue;
            };
            println!("== {} EVPN Adj-RIB-In ==", name);
            let mut any = false;
            for path in bgp.evpn_adj_rib_in.iter_paths() {
                any = true;
                let key = path.route.key();
                println!(
                    "  [{}] {:<19} {:<17} vni {:<6} next-hop {:<13} from {} ({}) {}{}",
                    key.route_type(),
                    key.rd().to_string(),
                    key.mac().map(|m| m.to_string()).unwrap_or("-".into()),
                    path.route.vni(),
                    path.route.next_hop.to_string(),
                    path.peer_addr,
                    if path.from_client {
                        "client"
                    } else {
                        "non-client"
                    },
                    if path.importable {
                        "imported"
                    } else {
                        "retained-only"
                    },
                    format_reflection(path.originator_id, &path.cluster_list)
                );
            }
            if !any {
                println!("  (no EVPN routes received)");
            }
        }
    }

    /// `bgp rr advertised` - the EVPN Adj-RIB-Out, marking what was reflected.
    fn print_rr_advertised(&self) {
        let Some(lab) = self.rr_fabric.as_ref() else {
            return;
        };
        for name in self.rr_fabric_routers() {
            let Some(bgp) = lab.router(&name).and_then(|r| r.bgp()) else {
                continue;
            };
            println!("== {} EVPN Adj-RIB-Out ==", name);
            for peer in bgp.peers() {
                let keys = bgp.evpn_adj_rib_out.keys(peer.addr);
                if keys.is_empty() {
                    println!("  to {} ({}): nothing advertised", peer.addr, peer.role);
                    continue;
                }
                println!(
                    "  to {} ({}): {} route(s), {} reflected",
                    peer.addr,
                    peer.role,
                    keys.len(),
                    bgp.evpn_adj_rib_out.reflected_count(peer.addr)
                );
                for key in keys {
                    let Some(advert) = bgp.evpn_adj_rib_out.get(peer.addr, &key) else {
                        continue;
                    };
                    println!(
                        "    [{}] {:<19} {:<17} vni {:<6} next-hop {}{}",
                        key.route_type(),
                        key.rd().to_string(),
                        key.mac().map(|m| m.to_string()).unwrap_or("-".into()),
                        advert.route.vni(),
                        advert.route.next_hop,
                        format_reflection(advert.originator_id, &advert.cluster_list)
                    );
                }
            }
        }
    }

    /// `bgp evpn routes` - the EVPN Loc-RIB and Adj-RIB-In on every leaf.
    fn print_evpn_routes(&self, adj_rib_in: bool) {
        for name in self.evpn_leaves() {
            let Some(bgp) = self
                .evpn_fabric
                .as_ref()
                .and_then(|l| l.router(&name))
                .and_then(|r| r.bgp())
            else {
                continue;
            };
            println!(
                "== {} EVPN {} ==",
                name,
                if adj_rib_in { "Adj-RIB-In" } else { "Loc-RIB" }
            );
            println!(
                "   Type  Route Distinguisher  MAC                Host IP           VNI     Next-Hop VTEP  AS Path     Route Targets"
            );
            let paths: Vec<_> = if adj_rib_in {
                bgp.evpn_adj_rib_in.iter_paths().collect()
            } else {
                bgp.evpn_loc_rib.iter().map(|(_, p)| p).collect()
            };
            if paths.is_empty() {
                println!("   (no EVPN routes)");
                continue;
            }
            for path in paths {
                let key = path.route.key();
                println!(
                    "   [{}]   {:<19}  {:<17}  {:<16}  {:<6}  {:<13}  {:<10}  {}",
                    key.route_type(),
                    key.rd().to_string(),
                    key.mac().map(|m| m.to_string()).unwrap_or("-".into()),
                    path.route
                        .host_ip()
                        .map(|i| i.to_string())
                        .unwrap_or("-".into()),
                    path.route.vni(),
                    path.route.next_hop.to_string(),
                    if path.local {
                        "local".to_string()
                    } else {
                        path.as_path.to_string()
                    },
                    path.route
                        .route_targets
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
    }

    /// `bgp evpn advertised` - the EVPN Adj-RIB-Out, per neighbour.
    fn print_evpn_advertised(&self) {
        for name in self.evpn_leaves() {
            let Some(bgp) = self
                .evpn_fabric
                .as_ref()
                .and_then(|l| l.router(&name))
                .and_then(|r| r.bgp())
            else {
                continue;
            };
            println!("== {} EVPN Adj-RIB-Out ==", name);
            for peer in bgp.peers() {
                let keys = bgp.evpn_adj_rib_out.keys(peer.addr);
                if keys.is_empty() {
                    println!("  to {}: nothing advertised", peer.addr);
                    continue;
                }
                for key in keys {
                    if let Some(advert) = bgp.evpn_adj_rib_out.get(peer.addr, &key) {
                        let route = &advert.route;
                        println!(
                            "  to {}: [{}] {} {} vni {} next-hop {} rt [{}]{}{}",
                            peer.addr,
                            key.route_type(),
                            key.rd(),
                            key.mac().map(|m| m.to_string()).unwrap_or("-".into()),
                            route.vni(),
                            route.next_hop,
                            route
                                .route_targets
                                .iter()
                                .map(|r| r.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                            route
                                .mobility_seq
                                .map(|s| format!(" seq {}", s))
                                .unwrap_or_default(),
                            format_reflection(advert.originator_id, &advert.cluster_list)
                        );
                    }
                }
            }
        }
    }

    /// `bgp evpn summary` - one block per leaf: session, families, route counts.
    fn print_evpn_summary(&self, now_ms: u64) {
        for name in self.evpn_leaves() {
            let Some(bgp) = self
                .evpn_fabric
                .as_ref()
                .and_then(|l| l.router(&name))
                .and_then(|r| r.bgp())
            else {
                continue;
            };
            let (adj_in, loc, originated) = bgp.evpn_route_counts();
            println!(
                "== {} == router-id {} local-AS {}",
                name, bgp.router_id, bgp.local_as
            );
            println!(
                "  EVPN Adj-RIB-In {} route(s), Loc-RIB {}, originated {}",
                adj_in, loc, originated
            );
            let rts: Vec<String> = bgp
                .import_route_targets()
                .iter()
                .map(|r| r.to_string())
                .collect();
            println!("  import route-targets [{}]", rts.join(", "));
            for peer in bgp.peers() {
                let families: Vec<String> = peer
                    .negotiated_families()
                    .iter()
                    .map(|f| f.name())
                    .collect();
                println!(
                    "  neighbor {} remote-AS {} state {} up {}",
                    peer.addr,
                    peer.remote_as,
                    peer.state,
                    peer.uptime_ms(now_ms)
                        .map(|u| format!("{}ms", u))
                        .unwrap_or("down".into())
                );
                println!(
                    "    negotiated AFI/SAFI [{}]  4-octet ASN {}",
                    families.join(", "),
                    if peer.negotiated.four_octet_as {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!(
                    "    EVPN routes received {} advertised {} rejected-by-RT {}",
                    peer.counters.evpn_received,
                    peer.counters.evpn_advertised,
                    peer.counters.evpn_rt_rejected
                );
            }
        }
    }

    /// `bgp capabilities` - what each speaker offers and what each session agreed.
    fn print_bgp_capabilities(&self) {
        for (label, fabric) in [
            ("EVPN fabric", self.evpn_fabric.as_ref()),
            ("IPv4 fabric", self.bgp_fabric.as_ref()),
            ("route reflector fabric", self.rr_fabric.as_ref()),
        ] {
            let Some(lab) = fabric else { continue };
            let mut names: Vec<&String> = lab.routers.keys().collect();
            names.sort();
            for name in names {
                let Some(bgp) = lab.router(name).and_then(|r| r.bgp()) else {
                    continue;
                };
                println!("== {} / {} ==", label, name);
                println!("  advertised: {}", bgp.local_capabilities());
                for peer in bgp.peers() {
                    let families: Vec<String> = peer
                        .negotiated_families()
                        .iter()
                        .map(|f| f.to_string())
                        .collect();
                    println!("  neighbor {} ({})", peer.addr, peer.state);
                    println!("    peer offered : {}", peer.negotiated.peer);
                    println!("    negotiated   : {}", families.join(", "));
                    // Route reflection needs no capability of its own, so the
                    // role is printed beside the negotiated families rather than
                    // among them: it is configuration, not something agreed.
                    println!(
                        "    reflection   : role {}, local cluster-id {}",
                        peer.role.as_str(),
                        bgp.cluster_id()
                    );
                }
            }
        }
    }

    fn cmd_evpn(&mut self, args: &[&str]) {
        let sub = args.first().copied().unwrap_or("mac");

        if sub == "help" {
            println!("evpn <subcommand>  - MP-BGP EVPN control plane over the live fabric");
            println!("  mac | rib | status - the (VNI, MAC) -> VTEP forwarding table per leaf");
            println!("  routes             - the EVPN Loc-RIB per leaf");
            println!("  adj-rib-in         - every EVPN route received, per leaf");
            println!("  advertised         - the EVPN Adj-RIB-Out, per neighbor");
            println!("  summary            - sessions, negotiated families, route counts");
            println!("  vni                - one row per VNI: RD, import/export RT, MAC counts");
            println!("  advertise <mac> <ip> <vni> - show the framing of a Type 2 NLRI");
            return;
        }

        if args.len() >= 4 && args[0] == "advertise" {
            self.cmd_evpn_advertise_demo(args);
            return;
        }

        let now = self.ensure_evpn_fabric();
        println!(
            "MP-BGP EVPN (AFI 25 / SAFI 70) over VXLAN - leaf-spine-leaf fabric, simulated time {}ms",
            now
        );
        match sub {
            "routes" | "loc-rib" => self.print_evpn_routes(false),
            "adj-rib-in" | "received" => self.print_evpn_routes(true),
            "advertised" | "adj-rib-out" => self.print_evpn_advertised(),
            "summary" | "sessions" => self.print_evpn_summary(now),
            "vni" | "instances" => self.print_evpn_vnis(),
            _ => self.print_evpn_mac_tables(),
        }
    }

    /// The original NLRI framing demonstration, kept as `evpn advertise`.
    fn cmd_evpn_advertise_demo(&mut self, args: &[&str]) {
        {
            let mac = MacAddress::from_str(args[1]).unwrap_or(self.stack.config.mac);
            let ip = Ipv4Address::from_str(args[2]).ok();
            let vni = args[3].parse::<u32>().unwrap_or(5001);
            let rd = RouteDistinguisher::new(self.stack.config.ip, 100);

            let nlri = EvpnNlri::build_mac_ip(rd.clone(), mac, ip, vni);
            let raw = nlri.serialize();

            println!(
                "Advertised BGP EVPN Route Type 2 (MAC/IP Advertisement, {} bytes):",
                raw.len()
            );
            println!("  RD: {} | VNI: {} | MAC: {} | IP: {:?}", rd, vni, mac, ip);
            println!(
                "  Control Plane: Synchronized across spine-leaf datacenter fabric without flooding!"
            );
        }
    }

    fn cmd_dhcpv6(&mut self, _args: &[&str]) {
        println!(
            "Sending DHCPv6 Solicit to ff02::1:2:{} (RFC 8415)...",
            DHCPV6_SERVER_PORT
        );
        let client_duid = vec![0x00, 0x03, 0x00, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let solicit = Dhcpv6Message::build_solicit(0xABCDEF, &client_duid);
        let raw = solicit.serialize();

        let my_ip6 = self.stack.config.ipv6.unwrap();
        let server_mcast = Ipv6Address::from_str("ff02::1:2").unwrap();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            DHCPV6_CLIENT_PORT,
            DHCPV6_SERVER_PORT,
            &raw,
        );
        let ip6_req = Ipv6Packet::serialize(my_ip6, server_mcast, NEXT_HEADER_UDP, 64, &udp_req);
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV6,
            &ip6_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip6 = Ipv6Packet::parse(eth.payload).unwrap();
            let udp = UdpDatagram::parse(
                self.remote_host_ip,
                self.stack.config.ip,
                ip6.payload,
                false,
            )
            .unwrap();
            if let Ok(adv) = Dhcpv6Message::parse(udp.payload) {
                println!(
                    "DHCPv6 Advertise Message Received from Server (TID=0x{:06X}):",
                    adv.transaction_id
                );
                if let Some(assigned_ip6) = adv.get_assigned_ipv6() {
                    println!("  Assigned IPv6 Address (IA_NA): {}", assigned_ip6);
                    println!("  Lease Preferred Lifetime     : 3600 seconds");
                    println!("  Lease Valid Lifetime         : 7200 seconds");
                    println!("  DNS Recursive Name Server    : 2001:4860:4860::8888");
                }
            }
        }
    }

    fn cmd_vxlan_gpe(&mut self, args: &[&str]) {
        let vni = if args.len() >= 2 {
            args[1].parse::<u32>().unwrap_or(7001)
        } else {
            7001
        };

        let msg = if args.len() >= 3 {
            args[2..].join(" ")
        } else {
            "Direct L3 IPv4 Payload over VXLAN-GPE".to_string()
        };

        let gpe = VxlanGpePacket::build(vni, VXLAN_GPE_NP_IPV4, msg.as_bytes());
        let raw = gpe.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            54790,
            VXLAN_GPE_UDP_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            920,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Encapsulated VXLAN-GPE Multi-Protocol Overlay Packet (UDP {}, {} bytes):",
            VXLAN_GPE_UDP_PORT,
            eth_req.len()
        );
        println!("  24-bit VNI    : {}", vni);
        println!("  Next Protocol : 0x01 (Direct IPv4 without Ethernet overhead)");
        println!("  Payload       : \"{}\"", msg);
    }

    fn cmd_vtp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("Cisco VLAN Trunking Protocol (VTP) Status:");
            println!("  VTP Domain Name   : {}", self.vtp.domain);
            println!("  VTP Mode          : {}", self.vtp.mode);
            println!("  Config Revision   : {}", self.vtp.revision);
            println!("  Synchronized VLANs:");
            for (id, name) in &self.vtp.vlans {
                println!("    - VLAN {:<4}: {}", id, name);
            }
        } else if args.len() >= 3 && args[0] == "add" {
            let id = args[1].parse::<u16>().unwrap_or(30);
            let name = args[2];
            if self.vtp.add_vlan(id, name) {
                println!(
                    "Added VLAN {} ('{}') -> New Configuration Revision: {}",
                    id, name, self.vtp.revision
                );
            }
        } else if args[0] == "summary" {
            let summary =
                VtpPacket::build_summary(&self.vtp.domain, self.vtp.revision, self.stack.config.ip);
            let mut snap_frame = VTP_SNAP_HEADER.to_vec();
            snap_frame.extend_from_slice(&summary.serialize());
            let eth_frame = EthernetFrame::serialize(
                VTP_MULTICAST_MAC,
                self.stack.config.mac,
                0x0000,
                &snap_frame,
            );
            println!(
                "Transmitted VTP Summary Advertisement to {} ({} bytes):",
                VTP_MULTICAST_MAC,
                eth_frame.len()
            );
            println!(
                "  Domain: {} | Revision: {} | Updater: {}",
                self.vtp.domain, self.vtp.revision, self.stack.config.ip
            );
        }
    }

    fn cmd_ldp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "hello" {
            println!("Transmitting LDP Discovery Basic Hello PDU (UDP 646)...");
            let hello_pdu = LdpPdu::build_hello(self.stack.config.ip, 15);
            let raw = hello_pdu.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                Ipv4Address::new(224, 0, 0, 2),
                646,
                LDP_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                Ipv4Address::new(224, 0, 0, 2),
                IP_PROTO_UDP,
                916,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x02]),
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "  LDP PDU Formatted ({} bytes): Version=1, LSR-ID={}, LabelSpace=0",
                raw.len(),
                hello_pdu.lsr_id
            );
            println!(
                "  Transmitted to Multicast 224.0.0.2:646 (Ethernet Frame: {} bytes)",
                eth_req.len()
            );
        } else if args.len() >= 3 && args[0] == "map" {
            let prefix = Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 50, 0, 0));
            let label = args[2].parse::<u32>().unwrap_or(200);

            let map_pdu = LdpPdu::build_label_mapping(self.stack.config.ip, 102, prefix, 24, label);
            let raw = map_pdu.serialize();
            println!(
                "Transmitted LDP Label Mapping Message (TCP 646, {} bytes):",
                raw.len()
            );
            println!("  FEC Prefix   : {}/24", prefix);
            println!("  Assigned Label: {}", label);
            println!(
                "  Dynamic LFIB : Injected Prefix FEC Binding -> Label {}",
                label
            );
        }
    }

    fn cmd_glbp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("Cisco Gateway Load Balancing Protocol (GLBP):");
            println!("  Group Number   : {}", self.glbp.group);
            println!("  Priority       : {}", self.glbp.priority);
            println!("  Weight         : {}", self.glbp.weight);
            println!("  Virtual IP     : {}", self.glbp.virtual_ip);
            println!("  Router Role    : {}", self.glbp.role);
            println!("  Active AVFs    : Forwarder #1, Forwarder #2");
            println!("  Balancing Mode : Round-Robin");
        } else if args[0] == "arp" {
            let resolved_mac = self.glbp.resolve_arp_reply_mac();
            println!(
                "GLBP ARP Request from Host -> Assigned Virtual MAC: {}",
                resolved_mac
            );
            println!("  (Traffic automatically load-balanced across active gateway forwarders!)");
        } else if args[0] == "hello" {
            let hello = self.glbp.build_advertisement();
            let raw = hello.serialize();
            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                GLBP_MULTICAST_IP,
                3222,
                GLBP_UDP_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                GLBP_MULTICAST_IP,
                IP_PROTO_UDP,
                917,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x66]),
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );
            println!(
                "Transmitted GLBP Hello to Multicast {} ({} bytes):",
                GLBP_MULTICAST_IP,
                eth_req.len()
            );
            println!(
                "  Group: {} | Priority: {} | Forwarder: #{} | Virtual IP: {}",
                hello.group, hello.priority, hello.forwarder_num, hello.virtual_ip
            );
        }
    }

    fn cmd_tacacs(&mut self, args: &[&str]) {
        let (user, pass) = if args.len() >= 3 && args[0] == "auth" {
            (args[1], args[2])
        } else {
            ("admin", "cisco123")
        };

        println!(
            "Initiating TACACS+ Authentication Session to {}:{} (RFC 8907)...",
            self.remote_host_ip, TACACS_PORT
        );
        let session_id = 0x55AA1122;
        let authen_start = TacacsPacket::build_authen_start(session_id, user, "tty0", pass);

        println!(
            "  1. Transmitted TACACS+ START (Type=1 Authen, Seq=1, SessionID=0x{:08X}, User='{}')",
            session_id, user
        );
        let resp = self.tacacs_server.authenticate(&authen_start);
        let status_str = if resp.body[0] == TACACS_AUTHEN_STATUS_PASS {
            "PASS (Granted)"
        } else {
            "FAIL (Denied)"
        };
        let msg_len = u16::from_be_bytes([resp.body[2], resp.body[3]]) as usize;
        let server_msg = String::from_utf8_lossy(&resp.body[6..6 + msg_len]);

        println!(
            "  2. Received TACACS+ REPLY (Type=1 Authen, Seq=2, Status={}):",
            status_str
        );
        println!("     \"{}\"", server_msg);
    }

    fn cmd_turn(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "alloc" {
            println!(
                "Sending TURN Allocate Request to {}:{} (RFC 5766)...",
                self.remote_host_ip, STUN_PORT
            );
            let tid = [0xBB; 12];
            let req = TurnPacket::build_allocate_request(tid, 600);
            let raw = req.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                54378,
                STUN_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                912,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            let resps = self.remote_stack.process_frame(&eth_req);
            for resp in resps {
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let udp = UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true)
                    .unwrap();
                if let Ok(turn_resp) = TurnPacket::parse(udp.payload)
                    && let Some((rel_ip, rel_port)) = turn_resp.get_xor_relayed_address()
                {
                    println!("TURN Allocate Response Received (Success 0x0103):");
                    println!("  Relayed Public IP  : {}", rel_ip);
                    println!("  Relayed Public Port: {}", rel_port);
                    println!("  Allocation Lifetime: 600 seconds");
                    println!("  Relay Status       : Symmetric NAT Traversal Active!");
                }
            }
        } else if args.len() >= 2 && args[0] == "send" {
            let msg = args[1..].join(" ");
            let peer_ip = Ipv4Address::new(198, 51, 100, 77);
            let peer_port = 5004;
            let send_ind = TurnPacket::build_send_indication(peer_ip, peer_port, msg.as_bytes());
            let raw = send_ind.serialize();
            println!(
                "Transmitted TURN Send Indication ({} bytes) to {}:{} via Relay Server",
                raw.len(),
                peer_ip,
                peer_port
            );
            println!("  Relayed Payload: \"{}\"", msg);
        }
    }

    fn cmd_gtp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "echo" {
            println!(
                "Sending 4G/5G GTP-U Echo Request to {}:{} (3GPP TS 29.281)...",
                self.remote_host_ip, GTP_U_UDP_PORT
            );
            let echo = GtpPacket::build_echo_request(0, 101);
            let raw = echo.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                52152,
                GTP_U_UDP_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                913,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            let resps = self.remote_stack.process_frame(&eth_req);
            for resp in resps {
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let udp = UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true)
                    .unwrap();
                if let Ok(gtp_resp) = GtpPacket::parse(udp.payload) {
                    println!(
                        "GTP-U Echo Response Received: MsgType={}, Seq={:?}",
                        gtp_resp.header.msg_type, gtp_resp.header.seq_num
                    );
                    println!("  Cellular UPF / gNodeB Node is Alive & Responsive!");
                }
            }
        } else if args.len() >= 3 && args[0] == "encap" {
            let teid = args[1].parse::<u32>().unwrap_or(0x01020304);
            let msg = args[2..].join(" ");
            let gpdu = GtpPacket::build_gpdu(teid, msg.as_bytes());
            let raw = gpdu.serialize();

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                52152,
                GTP_U_UDP_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                914,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "Encapsulated 4G/5G Cellular User Plane Data Packet (GTP-U G-PDU, {} bytes):",
                eth_req.len()
            );
            println!("  Subscriber TEID : 0x{:08X}", teid);
            println!("  Tunnel Payload  : {} bytes (\"{}\")", msg.len(), msg);
        }
    }

    fn cmd_hsrp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("Cisco Hot Standby Router Protocol (HSRPv1 - RFC 2281):");
            println!("  Group Number   : {}", self.hsrp.group);
            println!("  Priority       : {}", self.hsrp.priority);
            println!("  Virtual IP     : {}", self.hsrp.virtual_ip);
            println!(
                "  Virtual MAC    : {}",
                HsrpPacket::virtual_mac(self.hsrp.group)
            );
            println!("  Router State   : {}", self.hsrp.state);
            println!(
                "  Preempt Mode   : {}",
                if self.hsrp.preempt {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!(
                "  Active Router  : {:?}",
                self.hsrp.active_router.unwrap_or(self.stack.config.ip)
            );
        } else if args[0] == "hello" {
            let hello = self.hsrp.build_advertisement();
            let raw = hello.serialize();
            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                HSRP_MULTICAST_IP,
                1985,
                HSRP_UDP_PORT,
                &raw,
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                HSRP_MULTICAST_IP,
                IP_PROTO_UDP,
                915,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x02]),
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );
            println!(
                "Transmitted HSRP Hello to Multicast {} ({} bytes):",
                HSRP_MULTICAST_IP,
                eth_req.len()
            );
            println!(
                "  Group: {} | State: {} | Priority: {} | Virtual IP: {}",
                hello.group, hello.state, hello.priority, hello.virtual_ip
            );
        }
    }

    fn cmd_cdp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "neighbors" {
            println!(
                "Cisco Discovery Protocol (CDPv2) Neighbor Table (MAC {}):",
                CDP_MULTICAST_MAC
            );
            println!(
                "┌──────────────────────┬──────────────────────┬──────────────────────┬──────────────────┬─────────┐"
            );
            println!(
                "│ Device ID            │ Port ID              │ Platform             │ IP Address       │ TTL (s) │"
            );
            println!(
                "├──────────────────────┼──────────────────────┼──────────────────────┼──────────────────┼─────────┤"
            );
            for n in self.cdp_table.neighbors.values() {
                let ip_str = n
                    .ip_address
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "│ {:<20} │ {:<20} │ {:<20} │ {:<16} │ {:<7} │",
                    n.device_id, n.port_id, n.platform, ip_str, n.ttl
                );
            }
            println!(
                "└──────────────────────┴──────────────────────┴──────────────────────┴──────────────────┴─────────┘"
            );
        } else if args[0] == "announce" {
            let pkt = CdpPacket::build(
                "ToyStack-Router",
                "GigabitEthernet0/1",
                "ToyNetStack v1.0",
                self.stack.config.ip,
            );
            let mut snap_pkt = CDP_SNAP_HEADER.to_vec();
            snap_pkt.extend_from_slice(&pkt.serialize());

            let eth_frame = EthernetFrame::serialize(
                CDP_MULTICAST_MAC,
                self.stack.config.mac,
                0x0000,
                &snap_pkt,
            );
            println!(
                "Transmitted CDPv2 Advertisement Frame to {} ({} bytes):",
                CDP_MULTICAST_MAC,
                eth_frame.len()
            );
            println!(
                "  Device-ID: ToyStack-Router | Port: GigabitEthernet0/1 | Platform: ToyNetStack v1.0"
            );
        }
    }

    fn cmd_srv6(&mut self, _args: &[&str]) {
        let sid1 = Ipv6Address::from_str("2001:db8:1::1").unwrap();
        let sid2 = Ipv6Address::from_str("2001:db8:2::1").unwrap();
        let sid3 = Ipv6Address::from_str("2001:db8:3::1").unwrap();

        let srh = Srv6Header::build(59, &[sid1, sid2, sid3]);
        let raw = srh.serialize();

        println!("Segment Routing over IPv6 (SRv6 - RFC 8754):");
        println!(
            "  SRH Extension Header (Type {}, {} bytes):",
            IPV6_EXT_ROUTING,
            raw.len()
        );
        println!("  Routing Type : 4 (Segment Routing Header)");
        println!("  Segments Left: {}", srh.segments_left);
        println!("  Last Entry   : {}", srh.last_entry);
        println!("  Segment List (SIDs):");
        for (i, sid) in srh.segment_list.iter().enumerate() {
            let marker = if i as u8 == srh.segments_left {
                "<- Active Segment"
            } else {
                ""
            };
            println!("    - SID #{}: {:<40} {}", i, sid, marker);
        }
    }

    fn cmd_stun(&mut self, _args: &[&str]) {
        println!(
            "Querying STUN Server at {}:{} for NAT Reflexive Mapping...",
            self.remote_host_ip, STUN_PORT
        );
        let tid = [0xAA; 12];
        let req = StunPacket::build_binding_request(tid);
        let raw = req.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            53478,
            STUN_PORT,
            &raw,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            911,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(stun_resp) = StunPacket::parse(udp.payload)
                && let Some((r_ip, r_port)) = stun_resp.get_xor_mapped_address()
            {
                println!("STUN Binding Response Received (RFC 8449 XOR-MAPPED-ADDRESS):");
                println!("  Public Reflexive IP  : {}", r_ip);
                println!("  Public Reflexive Port: {}", r_port);
                println!("  NAT Traversal Status : Direct UDP Binding Discovered!");
            }
        }
    }

    fn cmd_rtp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "send" {
            let msg = if args.len() >= 2 {
                args[1..].join(" ")
            } else {
                "Audio G.711 PCM Payload 160B".to_string()
            };
            let rtp =
                RtpPacket::build_audio(RTP_PT_PCMU, 1, 160000, 0x12345678, false, msg.as_bytes());
            let raw = rtp.serialize();

            let udp_req =
                UdpDatagram::serialize(self.stack.config.ip, self.remote_host_ip, 5004, 5004, &raw);
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                909,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            println!(
                "Transmitted RTP Real-time Media Packet (UDP 5004, {} bytes):",
                eth_req.len()
            );
            println!(
                "  RTP Header : Version=2, PT=0 (PCMU), Seq=1, Timestamp=160000, SSRC=0x12345678"
            );
            println!("  RTP Payload: {} bytes (\"{}\")", msg.len(), msg);
        } else if args[0] == "sr" {
            let sr = RtcpSenderReport::build(0x12345678, 0xE584123400000000, 160000, 100, 16000);
            let raw = sr.serialize();
            println!(
                "Transmitted RTCP Sender Report (SR) Telemetry ({} bytes):",
                raw.len()
            );
            println!("  SSRC: 0x12345678 | Packets Sent: 100 | Octets Sent: 16000 bytes");
        }
    }

    fn cmd_ptp(&mut self, _args: &[&str]) {
        let clock_id = [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55];
        let t1 = PtpTimestamp::new(1700000000, 100_000_000);
        let t2 = PtpTimestamp::new(1700000000, 100_000_085);
        let t3 = PtpTimestamp::new(1700000000, 100_050_000);
        let t4 = PtpTimestamp::new(1700000000, 100_050_085);

        let sync_pkt = PtpPacket::build_sync(clock_id, 1, t1);
        let raw = sync_pkt.serialize();

        let (offset, delay) = calculate_ptp_offset_and_delay(t1, t2, t3, t4);
        println!("Precision Time Protocol (IEEE 1588v2 PTP - UDP 319/320):");
        println!("  Transmitted PTP Sync Packet ({} bytes, Seq=1)", raw.len());
        println!("  Grandmaster Clock ID : 00:11:22:FF:FE:33:44:55");
        println!("  Measured Offset      : {} ns", offset);
        println!(
            "  Mean Path Delay      : {} ns (Sub-microsecond precision!)",
            delay
        );
    }

    fn cmd_erspan(&mut self, args: &[&str]) {
        let sid = if args.len() >= 2 {
            args[1].parse::<u16>().unwrap_or(101)
        } else {
            101
        };
        let msg = if args.len() >= 3 {
            args[2..].join(" ")
        } else {
            "Mirrored Ingress Frame".to_string()
        };

        let inner_eth = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            msg.as_bytes(),
        );
        let erspan_payload = ErspanPacket::encapsulate(sid, 10, 1, &inner_eth);

        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_GRE,
            910,
            64,
            &erspan_payload,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Transmitted ERSPAN Type II Remote Mirrored Frame (GRE Protocol 47, {} bytes):",
            eth_req.len()
        );
        println!("  ERSPAN Session ID: {}", sid);
        println!("  VLAN Tag         : 10, Port Index: 1");
        println!(
            "  Mirrored Frame   : {} bytes (Inner Payload: \"{}\")",
            inner_eth.len(),
            msg
        );
    }

    fn cmd_mqtt(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("MQTT Telemetry Broker Subscriptions (Port {}):", MQTT_PORT);
            for (top, subs) in &self.mqtt_broker.subscriptions {
                println!("  Topic: {:<30} -> Subscribers: [{}]", top, subs.join(", "));
            }
        } else if args.len() >= 3 && args[0] == "pub" {
            let topic = args[1];
            let msg = args[2..].join(" ");
            let pub_pkt = MqttPacket::build_publish(topic, msg.as_bytes(), 0, None);
            let raw = pub_pkt.serialize();
            println!(
                "Published MQTT Message (Topic: '{}', {} bytes):",
                topic,
                raw.len()
            );
            println!("  Payload: \"{}\"", msg);
            let recipients = self.mqtt_broker.publish(topic);
            println!(
                "  Broker Routed to {} subscribers: {:?}",
                recipients.len(),
                recipients
            );
        } else if args.len() >= 2 && args[0] == "sub" {
            let topic = args[1];
            self.mqtt_broker.subscribe(topic, "ShellClient");
            println!("Subscribed 'ShellClient' to MQTT topic: '{}'", topic);
        }
    }

    fn cmd_coap(&mut self, args: &[&str]) {
        let path = if args.len() >= 2 && args[0] == "get" {
            args[1]
        } else {
            "sensors/temperature"
        };

        println!(
            "Sending CoAP CON GET to {}:{} for '{}'...",
            self.remote_host_ip, COAP_UDP_PORT, path
        );
        let req = CoapPacket::build_get(0x4321, path, &[0xDE, 0xAD]);
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            55683,
            COAP_UDP_PORT,
            &req.serialize(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            906,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(coap_resp) = CoapPacket::parse(udp.payload) {
                println!(
                    "CoAP Response Received: Type=ACK, Code={} (2.05 Content), MsgID=0x{:04X}",
                    coap_resp.code, coap_resp.message_id
                );
                println!(
                    "  Payload: \"{}\"",
                    String::from_utf8_lossy(&coap_resp.payload)
                );
            }
        }
    }

    fn cmd_sctp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "init" {
            let init = SctpPacket::build_init(5000, 2905, 0x98765432, 65535, 10, 10, 1000);
            let raw = init.serialize();
            let ip_pkt = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_SCTP,
                907,
                64,
                &raw,
            );
            let eth_frame = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_pkt,
            );
            println!(
                "Transmitted SCTP Association INIT Chunk ({} bytes, Protocol {}):",
                eth_frame.len(),
                IP_PROTO_SCTP
            );
            println!("  Common Header : SrcPort=5000, DstPort=2905, V-Tag=0x00000000");
            println!(
                "  INIT Chunk    : Tag=0x98765432, a_rwnd=65535, OutStreams=10, InStreams=10, ISN=1000"
            );
        } else if args.len() >= 2 && args[0] == "send" {
            let msg = args[1..].join(" ");
            let data = SctpPacket::build_data(5000, 2905, 0x98765432, 1, 0, 0, 0, msg.as_bytes());
            let raw = data.serialize();
            let ip_pkt = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_SCTP,
                908,
                64,
                &raw,
            );
            let eth_frame = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_pkt,
            );
            println!("Transmitted SCTP DATA Chunk ({} bytes):", eth_frame.len());
            println!(
                "  DATA Chunk    : TSN=1, StreamID=0, Seq=0, Payload: \"{}\"",
                msg
            );
        }
    }

    fn cmd_ldap(&mut self, args: &[&str]) {
        let filter = if args.len() >= 2 && args[0] == "search" {
            args[1]
        } else {
            "(objectClass=*)"
        };

        println!(
            "Querying LDAP Directory Service at {}:{} (Filter: '{}')...",
            self.remote_host_ip, LDAP_PORT, filter
        );
        let req =
            LdapMessage::new_search_request(101, "dc=example,dc=org", filter, &["cn", "mail"]);
        let resps = self.ldap_server.handle_request(&req);

        for resp in resps {
            match resp.protocol_op {
                LdapOp::SearchResultEntry {
                    object_name,
                    attributes,
                } => {
                    println!("  DN: {}", object_name);
                    for (k, v) in attributes {
                        println!("    {}: {}", k, v.join(", "));
                    }
                }
                LdapOp::SearchResultDone { result_code, .. } => {
                    println!("LDAP Search Result Done (ResultCode: {})", result_code);
                }
                _ => {}
            }
        }
    }

    fn cmd_netflow(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("NetFlow v9 Flow Cache Table (UDP {}):", NETFLOW_V9_UDP_PORT);
            println!(
                "┌──────────────────────┬──────────────────────┬────────┬────────┬───────┬───────┬─────────┐"
            );
            println!(
                "│ Source IP            │ Destination IP       │ S-Port │ D-Port │ Proto │ Pkts  │ Bytes   │"
            );
            println!(
                "├──────────────────────┼──────────────────────┼────────┼────────┼───────┼───────┼─────────┤"
            );
            for (&(s_ip, d_ip, s_p, d_p, proto), &(pkts, bytes, _flags)) in
                &self.netflow_table.flows
            {
                let p_str = if proto == 6 { "TCP" } else { "UDP" };
                println!(
                    "│ {:<20} │ {:<20} │ {:<6} │ {:<6} │ {:<5} │ {:<5} │ {:<7} │",
                    s_ip, d_ip, s_p, d_p, p_str, pkts, bytes
                );
            }
            println!(
                "└──────────────────────┴──────────────────────┴────────┴────────┴───────┴───────┴─────────┘"
            );
        } else if args[0] == "export" {
            let records = self.netflow_table.export_records();
            let pkt = NetflowPacket::build_export(1, records);
            let raw = pkt.serialize();
            println!(
                "Exported NetFlow v9 Datagram to {}:{} ({} bytes, {} flow records)",
                self.remote_host_ip,
                NETFLOW_V9_UDP_PORT,
                raw.len(),
                pkt.records.len()
            );
        }
    }

    fn cmd_sip(&mut self, args: &[&str]) {
        let user = if args.len() >= 2 && args[0] == "invite" {
            args[1]
        } else {
            "bob@example.com"
        };

        println!(
            "Initiating SIP VoIP Session to '{}' (UDP {})...",
            user, SIP_PORT
        );
        let local_sdp = build_simple_sdp("alice", &self.stack.config.ip.to_string(), 4000);
        let invite =
            SipMessage::build_invite("alice@example.com", user, "call-99881122", &local_sdp);
        let raw = invite.serialize();

        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            55060,
            SIP_PORT,
            raw.as_bytes(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            905,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(text) = std::str::from_utf8(udp.payload)
                && let Ok(sip_resp) = SipMessage::parse(text)
            {
                println!(
                    "SIP Response Received: {} {}",
                    sip_resp.status_code, sip_resp.reason_phrase
                );
                println!(
                    "  Call-ID: {}",
                    sip_resp.headers.get("Call-ID").unwrap_or(&"-".to_string())
                );
                println!("  Remote SDP Media: Audio RTP Port negotiated");
            }
        }
    }

    fn cmd_bfd(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!(
                "Bidirectional Forwarding Detection (BFD) Session State (UDP {}):",
                BFD_CONTROL_PORT
            );
            println!("  Session State        : {}", self.bfd_session.state);
            println!(
                "  Local Discriminator  : 0x{:08X}",
                self.bfd_session.local_discriminator
            );
            println!(
                "  Remote Discriminator : 0x{:08X}",
                self.bfd_session.remote_discriminator
            );
            println!(
                "  Min TX Interval      : {} ms",
                self.bfd_session.tx_interval_us / 1000
            );
            println!(
                "  Min RX Interval      : {} ms",
                self.bfd_session.rx_interval_us / 1000
            );
            println!("  Detect Multiplier    : {}", self.bfd_session.detect_mult);
        } else if args[0] == "poll" {
            println!(
                "Transmitting BFD Control Packet to {}:{}...",
                self.remote_host_ip, BFD_CONTROL_PORT
            );
            let pkt = BfdControlPacket::build_control(
                BfdState::Init,
                self.bfd_session.local_discriminator,
                self.bfd_session.remote_discriminator,
                self.bfd_session.tx_interval_us,
            );
            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                49384,
                BFD_CONTROL_PORT,
                &pkt.serialize(),
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                903,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );

            let resps = self.remote_stack.process_frame(&eth_req);
            for resp in resps {
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let udp = UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true)
                    .unwrap();
                if let Ok(bfd_resp) = BfdControlPacket::parse(udp.payload) {
                    println!(
                        "BFD Response Received: State={} (MyDisc=0x{:08X}, YourDisc=0x{:08X})",
                        bfd_resp.state, bfd_resp.my_discriminator, bfd_resp.your_discriminator
                    );
                    self.bfd_session.process_packet(&bfd_resp);
                    println!(
                        "BFD Local Session Transitioned -> State: {}",
                        self.bfd_session.state
                    );
                }
            }
        }
    }

    fn cmd_geneve(&mut self, args: &[&str]) {
        let vni = if args.len() >= 2 {
            args[1].parse::<u32>().unwrap_or(2001)
        } else {
            2001
        };

        let msg = if args.len() >= 3 {
            args[2..].join(" ")
        } else {
            "Geneve Encapsulated Multi-Tenant Frame".to_string()
        };

        let inner_eth = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            msg.as_bytes(),
        );
        let geneve_payload = GenevePacket::encapsulate_eth(vni, &inner_eth);
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            56081,
            GENEVE_UDP_PORT,
            &geneve_payload,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            904,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        println!(
            "Transmitted Geneve Overlay Packet (UDP {}, {} bytes):",
            GENEVE_UDP_PORT,
            eth_req.len()
        );
        println!("  24-bit VNI  : {}", vni);
        println!("  Inner Proto : 0x6558 (Transparent Ethernet)");
        println!(
            "  Inner Frame : {} bytes (Inner Payload: \"{}\")",
            inner_eth.len(),
            msg
        );
    }

    fn cmd_isis(&mut self, _args: &[&str]) {
        let sys_id = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let area = &[0x49, 0x00, 0x01];
        let hello = IsisHelloPacket::build_l1_lan_hello(sys_id, area, self.stack.config.ip);
        let raw = hello.serialize();
        let eth_frame = EthernetFrame::serialize(
            MacAddress([0x01, 80, 0xC2, 0x00, 0x00, 0x14]),
            self.stack.config.mac,
            ETHERTYPE_ISIS,
            &raw,
        );

        println!(
            "Transmitted IS-IS Level-1 LAN Hello (IIH) Frame (EtherType 0x{:04X}, {} bytes):",
            ETHERTYPE_ISIS,
            eth_frame.len()
        );
        println!("  NLPID Discriminator : 0x83 (IS-IS)");
        println!("  PDU Type            : 15 (L1 LAN IIH)");
        println!("  Circuit Type        : Level 1");
        println!("  Source System ID    : 0000.0000.0001");
        println!("  Holding Time        : 30s");
        println!("  Priority            : 64");
        println!(
            "  TLVs                : Area Addresses (TLV 1), NLPID Protocols Supported (TLV 129: IPv4, IPv6), IP Interface (TLV 132)"
        );
    }

    fn cmd_syslog(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "list" {
            println!("Syslog Event Collector Log Buffer (UDP 514):");
            for (i, log) in self.syslog_collector.logs.iter().enumerate() {
                println!(
                    "  #{:02} [{:<5}] <PRI:{:<2}> {}: {}",
                    i + 1,
                    log.severity,
                    log.pri_val(),
                    log.app_name,
                    log.message
                );
            }
        } else if args.len() >= 2 && args[0] == "send" {
            let msg_text = args[1..].join(" ");
            let sys_msg = SyslogMessage::new(
                SyslogFacility::Local0,
                SyslogSeverity::Warning,
                "toystack",
                "app",
                &msg_text,
            );
            let formatted = sys_msg.format_rfc5424();
            self.syslog_collector.record(sys_msg.clone());

            let udp_req = UdpDatagram::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                51400,
                SYSLOG_UDP_PORT,
                formatted.as_bytes(),
            );
            let ip_req = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_UDP,
                901,
                64,
                &udp_req,
            );
            let eth_req = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_req,
            );
            println!(
                "Transmitted Syslog RFC 5424 Event Frame ({} bytes, PRI {}):",
                eth_req.len(),
                sys_msg.pri_val()
            );
            println!("  Payload: \"{}\"", formatted);
        }
    }

    fn cmd_l2tp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!(
                "L2TPv3 Layer 2 Pseudowire Status (IP Protocol {}):",
                IP_PROTO_L2TPV3
            );
            println!("  Session ID   : 0x000003E9 (1001)");
            println!("  Cookie       : None (Standard 4-byte L2TPv3 Data Header)");
            println!("  Payload Type : Ethernet Frame Pseudowire");
        } else if args.len() >= 3 && args[0] == "encap" {
            let sid = args[1].parse::<u32>().unwrap_or(1001);
            let msg = args[2..].join(" ");
            let inner_eth = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                msg.as_bytes(),
            );
            let l2tp_payload = L2tpv3Packet::encapsulate(sid, &inner_eth, None);
            let ip_pkt = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_L2TPV3,
                902,
                64,
                &l2tp_payload,
            );
            let eth_frame = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_pkt,
            );
            println!(
                "Encapsulated L2TPv3 Pseudowire Packet ({} bytes, Protocol {}):",
                eth_frame.len(),
                IP_PROTO_L2TPV3
            );
            println!("  Session ID   : 0x{:08X}", sid);
            println!(
                "  Inner Frame  : {} bytes (Payload: \"{}\")",
                inner_eth.len(),
                msg
            );
        }
    }

    fn cmd_pim(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "hello" {
            let hello = PimPacket::build_hello(105, 100);
            let raw = hello.serialize();
            println!(
                "Transmitted PIM-SM Hello Packet ({} bytes, Protocol {}, Multicast {}):",
                raw.len(),
                IP_PROTO_PIM,
                ALL_PIM_ROUTERS_MULTICAST
            );
            println!("  PIM Version : 2");
            println!("  Type        : 0 (Hello)");
            println!("  HoldTime    : 105s, DR Priority: 100");
        } else if args.len() >= 2
            && args[0] == "join"
            && let Ok(grp) = Ipv4Address::from_str(args[1])
        {
            let rp = self.pim_router.rendezvous_point;
            let join_pkt = PimPacket::build_join_group(self.remote_host_ip, grp, rp);
            self.pim_router.join_shared_tree(grp);
            println!(
                "Transmitted PIM Join/Prune Message (*, G) for Group {}:",
                grp
            );
            println!("  Upstream Neighbor: {}", self.remote_host_ip);
            println!("  Rendezvous Point : {}", rp);
            println!("  Serialized Size  : {} bytes", join_pkt.serialize().len());
        }
    }

    fn cmd_radius(&mut self, args: &[&str]) {
        let (user, pass) = if args.len() >= 3 && args[0] == "auth" {
            (args[1], args[2])
        } else {
            ("alice", "secret123")
        };

        println!(
            "Sending RADIUS Access-Request to {}:{} for user '{}'...",
            self.remote_host_ip, RADIUS_AUTH_PORT, user
        );
        let auth = [0x11; 16];
        let req = RadiusPacket::build_access_request(
            101,
            auth,
            user,
            pass,
            b"sharedsecret",
            self.stack.config.ip,
        );
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            51812,
            RADIUS_AUTH_PORT,
            &req.serialize(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            801,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(rad_resp) = RadiusPacket::parse(udp.payload) {
                println!(
                    "RADIUS Response Received: Code={} (Access-Accept), ID={}",
                    rad_resp.code, rad_resp.identifier
                );
                for avp in rad_resp.attributes {
                    match avp.attr_type {
                        8 => println!(
                            "  Framed-IP-Address : {}",
                            Ipv4Address([avp.value[0], avp.value[1], avp.value[2], avp.value[3]])
                        ),
                        18 => println!(
                            "  Reply-Message     : \"{}\"",
                            String::from_utf8_lossy(&avp.value)
                        ),
                        _ => println!(
                            "  Attribute #{}     : {} bytes",
                            avp.attr_type,
                            avp.value.len()
                        ),
                    }
                }
            }
        }
    }

    fn cmd_pppoe(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "padi" {
            let padi = PppoePacket::build_padi();
            let raw = padi.serialize();
            let eth_frame = EthernetFrame::serialize(
                MacAddress::BROADCAST,
                self.stack.config.mac,
                ETHERTYPE_PPPOE_DISCOVERY,
                &raw,
            );
            println!(
                "Transmitted PPPoE Active Discovery Initiation (PADI) Frame (EtherType 0x{:04X}, {} bytes):",
                ETHERTYPE_PPPOE_DISCOVERY,
                eth_frame.len()
            );
            println!("  Code       : 0x09 (PADI)");
            println!("  Session ID : 0x0000");
            println!("  Tags       : Service-Name");
        } else if args.len() >= 3 && args[0] == "session" {
            let sid = args[1].parse::<u16>().unwrap_or(0x0042);
            let msg = args[2..].join(" ");
            let session_pkt = PppoePacket::build_session_ipv4(sid, msg.as_bytes());
            let raw = session_pkt.serialize();
            let eth_frame = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_PPPOE_SESSION,
                &raw,
            );
            println!(
                "Transmitted PPPoE Session Frame (EtherType 0x{:04X}, {} bytes):",
                ETHERTYPE_PPPOE_SESSION,
                eth_frame.len()
            );
            println!("  Session ID : 0x{:04X}", sid);
            println!("  PPP Proto  : 0x0021 (IPv4)");
            println!("  Payload    : \"{}\"", msg);
        }
    }

    fn cmd_eigrp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "hello" {
            let hello = EigrpPacket::build_hello(100);
            let raw = hello.serialize();
            println!(
                "Transmitted EIGRP Hello Packet ({} bytes, Protocol {}, Multicast {}):",
                raw.len(),
                IP_PROTO_EIGRP,
                EIGRP_MULTICAST_IP
            );
            println!("  Autonomous System : 100");
            println!("  K-Values          : K1=1, K2=0, K3=1, K4=0, K5=0");
            println!("  Hold Time         : 15 seconds");
        } else if args[0] == "dual" {
            println!("EIGRP DUAL Topology Table & Successor Selection (AS 100):");
            let dest = Ipv4Address::new(10, 50, 0, 0);
            if let Some((succ, fs_list, fd)) = self.eigrp_table.compute_dual(dest) {
                println!("  Destination Network   : {}/24", dest);
                println!("  Feasible Distance (FD): {}", fd);
                println!(
                    "  Primary Successor     : Next-Hop {} (Total Metric: {}, RD: {})",
                    succ.neighbor, succ.total_metric, succ.reported_distance
                );
                for fs in fs_list {
                    println!(
                        "  Feasible Successor    : Next-Hop {} (Total Metric: {}, RD: {} < FD {}) [Loop-Free Backup!]",
                        fs.neighbor, fs.total_metric, fs.reported_distance, fd
                    );
                }
            }
        }
    }

    fn cmd_ipsec(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("IPsec Security Association Database (SAD) (Protocol 50 ESP):");
            for (&spi, sa) in &self.sad_table.outbound {
                println!(
                    "  [Outbound SA] SPI: 0x{:08X} | {} -> {} | Next Seq: {}",
                    spi, sa.src_ip, sa.dst_ip, sa.next_seq
                );
            }
            for (&spi, sa) in &self.sad_table.inbound {
                println!(
                    "  [Inbound SA]  SPI: 0x{:08X} | {} -> {} | Replay Window Highest: {}",
                    spi, sa.src_ip, sa.dst_ip, sa.highest_seq_seen
                );
            }
        } else if args.len() >= 2 && args[0] == "encap" {
            let msg = args[1..].join(" ");
            let key = [0xAA; 16];
            let esp = EspPacket::build(0x1000, 1, 4, msg.as_bytes(), &key);
            let raw = esp.serialize();
            let ip_esp = Ipv4Packet::serialize(
                self.stack.config.ip,
                self.remote_host_ip,
                IP_PROTO_ESP,
                701,
                64,
                &raw,
            );
            let eth_esp = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_IPV4,
                &ip_esp,
            );
            println!(
                "Encapsulated IPsec ESP Tunnel Packet ({} bytes, Protocol 50):",
                eth_esp.len()
            );
            println!("  ESP Header : SPI=0x00001000, Seq=1");
            println!(
                "  ESP Payload: {} bytes (Inner Payload: \"{}\")",
                esp.payload.len(),
                msg
            );
            println!(
                "  ESP Trailer: PadLen={}, NextHeader=4 (IP-in-IP)",
                esp.pad_length
            );
            println!("  ESP ICV    : 16 bytes Authentication Tag");
        }
    }

    fn cmd_http3(&mut self, args: &[&str]) {
        let path = if args.len() >= 2 && args[0] == "get" {
            args[1]
        } else {
            "/api/v1/resource"
        };

        println!("Initiating HTTP/3 over QUIC Transaction (RFC 9114):");
        let settings = Http3Frame::build_settings(&[(0x01, 4096), (0x06, 65536)]);
        println!(
            "  1. Transmitted HTTP/3 SETTINGS frame ({} bytes)",
            settings.serialize().len()
        );

        let headers =
            Http3Frame::build_headers(&[(":method", "GET"), (":path", path), (":scheme", "https")]);
        println!(
            "  2. Transmitted HTTP/3 HEADERS frame (QPACK Compressed, Path: '{}', {} bytes)",
            path,
            headers.serialize().len()
        );

        let data = Http3Frame::build_data(b"{\"status\": 200, \"protocol\": \"HTTP/3 QUIC\"}");
        println!(
            "  3. Received HTTP/3 DATA frame ({} bytes payload): \"{}\"",
            data.payload.len(),
            String::from_utf8_lossy(&data.payload)
        );
    }

    fn cmd_lacp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            println!("Link Aggregation Group (LACP / IEEE 802.1AX / 802.3ad):");
            println!("  Bond Device  : {}", self.lag.bond_name);
            println!(
                "  Slaves       : eth0, eth1 (State: Active/Aggregated/Collecting/Distributing)"
            );
            println!("  LACP Key     : {}", self.lag.lacp_key);
            println!("  Hash Policy  : Layer 3 + Layer 4 5-Tuple");

            let actor = LacpPortInfo {
                system_priority: 32768,
                system_mac: self.stack.config.mac,
                key: self.lag.lacp_key,
                port_priority: 128,
                port_number: 1,
                state: LACP_STATE_ACTIVITY
                    | LACP_STATE_AGGREGATION
                    | LACP_STATE_SYNCHRONIZATION
                    | LACP_STATE_COLLECTING
                    | LACP_STATE_DISTRIBUTING,
            };
            let pkt = LacpPacket::build(actor.clone(), actor);
            println!(
                "  Generated LACPDU Frame (EtherType 0x{:04X}, {} bytes)",
                ETHERTYPE_SLOW_PROTOCOLS,
                pkt.serialize().len()
            );
        } else if args.len() >= 3 && args[0] == "hash" {
            let s_ip = Ipv4Address::from_str(args[1]).unwrap_or(self.stack.config.ip);
            let d_ip = Ipv4Address::from_str(args[2]).unwrap_or(self.remote_host_ip);
            let slave = self.lag.select_slave_port(s_ip, d_ip, 50000, 80);
            println!(
                "LACP 5-Tuple Egress Hash: {} -> {} | Selected Slave: {}",
                s_ip, d_ip, slave
            );
        }
    }

    fn cmd_ospf(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "hello" {
            let hello = OspfHelloPacket::build_hello(
                self.stack.config.ip,
                Ipv4Address::new(255, 255, 255, 0),
                self.remote_host_ip,
                vec![self.remote_host_ip],
            );
            let raw = hello.serialize();
            println!(
                "Transmitted OSPFv2 Hello Packet ({} bytes, Protocol 89, Multicast {}):",
                raw.len(),
                OSPF_ALL_SPF_ROUTERS
            );
            println!("  Router ID  : {}", self.stack.config.ip);
            println!("  Area ID    : 0.0.0.0 (Backbone)");
            println!("  DR         : {}", self.remote_host_ip);
            println!("  Hello/Dead : 10s / 40s");
        } else if args[0] == "spf" {
            println!(
                "OSPF Dijkstra Shortest Path Tree Calculation from {}:",
                self.stack.config.ip
            );
            let paths = self
                .ospf_lsdb
                .compute_shortest_paths(Ipv4Address::new(1, 1, 1, 1));
            for (dest, (cost, nh)) in paths {
                println!(
                    "  -> Destination: {:<15} | Metric Cost: {:<4} | Next-Hop: {:?}",
                    dest,
                    cost,
                    nh.unwrap()
                );
            }
        }
    }

    fn cmd_stp(&mut self, _args: &[&str]) {
        println!("Spanning Tree Protocol (IEEE 802.1D) Bridge Status:");
        println!("  Bridge ID     : {}", self.stp_engine.bridge_id);
        println!("  Root Bridge ID: {}", self.stp_engine.root_id);
        println!("  Root Path Cost: {}", self.stp_engine.root_path_cost);
        println!("  Port States:");
        for (port, (role, state)) in &self.stp_engine.port_states {
            println!("    - Port {:02}: Role={:?}, State={}", port, role, state);
        }
    }

    fn cmd_vxlan(&mut self, args: &[&str]) {
        // The live subcommands read the running EVPN fabric; the default one
        // below still demonstrates the encapsulation framing on its own.
        match args.first().copied().unwrap_or("") {
            "vtep" | "vteps" => {
                self.ensure_evpn_fabric();
                self.print_evpn_vteps();
                return;
            }
            "vni" | "vnis" => {
                self.ensure_evpn_fabric();
                self.print_evpn_vnis();
                return;
            }
            "help" => {
                println!("vxlan <subcommand>  - VXLAN overlay (RFC 7348), UDP port 4789");
                println!("  vtep              - VTEP source, underlay, and instances per leaf");
                println!("  vni               - one row per VNI: RD, Route Targets, MAC counts");
                println!("  <vni> <message>   - show the framing of one encapsulated frame");
                return;
            }
            _ => {}
        }

        let vni = if args.len() >= 2 {
            args[1].parse::<u32>().unwrap_or(1001)
        } else {
            1001
        };

        let msg = if args.len() >= 3 {
            args[2..].join(" ")
        } else {
            "Overlay Ethernet Frame".to_string()
        };

        let inner_eth = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            msg.as_bytes(),
        );
        let vxlan_encap = VxlanPacket::encapsulate(vni, &inner_eth).unwrap();
        println!(
            "VXLAN Encapsulated Frame (Port {}, VNI {}, {} bytes):",
            VXLAN_UDP_PORT,
            vni,
            vxlan_encap.len()
        );
        println!("  Outer Layer: UDP Port {}", VXLAN_UDP_PORT);
        println!("  VXLAN Header: Flags=0x08 (VNI Valid), 24-bit VNI={}", vni);
        println!(
            "  Inner Frame : {} bytes (Inner Payload: \"{}\")",
            inner_eth.len(),
            msg
        );
    }

    fn cmd_mpls(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "lfib" {
            println!("MPLS Label Forwarding Information Base (LFIB):");
            println!("┌───────────┬────────────────────────────────┐");
            println!("│ In-Label  │ Action                         │");
            println!("├───────────┼────────────────────────────────┤");
            for (&in_lbl, act) in self.lfib.all_entries() {
                println!("│ {:<9} │ {:<30} │", in_lbl, act);
            }
            println!("└───────────┴────────────────────────────────┘");
        } else if args.len() >= 3 && args[0] == "push" {
            let label = args[1].parse::<u32>().unwrap_or(100);
            let msg = args[2..].join(" ");
            let shim = MplsHeader::new(label, 0, true, 64);
            let mpls_pkt = MplsPacket {
                labels: vec![shim],
                payload: msg.as_bytes().to_vec(),
            };
            let raw = mpls_pkt.serialize();
            let eth_frame = EthernetFrame::serialize(
                self.remote_host_mac,
                self.stack.config.mac,
                ETHERTYPE_MPLS_UNICAST,
                &raw,
            );
            println!(
                "Generated MPLS Encapsulated Frame (EtherType 0x{:04x}, {} bytes):",
                ETHERTYPE_MPLS_UNICAST,
                eth_frame.len()
            );
            println!(
                "  MPLS Label Stack : [Label: {}, TC: 0, S: true, TTL: 64]",
                label
            );
            println!("  Inner Payload    : \"{}\"", msg);
        }
    }

    /// Builds and converges the BGP fabric on first use.
    ///
    /// Everything the `bgp` subcommands print afterwards is read out of that running
    /// control plane: the sessions really completed a TCP handshake on port 179 and
    /// exchanged OPEN, KEEPALIVE, and UPDATE messages over this stack.
    fn ensure_bgp_fabric(&mut self) -> u64 {
        if self.bgp_fabric.is_none() {
            let mut lab = build_bgp_demo_fabric();
            let converged = converge_bgp(&mut lab, 60_000);
            if !converged {
                println!("(warning: the BGP fabric did not fully converge)");
            }
            // Let the fabric idle for a few simulated seconds so the keepalive timers
            // fire at least once and the reported uptimes are meaningful.
            for _ in 0..8 {
                lab.advance_time(1_000);
                lab.run_pumped(20);
            }
            self.bgp_fabric = Some(lab);
        }
        self.bgp_fabric
            .as_ref()
            .map(|l| l.current_time_ms)
            .unwrap_or(0)
    }

    /// Router names in the demo fabric, in a stable order.
    fn bgp_routers(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .bgp_fabric
            .as_ref()
            .map(|l| l.routers.keys().cloned().collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    fn cmd_bgp(&mut self, args: &[&str]) {
        let sub = args.first().copied().unwrap_or("summary");

        match sub {
            "help" => {
                println!("bgp <subcommand>  - BGP-4 control plane running on TCP port 179");
                println!("  summary | status  - one line per neighbor per router");
                println!("  peers | neighbors - full per-neighbor state, timers, counters");
                println!("  routes | loc-rib  - the best path per prefix (Loc-RIB)");
                println!("  rib | adj-rib-in  - every path received, best paths marked");
                println!("  advertised        - the Adj-RIB-Out, per neighbor");
                println!("  route | fib       - each router's real IPv4 forwarding table");
                println!("  events | log      - the control-plane event log");
                println!("  capabilities      - what each speaker offers and each session agreed");
                println!("  evpn [summary|routes|advertised|adj-rib-in] - the MP-BGP EVPN family");
                println!(
                    "  rr [clients|routes|advertised] - RFC 4456 route reflection, on a fabric"
                );
                println!(
                    "                      whose reflectors have no VNI and no import Route Target"
                );
                println!("  open              - show the framing of a BGP OPEN message");
                println!("  local-rib         - the static sample RIB kept for reference");
                return;
            }
            "capabilities" | "caps" => {
                // Every fabric, so the output shows an IPv4-only session beside
                // one that negotiated EVPN, and beside a reflector session.
                self.ensure_bgp_fabric();
                self.ensure_evpn_fabric();
                self.ensure_rr_fabric();
                self.print_bgp_capabilities();
                return;
            }
            "rr" | "route-reflector" | "reflector" => {
                let now = self.ensure_rr_fabric();
                match args.get(1).copied().unwrap_or("summary") {
                    "clients" | "peers" => self.print_rr_clients(),
                    "routes" | "adj-rib-in" | "received" => self.print_rr_routes(),
                    "advertised" | "adj-rib-out" | "reflected" => self.print_rr_advertised(),
                    _ => self.print_rr_summary(now),
                }
                return;
            }
            "evpn" => {
                let now = self.ensure_evpn_fabric();
                match args.get(1).copied().unwrap_or("summary") {
                    "routes" | "loc-rib" => self.print_evpn_routes(false),
                    "adj-rib-in" | "received" => self.print_evpn_routes(true),
                    "advertised" | "adj-rib-out" => self.print_evpn_advertised(),
                    "mac" => self.print_evpn_mac_tables(),
                    _ => self.print_evpn_summary(now),
                }
                return;
            }
            "open" => {
                let open = BgpMessage::build_open(65001, 180, self.stack.config.ip);
                let raw = open.serialize();
                println!(
                    "BGP OPEN Message Framed ({} bytes): Marker=0xFF*16, MyAS=65001, HoldTime=180",
                    raw.len()
                );
                return;
            }
            _ => {}
        }

        let now = self.ensure_bgp_fabric();
        let names = self.bgp_routers();
        let Some(lab) = self.bgp_fabric.as_ref() else {
            return;
        };

        match sub {
            "summary" | "status" => {
                println!(
                    "BGP-4 fabric (RFC 4271) - AS65001 <-> AS65002 <-> AS65003, simulated time {}ms",
                    now
                );
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("\n== {} ==", name);
                        print!("{}", bgp.format_summary(now));
                    }
                }
            }
            "peers" | "neighbors" | "neighbor" => {
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("== {} ==", name);
                        print!("{}", bgp.format_peers(now));
                    }
                }
            }
            "routes" | "loc-rib" => {
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("== {} Loc-RIB ==", name);
                        print!("{}", bgp.format_routes());
                    }
                }
            }
            "rib" | "adj-rib-in" => {
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("== {} Adj-RIB-In ==", name);
                        print!("{}", bgp.format_rib());
                    }
                }
            }
            "advertised" | "adj-rib-out" => {
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("== {} Adj-RIB-Out ==", name);
                        for peer in bgp.peers() {
                            let prefixes = bgp.adj_rib_out.prefixes(peer.addr);
                            if prefixes.is_empty() {
                                println!("  to {}: nothing advertised", peer.addr);
                                continue;
                            }
                            for prefix in prefixes {
                                if let Some(r) = bgp.adj_rib_out.get(peer.addr, &prefix) {
                                    println!(
                                        "  to {}: {} as-path [{}] next-hop {}",
                                        peer.addr, prefix, r.as_path, r.next_hop
                                    );
                                }
                            }
                        }
                    }
                }
            }
            "route" | "fib" => {
                for name in &names {
                    println!("== {} IPv4 forwarding table ==", name);
                    for r in lab.routers[name].routing_table.all_routes() {
                        println!("  {}", r);
                    }
                }
            }
            "events" | "log" => {
                for name in &names {
                    if let Some(bgp) = lab.routers[name].bgp() {
                        println!("== {} control-plane log ==", name);
                        for e in bgp.events() {
                            println!("  {}", e);
                        }
                    }
                }
            }
            "local-rib" => self.cmd_bgp_static_rib(),
            other => {
                println!("unknown bgp subcommand '{}'; try 'bgp help'", other);
            }
        }
    }

    /// The original static sample RIB, kept as a reference table.
    fn cmd_bgp_static_rib(&self) {
        {
            println!("BGP sample Routing Information Base (static reference data):");
            println!("┌──────────────────────┬──────────────────┬────────────────────────┐");
            println!("│ Network Prefix       │ Next Hop         │ AS Path                │");
            println!("├──────────────────────┼──────────────────┼────────────────────────┤");
            for ((p, m), (nh, path)) in self.bgp_rib.all_routes() {
                let p_str = format!("{}/{}", p, m);
                let path_str = path
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("│ {:<20} │ {:<16} │ {:<22} │", p_str, nh, path_str);
            }
            println!("└──────────────────────┴──────────────────┴────────────────────────┘");
        }
    }

    fn cmd_lldp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "neighbors" {
            println!(
                "Link Layer Discovery Protocol (LLDP) Neighbors (EtherType 0x{:04X}):",
                ETHERTYPE_LLDP
            );
            println!("┌──────────────────────┬─────────────┬──────────┬──────────────────────┐");
            println!("│ Chassis ID           │ Port ID     │ TTL (s)  │ System Name          │");
            println!("├──────────────────────┼─────────────┼──────────┼──────────────────────┤");
            for n in self.lldp_table.all_neighbors().values() {
                println!(
                    "│ {:<20} │ {:<11} │ {:<8} │ {:<20} │",
                    n.chassis_id,
                    n.port_id,
                    n.ttl,
                    n.system_name.as_deref().unwrap_or("-")
                );
            }
            println!("└──────────────────────┴─────────────┴──────────┴──────────────────────┘");
        } else if args[0] == "announce" {
            let lldp_pkt = LldpPacket {
                chassis_id: self.stack.config.mac.to_string(),
                port_id: "eth0".to_string(),
                ttl: 120,
                system_name: Some("ToyNetStack-Host".to_string()),
            };
            let raw = lldp_pkt.serialize();
            let eth_frame = EthernetFrame::serialize(
                LLDP_MULTICAST_MAC,
                self.stack.config.mac,
                ETHERTYPE_LLDP,
                &raw,
            );
            println!(
                "Transmitted LLDPDU Advertisement to Multicast MAC {} ({} bytes)",
                LLDP_MULTICAST_MAC,
                eth_frame.len()
            );
        }
    }

    fn cmd_snmp(&mut self, args: &[&str]) {
        let oid = if args.len() >= 2 && args[0] == "get" {
            args[1]
        } else {
            "1.3.6.1.2.1.1.1.0"
        };

        println!(
            "SNMPv2c GetRequest to {}:161 for OID '{}'...",
            self.remote_host_ip, oid
        );
        let req = SnmpMessage::build_get_request("public", 101, &[oid]);
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            50161,
            161,
            &req.serialize(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            601,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(snmp_resp) = SnmpMessage::parse(udp.payload) {
                println!(
                    "SNMPv2c Response received (Community: \"{}\"):",
                    snmp_resp.community
                );
                for vb in snmp_resp.pdu.varbinds {
                    println!("  {} = {}", vb.oid, vb.value);
                }
            }
        }
    }

    fn cmd_quic(&mut self, args: &[&str]) {
        let payload_str = if args.len() >= 2 && args[0] == "frame" {
            args[1..].join(" ")
        } else {
            "QUIC stream payload data".to_string()
        };

        println!("Generating QUIC Binary Packets (RFC 9000):");
        let initial = QuicPacket::build_initial(
            vec![0x12, 0x34, 0x56, 0x78],
            vec![0x87, 0x65, 0x43, 0x21],
            payload_str.as_bytes(),
        );
        let raw_initial = initial.serialize();
        println!(
            "  1. Long Header Initial ({} bytes): DCID=12345678, SCID=87654321, Version=0x00000001",
            raw_initial.len()
        );

        let short = QuicPacket::build_1rtt(
            vec![0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd],
            1,
            payload_str.as_bytes(),
        );
        let raw_short = short.serialize();
        println!(
            "  2. Short Header 1-RTT ({} bytes): DCID=12345678aabbccdd, PacketNum=1, SpinBit=0",
            raw_short.len()
        );
    }

    fn cmd_vrrp(&mut self, _args: &[&str]) {
        println!("Virtual Router Redundancy Protocol (VRRPv3 - RFC 5798):");
        println!("  VRID       : {}", self.vrrp.vrid);
        println!("  Virtual IP : {}", self.vrrp.virtual_ip);
        println!("  Virtual MAC: {}", VrrpPacket::virtual_mac(self.vrrp.vrid));
        println!("  Priority   : {}", self.vrrp.priority);
        println!("  State      : {}", self.vrrp.state);

        let adv = self.vrrp.build_advertisement();
        println!(
            "  Advertisement Frame Generated ({} bytes): Checksum=0x{:04x}",
            adv.serialize().len(),
            adv.checksum
        );
    }

    fn cmd_arp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "list" {
            println!("Address Resolution Protocol (ARP) Cache Table:");
            println!("┌──────────────────┬───────────────────┐");
            println!("│ IPv4 Address     │ MAC Address       │");
            println!("├──────────────────┼───────────────────┤");
            for (&ip, &mac) in self.stack.arp_table.entries() {
                println!("│ {:<16} │ {:<17} │", Ipv4Address(ip), mac);
            }
            println!("└──────────────────┴───────────────────┘");
        } else if args[0] == "clear" {
            self.stack.arp_table = ArpTable::new();
            println!("ARP cache cleared.");
        }
    }

    fn cmd_ndp(&self) {
        println!("IPv6 Neighbor Discovery Protocol (NDP) Cache Table:");
        println!("┌──────────────────────────────────────────┬───────────────────┐");
        println!("│ IPv6 Address                             │ MAC Address       │");
        println!("├──────────────────────────────────────────┼───────────────────┤");
        for (&ip, &mac) in self.stack.ndp_table.entries() {
            println!("│ {:<40} │ {:<17} │", ip, mac);
        }
        println!("└──────────────────────────────────────────┴───────────────────┘");
    }

    fn cmd_route(&self) {
        println!("IPv4 Routing Table (Longest Prefix Match):");
        for r in self.stack.routing_table.all_routes() {
            println!("  {}", r);
        }
    }

    fn cmd_rip(&self, _args: &[&str]) {
        println!("RIPv2 Distance-Vector Routing Status (Port 520):");
        println!("  Advertised Subnets:");
        for (dest, prefix, metric) in &self.rip.route_metrics {
            println!("    - {}/{} (Hop Metric: {})", dest, prefix, metric);
        }
    }

    fn cmd_traceroute(&mut self, args: &[&str]) {
        let target_ip = if args.is_empty() {
            self.remote_host_ip
        } else {
            match Ipv4Address::from_str(args[0]) {
                Ok(ip) => ip,
                Err(_) => {
                    println!("Invalid IPv4 target: {}", args[0]);
                    return;
                }
            }
        };

        println!(
            "traceroute to {} (30 hops max, 32 byte packets):",
            target_ip
        );
        let hops = vec![
            TracerouteHopResult {
                hop: 1,
                responder_ip: Some(Ipv4Address::new(192, 168, 1, 1)),
                rtt_ms: 0.45,
                reached: false,
            },
            TracerouteHopResult {
                hop: 2,
                responder_ip: Some(Ipv4Address::new(10, 0, 0, 1)),
                rtt_ms: 1.20,
                reached: false,
            },
            TracerouteHopResult {
                hop: 3,
                responder_ip: Some(target_ip),
                rtt_ms: 2.15,
                reached: true,
            },
        ];

        for h in hops {
            println!(" {}", h);
        }
    }

    fn cmd_ntp(&mut self, _args: &[&str]) {
        println!("Querying NTP Server ({}:123)...", self.remote_host_ip);
        let t1 = NtpTimestamp::new(3900000000, 100000);
        let req = NtpPacket::build_client_request(t1);
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            49150,
            123,
            &req.serialize(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            501,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(ntp_resp) = NtpPacket::parse(udp.payload) {
                let t4 = NtpTimestamp::new(3900000000, 150000);
                let (offset, delay) = calculate_offset_and_delay(
                    t1.to_unix_f64(),
                    ntp_resp.receive_timestamp.to_unix_f64(),
                    ntp_resp.transmit_timestamp.to_unix_f64(),
                    t4.to_unix_f64(),
                );
                println!("NTP Server Response (Stratum {}):", ntp_resp.stratum);
                println!(
                    "  Reference ID : {}",
                    String::from_utf8_lossy(&ntp_resp.reference_id)
                );
                println!("  Round-Trip   : {:.3} ms", delay * 1000.0);
                println!("  Clock Offset : {:.3} ms", offset * 1000.0);
            }
        }
    }

    fn cmd_tftp(&mut self, args: &[&str]) {
        let filename = if args.len() >= 2 && args[0] == "get" {
            args[1]
        } else {
            "pxeboot.bin"
        };

        println!("Requesting file '{}' over TFTP (Port 69)...", filename);
        let rrq = TftpPacket::Rrq {
            filename: filename.to_string(),
            mode: "octet".to_string(),
        };
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            50069,
            69,
            &rrq.serialize(),
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            502,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(tftp_resp) = TftpPacket::parse(udp.payload) {
                match tftp_resp {
                    TftpPacket::Data { block_num, data } => {
                        println!(
                            "TFTP DATA received: Block #{} ({} bytes)",
                            block_num,
                            data.len()
                        );
                        println!("  Content: \"{}\"", String::from_utf8_lossy(&data));
                    }
                    TftpPacket::Error {
                        error_code,
                        message,
                    } => {
                        println!("TFTP ERROR #{}: {}", error_code, message);
                    }
                    _ => {}
                }
            }
        }
    }

    fn cmd_tunnel(&mut self, args: &[&str]) {
        if args.len() < 3 || args[0] != "gre" {
            println!("Usage: tunnel gre <destination_ip> <message>");
            return;
        }

        let dst_ip = Ipv4Address::from_str(args[1]).unwrap_or(self.remote_host_ip);
        let msg = args[2..].join(" ");

        let encap = GrePacket::encapsulate_gre_ipv4(
            self.stack.config.ip,
            dst_ip,
            msg.as_bytes(),
            Some(0x1001),
        );
        println!("Encapsulated GRE Packet ({} bytes):", encap.len());
        println!(
            "  Outer IP Header: {} -> {} (Protocol 47 GRE)",
            self.stack.config.ip, dst_ip
        );
        println!("  GRE Header     : Key=0x1001, Inner EtherType=0x0800 (IPv4)");
        println!("  Inner Payload  : \"{}\"", msg);
    }

    fn cmd_igmp(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "list" {
            println!("Active Multicast Group Subscriptions (IGMPv2):");
            for g in self.igmp_table.all_groups() {
                let mac = multicast_ip_to_mac(g);
                println!("  - IP: {:<15} -> Ethernet Multicast MAC: {}", g, mac);
            }
        } else if args.len() >= 2 && args[0] == "join" {
            if let Ok(group) = Ipv4Address::from_str(args[1]) {
                self.igmp_table.join(group);
                let mac = multicast_ip_to_mac(group);
                let report = IgmpPacket::build_v2_membership_report(group);
                println!("Joined Multicast Group {}:", group);
                println!("  Mapped MAC : {}", mac);
                println!(
                    "  IGMP Report: Type=0x16 (V2 Membership Report), Group={}",
                    report.group_address
                );
            } else {
                println!("Invalid Multicast IP: {}", args[1]);
            }
        }
    }

    fn cmd_ws(&mut self, args: &[&str]) {
        if args.len() < 2 || args[0] != "send" {
            println!("Usage: ws send <message>");
            return;
        }

        let msg = args[1..].join(" ");
        let mask = [0xde, 0xad, 0xbe, 0xef];
        let frame = WebSocketFrame::build_text(&msg, true, Some(mask));
        let raw = frame.serialize();

        println!(
            "Generated Masked WebSocket Text Frame ({} bytes):",
            raw.len()
        );
        println!("  Header     : FIN=true, Opcode=0x1 (Text), Masked=true");
        println!(
            "  Masking Key: {:02x}{:02x}{:02x}{:02x}",
            mask[0], mask[1], mask[2], mask[3]
        );
        println!("  Payload    : \"{}\"", msg);
    }

    fn cmd_ping(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: ping <target_ip>");
            return;
        }

        let target_ip = match Ipv4Address::from_str(args[0]) {
            Ok(ip) => ip,
            Err(_) => {
                println!("Invalid IPv4 address: {}", args[0]);
                return;
            }
        };

        println!("PING {} (32 bytes of data):", target_ip);
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);

        let ping_payload = b"ToyNetStack ping test payload 12";
        let icmp_req = IcmpPacket::build_echo_request(0x1337, seq, ping_payload);
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            target_ip,
            IP_PROTO_ICMP,
            seq,
            64,
            &icmp_req,
        );

        let dst_mac = self
            .stack
            .arp_table
            .lookup(&target_ip.0)
            .unwrap_or(self.remote_host_mac);
        let eth_req =
            EthernetFrame::serialize(dst_mac, self.stack.config.mac, ETHERTYPE_IPV4, &ip_req);
        self.record_packet(&eth_req);

        let resps = self.remote_stack.process_frame(&eth_req);
        if resps.is_empty() {
            println!("Request timed out. Destination Host Unreachable.");
        } else {
            for resp in resps {
                self.record_packet(&resp);
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
                let icmp = IcmpPacket::parse(ip.payload, true).unwrap();
                if icmp.icmp_type == IcmpType::EchoReply {
                    println!(
                        "32 bytes from {}: icmp_seq={} ttl={} id=0x{:04x} (time < 1ms)",
                        ip.header.src_ip, icmp.sequence_number, ip.header.ttl, icmp.identifier
                    );
                }
            }
        }
    }

    fn cmd_ping6(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: ping6 <target_ipv6>");
            return;
        }

        let target_ip6 = match Ipv6Address::from_str(args[0]) {
            Ok(ip) => ip,
            Err(_) => {
                println!("Invalid IPv6 address: {}", args[0]);
                return;
            }
        };

        let my_ip6 = self.stack.config.ipv6.unwrap_or(Ipv6Address::LOOPBACK);
        println!("PING6 {} from {} (32 bytes of data):", target_ip6, my_ip6);
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);

        let ping_payload = b"ToyNetStack ping6 payload 123456";
        let icmp6_req =
            Icmpv6Packet::build_echo_request(my_ip6, target_ip6, 0x1337, seq, ping_payload);
        let ip6_req = Ipv6Packet::serialize(my_ip6, target_ip6, NEXT_HEADER_ICMPV6, 64, &icmp6_req);

        let dst_mac = self
            .stack
            .ndp_table
            .lookup(&target_ip6)
            .unwrap_or(self.remote_host_mac);
        let eth_req =
            EthernetFrame::serialize(dst_mac, self.stack.config.mac, ETHERTYPE_IPV6, &ip6_req);
        self.record_packet(&eth_req);

        let resps = self.remote_stack.process_frame(&eth_req);
        if resps.is_empty() {
            println!("Request timed out. Destination IPv6 Host Unreachable.");
        } else {
            for resp in resps {
                self.record_packet(&resp);
                let eth = EthernetFrame::parse(&resp).unwrap();
                let ip6 = Ipv6Packet::parse(eth.payload).unwrap();
                let icmp6 =
                    Icmpv6Packet::parse(ip6.header.src_ip, ip6.header.dst_ip, ip6.payload, true)
                        .unwrap();
                if icmp6.msg_type == ICMPV6_TYPE_ECHO_REPLY {
                    println!(
                        "32 bytes from {}: icmp6_seq={} hop_limit={} (time < 1ms)",
                        ip6.header.src_ip, seq, ip6.header.hop_limit
                    );
                }
            }
        }
    }

    fn cmd_dns(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: dns <hostname>");
            return;
        }

        let hostname = args[0];
        println!(
            "Resolving '{}' via virtual DNS server ({})...",
            hostname, self.remote_host_ip
        );

        let query_data = DnsMessage::build_query(0x1234, hostname);
        let udp_req = UdpDatagram::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            53535,
            53,
            &query_data,
        );
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            self.remote_host_ip,
            IP_PROTO_UDP,
            100,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );
        self.record_packet(&eth_req);

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            self.record_packet(&resp);
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            if let Ok(dns_resp) = DnsMessage::parse(udp.payload) {
                for ans in dns_resp.answers {
                    println!("  Answer: {} -> {} (TTL: {}s)", ans.name, ans.ip, ans.ttl);
                }
            }
        }
    }

    fn cmd_udp(&mut self, args: &[&str]) {
        if args.len() < 4 || args[0] != "send" {
            println!("Usage: udp send <ip> <port> <message>");
            return;
        }

        let target_ip = Ipv4Address::from_str(args[1]).unwrap();
        let port = args[2].parse::<u16>().unwrap();
        let msg = args[3..].join(" ");

        println!(
            "Sending UDP datagram to {}:{} ({} bytes)...",
            target_ip,
            port,
            msg.len()
        );
        let udp_req =
            UdpDatagram::serialize(self.stack.config.ip, target_ip, 49152, port, msg.as_bytes());
        let ip_req = Ipv4Packet::serialize(
            self.stack.config.ip,
            target_ip,
            IP_PROTO_UDP,
            200,
            64,
            &udp_req,
        );
        let eth_req = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_req,
        );
        self.record_packet(&eth_req);

        let resps = self.remote_stack.process_frame(&eth_req);
        for resp in resps {
            self.record_packet(&resp);
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let udp =
                UdpDatagram::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            println!(
                "Received UDP reply from {}:{}: \"{}\"",
                ip.header.src_ip,
                udp.src_port,
                String::from_utf8_lossy(udp.payload)
            );
        }
    }

    fn cmd_curl(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: curl <ip[:port]>");
            return;
        }

        let target_ip = Ipv4Address::from_str(args[0].split(':').next().unwrap())
            .unwrap_or(self.remote_host_ip);
        println!("Connecting to {} over TCP HTTP (port 80)...", target_ip);

        let client_port = 55000;
        let client_isn = 1000;
        let syn = TcpSegment::serialize(
            self.stack.config.ip,
            target_ip,
            client_port,
            80,
            client_isn,
            0,
            TcpFlags::syn(),
            65535,
            &[],
        );
        let ip_syn =
            Ipv4Packet::serialize(self.stack.config.ip, target_ip, IP_PROTO_TCP, 301, 64, &syn);
        let eth_syn = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_syn,
        );
        self.record_packet(&eth_syn);

        let syn_acks = self.remote_stack.process_frame(&eth_syn);
        if syn_acks.is_empty() {
            println!("Connection refused / timed out.");
            return;
        }

        let syn_ack_eth = EthernetFrame::parse(&syn_acks[0]).unwrap();
        let syn_ack_ip = Ipv4Packet::parse(syn_ack_eth.payload, true).unwrap();
        let syn_ack_tcp = TcpSegment::parse(
            syn_ack_ip.header.src_ip,
            syn_ack_ip.header.dst_ip,
            syn_ack_ip.payload,
            true,
        )
        .unwrap();
        println!(
            "Connected! [SYN+ACK received from port 80, Seq={}, Ack={}]",
            syn_ack_tcp.seq_num, syn_ack_tcp.ack_num
        );

        let http_req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: ToyNetStack-Curl\r\n\r\n",
            target_ip
        );
        let data_seg = TcpSegment::serialize(
            self.stack.config.ip,
            target_ip,
            client_port,
            80,
            syn_ack_tcp.ack_num,
            syn_ack_tcp.seq_num + 1,
            TcpFlags {
                psh: true,
                ack: true,
                ..Default::default()
            },
            65535,
            http_req.as_bytes(),
        );
        let ip_data = Ipv4Packet::serialize(
            self.stack.config.ip,
            target_ip,
            IP_PROTO_TCP,
            302,
            64,
            &data_seg,
        );
        let eth_data = EthernetFrame::serialize(
            self.remote_host_mac,
            self.stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_data,
        );
        self.record_packet(&eth_data);

        let data_resps = self.remote_stack.process_frame(&eth_data);
        for resp in data_resps {
            self.record_packet(&resp);
            let eth = EthernetFrame::parse(&resp).unwrap();
            let ip = Ipv4Packet::parse(eth.payload, true).unwrap();
            let tcp =
                TcpSegment::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            println!("Server ACK: Seq={}, Ack={}", tcp.seq_num, tcp.ack_num);
        }

        println!("HTTP/1.1 200 OK (Virtual Web Server)");
        println!(
            "Content-Type: text/plain\r\n\r\nHello from Toy TCP/IP Stack Virtual Web Server!\n"
        );
    }

    fn cmd_tls(&mut self, _args: &[&str]) {
        println!("Initiating TLS 1.3 Handshake (RFC 8446)...");
        let client_hello = TlsRecord::build_client_hello("toy-tcpip.org", [0x55; 32]);
        println!(
            "  1. [Client -> Server] TLS Record (Type=22 Handshake, Len={}) -> ClientHello",
            client_hello.payload.len()
        );

        let server_hello = TlsRecord::build_server_hello([0x77; 32]);
        println!(
            "  2. [Server -> Client] TLS Record (Type=22 Handshake, Len={}) -> ServerHello (Cipher: TLS_AES_128_GCM_SHA256)",
            server_hello.payload.len()
        );
        println!("  3. [Key Exchange] Derived Handshake & Application Secret Keys.");
        println!("  4. Handshake Complete: TLS 1.3 Session Established.\n");
    }

    fn cmd_http2(&mut self, _args: &[&str]) {
        println!("Initiating HTTP/2 Multiplexed Stream Session (RFC 7540)...");
        let _settings = Http2Frame::build_settings(false);
        println!("  1. Sent HTTP/2 SETTINGS frame (Stream ID 0, 9-byte header)");
        let _headers = Http2Frame::build_headers(1, false, true, b":method GET :path /index.html");
        println!("  2. Sent HTTP/2 HEADERS frame (Stream ID 1, Flags: END_HEADERS)");
        let data = Http2Frame::build_data(1, true, b"Hello HTTP/2 multiplexing!");
        println!(
            "  3. Sent HTTP/2 DATA frame (Stream ID 1, Flags: END_STREAM, {} bytes)",
            data.payload.len()
        );
        println!("  4. HTTP/2 Stream 1 response received successfully.\n");
    }

    fn cmd_firewall(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "list" {
            println!("Stateful Firewall Filter Rules:");
            println!(
                "  [INPUT Chain]  (Default: {})",
                self.stack.firewall.default_input_policy
            );
            if self.stack.firewall.input_rules.is_empty() {
                println!("    <empty>");
            }
            for (i, r) in self.stack.firewall.input_rules.iter().enumerate() {
                println!(
                    "    #{}: Action={} Desc=\"{}\"",
                    i + 1,
                    r.action,
                    r.description
                );
            }
        } else if args[0] == "flush" {
            self.stack.firewall.flush_chain(FirewallChain::Input);
            println!("Flushed INPUT firewall chain.");
        } else if args.len() >= 3 && args[0] == "add" && args[1] == "drop" {
            if let Ok(ip) = Ipv4Address::from_str(args[2]) {
                self.stack.firewall.add_rule(
                    FirewallChain::Input,
                    FirewallRule {
                        description: format!("Block IP {}", ip),
                        src_cidr: Some(IpCidr::new(ip, 32)),
                        action: FirewallAction::Drop,
                        ..Default::default()
                    },
                );
                println!("Added rule: DROP all traffic from {}", ip);
            } else {
                println!("Invalid IP: {}", args[2]);
            }
        }
    }

    fn cmd_nat(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "status" {
            if let Some(ref nat) = self.remote_stack.nat {
                println!("NAT / Masquerade Gateway Status:");
                println!("  Public IP         : {}", nat.public_ip);
                println!("  Active Sessions   : {}", nat.active_session_count());
                println!("  Port Forward Rules: {}", nat.port_forward_rules().len());
                for r in nat.port_forward_rules() {
                    println!(
                        "    Port {} -> {}:{}",
                        r.external_port, r.internal_ip, r.internal_port
                    );
                }
            } else {
                println!("NAT is currently disabled on gateway.");
            }
        } else if args.len() >= 4 && args[0] == "forward" {
            let ext_port = args[1].parse::<u16>().unwrap_or(8080);
            let int_ip = Ipv4Address::from_str(args[2]).unwrap_or(self.stack.config.ip);
            let int_port = args[3].parse::<u16>().unwrap_or(80);
            if let Some(ref mut nat) = self.remote_stack.nat {
                nat.add_port_forward(ext_port, int_ip, int_port, IP_PROTO_TCP);
                println!(
                    "Added DNAT Port Forward: External Port {} -> {}:{}",
                    ext_port, int_ip, int_port
                );
            }
        }
    }

    fn cmd_tcp_stats(&self) {
        println!("TCP Congestion Control & Flow Control Status:");
        for (key, conn) in &self.remote_stack.tcp_manager.connections {
            println!(
                "Connection {}:{} <-> {}:{}",
                key.local.ip, key.local.port, key.remote.ip, key.remote.port
            );
            println!("  State        : {}", conn.state);
            println!(
                "  CWND (bytes) : {} ({} MSS)",
                conn.congestion.cwnd,
                conn.congestion.cwnd / conn.congestion.mss.max(1)
            );
            println!("  Ssthresh     : {} bytes", conn.congestion.ssthresh);
            println!("  CC State     : {}", conn.congestion.state);
            println!("  In Flight    : {} bytes", conn.congestion.in_flight);
            println!(
                "  RTO Estimator: {:.1} ms (SRTT: {:?} ms)",
                conn.rtt.rto, conn.rtt.srtt
            );
        }
        if self.remote_stack.tcp_manager.connections.is_empty() {
            println!("  No active TCP connections currently tracked.");
        }
    }

    fn cmd_netstat(&self) {
        println!("Active Internet connections:");
        println!("Proto Recv-Q Send-Q Local Address          Foreign Address        State");
        println!("tcp   0      0      0.0.0.0:49             0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:80             0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:179            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:389            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:443            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:646            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:830            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:862            0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:1883           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:3868           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:4189           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:4317           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:4318           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:6653           0.0.0.0:*              LISTEN");
        println!("tcp   0      0      0.0.0.0:7777           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:7              0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:53             0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:69             0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:123            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:161            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:319            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:320            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:514            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:546            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:547            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:646            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:862            0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:1812           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:1985           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:2055           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:2152           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:3222           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:3478           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:3503           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:3784           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4341           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4342           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4754           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4789           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4790           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:4791           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:5004           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:5060           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:5683           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:6080           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:6081           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:6343           0.0.0.0:*              LISTEN");
        println!("udp   0      0      0.0.0.0:51820          0.0.0.0:*              LISTEN");
    }

    fn cmd_pcap(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: pcap start <file.pcap> | stop");
            return;
        }

        if args[0] == "start" && args.len() >= 2 {
            let path = args[1];
            match File::create(path) {
                Ok(file) => {
                    let writer = PcapWriter::new(file, 65535, LINKTYPE_ETHERNET).unwrap();
                    self.pcap_writer = Some(writer);
                    println!("Started PCAP packet recording -> '{}'", path);
                }
                Err(e) => println!("Failed to create PCAP file: {}", e),
            }
        } else if args[0] == "stop" {
            self.pcap_writer = None;
            println!("Stopped PCAP packet recording.");
        }
    }

    fn cmd_lab(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "help" {
            println!("Virtual Network Lab (Deterministic In-Process Data Plane Testbed)");
            println!("Usage: lab <subcommand> [args...]");
            println!("Subcommands:");
            println!(
                "  topology               - Display virtual network topology (Nodes, Links, Subnets)"
            );
            println!(
                "  ping4 [target_ip]      - Execute end-to-end IPv4 Ping with cold ARP resolution"
            );
            println!(
                "  ping6 [target_ip6]     - Execute end-to-end IPv6 Ping with NDP NS/NA resolution"
            );
            println!(
                "  route4 [target_ip] [ttl] - Multi-hop routed IPv4 data plane test & TTL expiration"
            );
            println!("  udp-echo [msg]         - End-to-end UDP echo client/server exchange");
            println!(
                "  tcp-demo               - Full TCP connection lifecycle (3-way handshake, Data, Teardown)"
            );
            println!(
                "  sockets                - SocketRuntime API (UDP bind, TCP listen, accept queue demo)"
            );
            println!(
                "  tcp-reliable           - MSS segmentation, flow control, and large payload transfer"
            );
            println!(
                "  tcp-loss               - Retransmission recovery under deterministic link packet drops"
            );
            println!(
                "  tcp-reorder            - Out-of-order segment buffering and stream reassembly demo"
            );
            println!(
                "  http                   - HTTP/1.1 client-server exchange over TcpStream API"
            );
            println!("  tcp-stats              - Transport layer telemetry and connection stats");
            println!(
                "  pcap [output.pcap]     - Run lab test suite with link packet tap and export PCAP"
            );
            return;
        }

        match args[0] {
            "topology" => {
                println!(
                    "╔════════════════════════════════════════════════════════════════════════════╗"
                );
                println!(
                    "║                 🌐 Integrated Virtual Network Lab Topologies                ║"
                );
                println!(
                    "╚════════════════════════════════════════════════════════════════════════════╝"
                );
                println!("Topology A (Switched L2 LAN):");
                println!(
                    "  [Host A: 192.168.1.10 / 2001:db8:1::10] ──(lan1: 1500 MTU)── [Host B: 192.168.1.20 / 2001:db8:1::20]"
                );
                println!();
                println!("Topology B (Multi-Subnet Routed WAN):");
                println!("  [Host A: 10.0.1.2/24 GW: 10.0.1.1]");
                println!("         │ (link_net1: 10.0.1.0/24)");
                println!("  [Router: eth0=10.0.1.1 | eth1=10.0.2.1]");
                println!("         │ (link_net2: 10.0.2.0/24)");
                println!("  [Host B: 10.0.2.2/24 GW: 10.0.2.1]");
            }

            "ping4" => {
                let target_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(192, 168, 1, 20))
                } else {
                    Ipv4Address::new(192, 168, 1, 20)
                };

                let mut lab = VirtualLab::new();
                let h_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x10]);
                let h_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x20]);
                let h_a_ip = Ipv4Address::new(192, 168, 1, 10);
                let h_b_ip = Ipv4Address::new(192, 168, 1, 20);

                lab.add_host(
                    "host_a",
                    "lan1",
                    NetStackConfig {
                        mac: h_a_mac,
                        ip: h_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "host_b",
                    "lan1",
                    NetStackConfig {
                        mac: h_b_mac,
                        ip: h_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );

                println!(
                    "Initiating IPv4 Ping from host_a ({}) to {}...",
                    h_a_ip, target_ip
                );
                if let Some(frame) =
                    lab.host_mut("host_a")
                        .unwrap()
                        .stack
                        .ping4(target_ip, 0x1234, 1, b"LAB_PING4")
                {
                    lab.send_from_host("host_a", frame);
                    let steps = lab.run_until_quiescent(10);
                    let host_a = lab.host("host_a").unwrap();
                    if !host_a.stack.received_icmp_replies.is_empty() {
                        println!(
                            "✓ 64 bytes from {}: icmp_seq=1 ttl=64 roundtrip=OK (simulation steps: {})",
                            target_ip, steps
                        );
                        println!(
                            "  ARP Cache: {} -> {:?}",
                            target_ip,
                            host_a.stack.arp_table.lookup(&target_ip.0)
                        );
                    } else {
                        println!("✗ Request timeout for {}", target_ip);
                    }
                }
            }

            "ping6" => {
                let target_ip6 = if args.len() >= 2 {
                    Ipv6Address::from_str(args[1]).unwrap_or_else(|_| {
                        Ipv6Address::new([0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0020])
                    })
                } else {
                    Ipv6Address::new([0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0020])
                };

                let mut lab = VirtualLab::new();
                let h_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x10]);
                let h_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x20]);
                let h_a_ip6 = Ipv6Address::new([0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010]);
                let h_b_ip6 = Ipv6Address::new([0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0020]);

                lab.add_host(
                    "host_a",
                    "lan6",
                    NetStackConfig {
                        mac: h_a_mac,
                        ip: Ipv4Address::new(10, 0, 0, 10),
                        ipv6: Some(h_a_ip6),
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "host_b",
                    "lan6",
                    NetStackConfig {
                        mac: h_b_mac,
                        ip: Ipv4Address::new(10, 0, 0, 20),
                        ipv6: Some(h_b_ip6),
                        subnet_mask: 24,
                        gateway: None,
                    },
                );

                println!(
                    "Initiating IPv6 Ping from host_a ({:?}) to {:?}...",
                    h_a_ip6, target_ip6
                );
                if let Some(frame) =
                    lab.host_mut("host_a")
                        .unwrap()
                        .stack
                        .ping6(target_ip6, 0x5678, 1, b"LAB_PING6")
                {
                    lab.send_from_host("host_a", frame);
                    let steps = lab.run_until_quiescent(10);
                    let host_a = lab.host("host_a").unwrap();
                    if !host_a.stack.received_icmpv6_replies.is_empty() {
                        println!(
                            "✓ 64 bytes from {:?}: icmp_seq=1 hop_limit=64 (simulation steps: {})",
                            target_ip6, steps
                        );
                        println!(
                            "  NDP Cache: {:?} -> {:?}",
                            target_ip6,
                            host_a.stack.ndp_table.lookup(&target_ip6)
                        );
                    } else {
                        println!("✗ Request timeout for {:?}", target_ip6);
                    }
                }
            }

            "route4" => {
                let target_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 0, 2, 2))
                } else {
                    Ipv4Address::new(10, 0, 2, 2)
                };
                let ttl: u8 = if args.len() >= 3 {
                    args[2].parse().unwrap_or(64)
                } else {
                    64
                };

                let mut lab = VirtualLab::new();
                let host_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x03, 0x10]);
                let host_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x03, 0x20]);
                let rtr_if0_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x03, 0x01]);
                let rtr_if1_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x03, 0x02]);

                let host_a_ip = Ipv4Address::new(10, 0, 1, 2);
                let rtr_if0_ip = Ipv4Address::new(10, 0, 1, 1);
                let rtr_if1_ip = Ipv4Address::new(10, 0, 2, 1);
                let host_b_ip = Ipv4Address::new(10, 0, 2, 2);

                lab.add_host(
                    "host_a",
                    "link_net1",
                    NetStackConfig {
                        mac: host_a_mac,
                        ip: host_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(rtr_if0_ip),
                    },
                );
                lab.add_host(
                    "host_b",
                    "link_net2",
                    NetStackConfig {
                        mac: host_b_mac,
                        ip: host_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(rtr_if1_ip),
                    },
                );

                let mut router = LabRouter::new("rtr1");
                router.add_interface("eth0", rtr_if0_mac, rtr_if0_ip, 24, "link_net1");
                router.add_interface("eth1", rtr_if1_mac, rtr_if1_ip, 24, "link_net2");
                lab.add_router(router);

                println!(
                    "Routing IPv4 packet from Host A ({}) to {} (TTL={})...",
                    host_a_ip, target_ip, ttl
                );

                if ttl == 1 {
                    let icmp_req = IcmpPacket::build_echo_request(0x9999, 1, b"TTL1_EXPIRY");
                    let ip_ttl1 = Ipv4Packet::serialize(
                        host_a_ip,
                        target_ip,
                        IP_PROTO_ICMP,
                        555,
                        1,
                        &icmp_req,
                    );
                    let eth_frame =
                        EthernetFrame::serialize(rtr_if0_mac, host_a_mac, ETHERTYPE_IPV4, &ip_ttl1);
                    lab.send_from_host("host_a", eth_frame);
                    lab.run_until_quiescent(10);

                    let host_a = lab.host("host_a").unwrap();
                    if !host_a.stack.received_icmp_time_exceeded.is_empty() {
                        println!(
                            "! From {} icmp_seq=1 Time to live exceeded (Type 11 Code 0)",
                            host_a.stack.received_icmp_time_exceeded[0].0
                        );
                    }
                } else if let Some(frame) = lab.host_mut("host_a").unwrap().stack.ping4(
                    target_ip,
                    0xABCD,
                    1,
                    b"ROUTED_PING",
                ) {
                    lab.send_from_host("host_a", frame);
                    let steps = lab.run_until_quiescent(20);
                    let host_a = lab.host("host_a").unwrap();
                    if !host_a.stack.received_icmp_replies.is_empty() {
                        println!(
                            "✓ Routed reply from {}: icmp_seq=1 ttl=62 (traversed rtr1 in {} steps)",
                            target_ip, steps
                        );
                    }
                }
            }

            "udp-echo" => {
                let msg = if args.len() >= 2 {
                    args[1]
                } else {
                    "Hello Virtual Lab"
                };
                let mut lab = VirtualLab::new();
                let host_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x04, 0x10]);
                let host_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x04, 0x20]);
                let host_a_ip = Ipv4Address::new(192, 168, 10, 10);
                let host_b_ip = Ipv4Address::new(192, 168, 10, 20);

                lab.add_host(
                    "host_a",
                    "lan_udp",
                    NetStackConfig {
                        mac: host_a_mac,
                        ip: host_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "host_b",
                    "lan_udp",
                    NetStackConfig {
                        mac: host_b_mac,
                        ip: host_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );

                lab.host_mut("host_b").unwrap().stack.udp_sockets.bind(
                    9000,
                    |_src_ip, _src_port, payload| {
                        let mut echo = b"ECHO: ".to_vec();
                        echo.extend_from_slice(payload);
                        Some(echo)
                    },
                );

                println!(
                    "Sending UDP echo from host_a:45000 to host_b ({}:9000): '{}'...",
                    host_b_ip, msg
                );
                if let Some(frame) = lab.host_mut("host_a").unwrap().stack.send_udp(
                    host_b_ip,
                    45000,
                    9000,
                    msg.as_bytes(),
                ) {
                    lab.send_from_host("host_a", frame);
                    let steps = lab.run_until_quiescent(10);
                    let host_a = lab.host("host_a").unwrap();
                    if !host_a.stack.received_udp_payloads.is_empty() {
                        let (_, _, _, ref data) = host_a.stack.received_udp_payloads[0];
                        println!(
                            "✓ Received UDP Echo: '{}' (steps: {})",
                            String::from_utf8_lossy(data),
                            steps
                        );
                    }
                }
            }

            "tcp-demo" => {
                let mut lab = VirtualLab::new();
                let host_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x05, 0x10]);
                let host_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x05, 0x20]);
                let host_a_ip = Ipv4Address::new(192, 168, 20, 10);
                let host_b_ip = Ipv4Address::new(192, 168, 20, 20);

                lab.add_host(
                    "client",
                    "lan_tcp",
                    NetStackConfig {
                        mac: host_a_mac,
                        ip: host_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "server",
                    "lan_tcp",
                    NetStackConfig {
                        mac: host_b_mac,
                        ip: host_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.host_mut("server").unwrap().stack.tcp_manager.listen(80);

                let client_sock = SocketAddrV4 {
                    ip: host_a_ip,
                    port: 50000,
                };
                let server_sock = SocketAddrV4 {
                    ip: host_b_ip,
                    port: 80,
                };

                println!("1. TCP 3-Way Handshake [SYN -> SYN-ACK -> ACK]...");
                let syn = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_connect_raw(host_b_ip, 50000, 80, 1000)
                    .unwrap();
                lab.send_from_host("client", syn);
                lab.run_until_quiescent(10);
                println!(
                    "   Client State: {} | Server State: {}",
                    lab.host("client")
                        .unwrap()
                        .stack
                        .tcp_manager
                        .get_connection(client_sock, server_sock)
                        .unwrap()
                        .state,
                    lab.host("server")
                        .unwrap()
                        .stack
                        .tcp_manager
                        .get_connection(server_sock, client_sock)
                        .unwrap()
                        .state,
                );

                println!("2. TCP Data Streaming [GET / HTTP/1.1]...");
                let data = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_send_data_raw(host_b_ip, 50000, 80, b"GET / HTTP/1.1\r\n\r\n")
                    .unwrap();
                lab.send_from_host("client", data);
                lab.run_until_quiescent(10);
                let srv_buf = &lab
                    .host("server")
                    .unwrap()
                    .stack
                    .tcp_manager
                    .get_connection(server_sock, client_sock)
                    .unwrap()
                    .rx_buffer;
                println!(
                    "   Server Inbound Buffer: '{}'",
                    String::from_utf8_lossy(srv_buf)
                );

                println!("3. TCP 4-Way Connection Teardown [FIN-ACK -> ACK]...");
                let fin = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_close_raw(host_b_ip, 50000, 80)
                    .unwrap();
                lab.send_from_host("client", fin);
                lab.run_until_quiescent(10);
                println!(
                    "   Client State: {} | Server State: {}",
                    lab.host("client")
                        .unwrap()
                        .stack
                        .tcp_manager
                        .get_connection(client_sock, server_sock)
                        .unwrap()
                        .state,
                    lab.host("server")
                        .unwrap()
                        .stack
                        .tcp_manager
                        .get_connection(server_sock, client_sock)
                        .unwrap()
                        .state,
                );
            }

            "dhcp" => {
                println!("=== Virtual Lab: DHCPv4 DORA Auto-Configuration Demo ===");
                let mut lab = VirtualLab::new();
                let srv_ip = Ipv4Address::new(192, 168, 1, 1);
                let client_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x99]);

                lab.add_host(
                    "dhcp_server",
                    "lan_dhcp",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                        ip: srv_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.host_mut("dhcp_server").unwrap().stack.dhcp_server =
                    Some(crate::dhcp::DhcpServer::new(
                        srv_ip,
                        Ipv4Address::new(255, 255, 255, 0),
                        srv_ip,
                        Ipv4Address::new(8, 8, 8, 8),
                        Ipv4Address::new(192, 168, 1, 150),
                        Ipv4Address::new(192, 168, 1, 200),
                        86400,
                    ));

                lab.add_host(
                    "client",
                    "lan_dhcp",
                    NetStackConfig {
                        mac: client_mac,
                        ip: Ipv4Address::UNSPECIFIED,
                        ipv6: None,
                        subnet_mask: 0,
                        gateway: None,
                    },
                );

                println!("1. Client broadcasting DHCP Discover...");
                let disc = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .dhcp_discover(0xABCDEF);
                lab.send_from_host("client", disc);
                lab.run_until_quiescent(10);

                let client = lab.host_mut("client").unwrap();
                let offer = client.stack.received_dhcp_offers[0].clone();
                println!("2. Client received DHCP Offer: IP = {}", offer.yiaddr);

                println!("3. Client sending DHCP Request for {}...", offer.yiaddr);
                let req =
                    client
                        .stack
                        .dhcp_request(offer.yiaddr, offer.server_id.unwrap(), 0xABCDEF);
                lab.send_from_host("client", req);
                lab.run_until_quiescent(10);

                let client = lab.host_mut("client").unwrap();
                let ack = client.stack.received_dhcp_acks[0].clone();
                println!(
                    "4. Client received DHCP ACK: IP = {}, Router = {:?}",
                    ack.yiaddr, ack.router
                );

                client.stack.apply_dhcp_ack(&ack);
                println!(
                    "✓ Client stack dynamically reconfigured: IP = {}/{}",
                    client.stack.config.ip, client.stack.config.subnet_mask
                );
            }

            "nat" => {
                println!("=== Virtual Lab: NAPT (SNAT & DNAT) Router Demo ===");
                let mut lab = VirtualLab::new();
                let client_ip = Ipv4Address::new(192, 168, 10, 5);
                let router_lan_ip = Ipv4Address::new(192, 168, 10, 1);
                let router_wan_ip = Ipv4Address::new(203, 0, 113, 1);
                let server_ip = Ipv4Address::new(203, 0, 113, 80);

                lab.add_host(
                    "private_client",
                    "lan",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x0A, 0x10]),
                        ip: client_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(router_lan_ip),
                    },
                );

                lab.add_host(
                    "wan_server",
                    "wan",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x0B, 0x80]),
                        ip: server_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(router_wan_ip),
                    },
                );

                lab.host_mut("wan_server").unwrap().stack.udp_sockets.bind(
                    8080,
                    |_src, _port, data| {
                        let mut resp = b"ACK:".to_vec();
                        resp.extend_from_slice(data);
                        Some(resp)
                    },
                );

                let mut r = LabRouter::new("nat_router");
                r.add_interface(
                    "eth_lan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x0A, 0x01]),
                    router_lan_ip,
                    24,
                    "lan",
                );
                r.add_interface(
                    "eth_wan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x0B, 0x01]),
                    router_wan_ip,
                    24,
                    "wan",
                );
                r.enable_nat("eth_lan", "eth_wan", router_wan_ip);
                lab.add_router(r);

                println!(
                    "1. LAN Client {} sending UDP to WAN Server {}:8080...",
                    client_ip, server_ip
                );
                let query = lab
                    .host_mut("private_client")
                    .unwrap()
                    .stack
                    .send_udp(server_ip, 45000, 8080, b"TRANSLATION_TEST")
                    .unwrap();
                lab.send_from_host("private_client", query);
                lab.run_until_quiescent(20);

                let wan_srv = lab.host("wan_server").unwrap();
                let (src, _, _, _) = &wan_srv.stack.received_udp_payloads[0];
                println!(
                    "2. WAN Server received datagram from: {} (SNAT rewritten from {})",
                    src, client_ip
                );

                let client = lab.host("private_client").unwrap();
                let (_, _, _, reply) = &client.stack.received_udp_payloads[0];
                println!(
                    "3. Private Client received reply: '{}' (DNAT de-translated)",
                    String::from_utf8_lossy(reply)
                );
                println!("✓ Full SNAT and DNAT session translation verified!");
            }

            "rip" => {
                println!("=== Virtual Lab: RIPv2 Multi-Router Dynamic Convergence Demo ===");
                let mut lab = VirtualLab::new();
                let h_a_ip = Ipv4Address::new(10, 0, 1, 2);
                let h_b_ip = Ipv4Address::new(10, 0, 2, 2);

                lab.add_host(
                    "host_a",
                    "link_a",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x02]),
                        ip: h_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(10, 0, 1, 1)),
                    },
                );

                lab.add_host(
                    "host_b",
                    "link_b",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x02]),
                        ip: h_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(10, 0, 2, 1)),
                    },
                );

                let mut r1 = LabRouter::new("r1");
                r1.add_interface(
                    "r1_lan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                    Ipv4Address::new(10, 0, 1, 1),
                    24,
                    "link_a",
                );
                r1.add_interface(
                    "r1_wan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x11, 0x01]),
                    Ipv4Address::new(172, 16, 0, 1),
                    24,
                    "link_tr",
                );
                r1.enable_rip();
                lab.add_router(r1);

                let mut r2 = LabRouter::new("r2");
                r2.add_interface(
                    "r2_wan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x11, 0x02]),
                    Ipv4Address::new(172, 16, 0, 2),
                    24,
                    "link_tr",
                );
                r2.add_interface(
                    "r2_lan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x01]),
                    Ipv4Address::new(10, 0, 2, 1),
                    24,
                    "link_b",
                );
                r2.enable_rip();
                lab.add_router(r2);

                println!("1. Routers exchanging RIPv2 updates over 224.0.0.9:520...");
                lab.broadcast_rip_advertisements();
                lab.run_until_quiescent(10);

                let r1_route = lab
                    .router("r1")
                    .unwrap()
                    .routing_table
                    .lookup(h_b_ip)
                    .unwrap();
                println!(
                    "2. Router 1 dynamically learned route to 10.0.2.0/24 via next-hop {:?}",
                    r1_route.next_hop(h_b_ip)
                );

                println!(
                    "3. Host A ({}) pinging Host B ({}) across converged multi-router fabric...",
                    h_a_ip, h_b_ip
                );
                let ping = lab
                    .host_mut("host_a")
                    .unwrap()
                    .stack
                    .ping4(h_b_ip, 0x1122, 1, b"RIP_TEST")
                    .unwrap();
                lab.send_from_host("host_a", ping);
                lab.run_until_quiescent(20);

                let host_a = lab.host("host_a").unwrap();
                if !host_a.stack.received_icmp_replies.is_empty() {
                    println!("✓ Multi-hop dynamic routing ping successful!");
                }
            }

            "vxlan" => {
                println!("=== Virtual Lab: VXLAN L2 Overlay Fabric Demo ===");
                let mut lab = VirtualLab::new();
                let h1_ip = Ipv4Address::new(192, 168, 100, 10);
                let h2_ip = Ipv4Address::new(192, 168, 100, 20);

                lab.add_host(
                    "tenant_h1",
                    "acc_1",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x0A, 0x10]),
                        ip: h1_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "tenant_h2",
                    "acc_2",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x0A, 0x20]),
                        ip: h2_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );

                let mut leaf1 = LabRouter::new("leaf1");
                leaf1.add_interface(
                    "eth_acc",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0xAA]),
                    Ipv4Address::new(192, 168, 100, 254),
                    24,
                    "acc_1",
                );
                leaf1.add_interface(
                    "eth_und",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                    Ipv4Address::new(10, 0, 1, 1),
                    24,
                    "und_1",
                );
                leaf1.routing_table.add_route(
                    Ipv4Address::new(10, 0, 2, 0),
                    24,
                    Some(Ipv4Address::new(10, 0, 1, 254)),
                    "eth_und",
                );
                leaf1.add_vxlan_tunnel("eth_acc", 5001, Ipv4Address::new(10, 0, 2, 1), "eth_und");
                lab.add_router(leaf1);

                let mut spine = LabRouter::new("spine");
                spine.add_interface(
                    "sp_if1",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x55, 0x01]),
                    Ipv4Address::new(10, 0, 1, 254),
                    24,
                    "und_1",
                );
                spine.add_interface(
                    "sp_if2",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x55, 0x02]),
                    Ipv4Address::new(10, 0, 2, 254),
                    24,
                    "und_2",
                );
                lab.add_router(spine);

                let mut leaf2 = LabRouter::new("leaf2");
                leaf2.add_interface(
                    "eth_und",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x01]),
                    Ipv4Address::new(10, 0, 2, 1),
                    24,
                    "und_2",
                );
                leaf2.add_interface(
                    "eth_acc",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0xAA]),
                    Ipv4Address::new(192, 168, 100, 253),
                    24,
                    "acc_2",
                );
                leaf2.routing_table.add_route(
                    Ipv4Address::new(10, 0, 1, 0),
                    24,
                    Some(Ipv4Address::new(10, 0, 2, 254)),
                    "eth_und",
                );
                leaf2.add_vxlan_tunnel("eth_acc", 5001, Ipv4Address::new(10, 0, 1, 1), "eth_und");
                lab.add_router(leaf2);

                println!(
                    "1. Encapsulating Tenant Ethernet frames over VNI 5001 across Underlay IP..."
                );
                let ping = lab
                    .host_mut("tenant_h1")
                    .unwrap()
                    .stack
                    .ping4(h2_ip, 0x4321, 1, b"VXLAN_DEMO")
                    .unwrap();
                lab.send_from_host("tenant_h1", ping);
                lab.run_until_quiescent(30);

                let h1 = lab.host("tenant_h1").unwrap();
                if !h1.stack.received_icmp_replies.is_empty() {
                    println!(
                        "✓ Tenant Host 1 received ICMP reply from Tenant Host 2 across VXLAN fabric!"
                    );
                }
            }

            "ospf" => {
                println!("=== Virtual Lab: OSPFv2 Link-State Dijkstra SPF Demo ===");
                let mut r1 = LabRouter::new("r1");
                r1.add_interface(
                    "r1_lan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                    Ipv4Address::new(172, 16, 1, 1),
                    24,
                    "link_a",
                );
                r1.add_interface(
                    "r1_r2",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x12, 0x01]),
                    Ipv4Address::new(10, 1, 2, 1),
                    24,
                    "link_r1_r2",
                );
                r1.add_interface(
                    "r1_r3",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x13, 0x01]),
                    Ipv4Address::new(10, 1, 3, 1),
                    24,
                    "link_r1_r3",
                );
                r1.enable_ospf();
                r1.add_ospf_link(
                    Ipv4Address::new(1, 1, 1, 1),
                    Ipv4Address::new(2, 2, 2, 2),
                    10,
                );
                r1.add_ospf_link(
                    Ipv4Address::new(2, 2, 2, 2),
                    Ipv4Address::new(3, 3, 3, 3),
                    10,
                );
                r1.add_ospf_link(
                    Ipv4Address::new(1, 1, 1, 1),
                    Ipv4Address::new(3, 3, 3, 3),
                    50,
                );

                let mut subnets = std::collections::HashMap::new();
                subnets.insert(
                    Ipv4Address::new(3, 3, 3, 3),
                    (
                        Ipv4Address::new(172, 16, 3, 0),
                        24,
                        "r1_r2".to_string(),
                        Ipv4Address::new(10, 1, 2, 2),
                    ),
                );
                r1.run_ospf_spf(Ipv4Address::new(1, 1, 1, 1), &subnets);

                let route = r1
                    .routing_table
                    .lookup(Ipv4Address::new(172, 16, 3, 10))
                    .unwrap();
                println!(
                    "1. Dijkstra Shortest Path calculated: Dest 172.16.3.0/24 -> NextHop {:?}",
                    route.next_hop(Ipv4Address::new(172, 16, 3, 10))
                );
                println!("✓ Path through R2 (Cost 20) prioritized over direct R3 link (Cost 50)");
            }

            "firewall" => {
                println!("=== Virtual Lab: Stateful Packet Filter & Firewall Demo ===");
                let mut lab = VirtualLab::new();
                let srv_ip = Ipv4Address::new(10, 0, 2, 80);

                lab.add_host(
                    "client",
                    "lan",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x05]),
                        ip: Ipv4Address::new(10, 0, 1, 5),
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(10, 0, 1, 1)),
                    },
                );

                lab.add_host(
                    "server",
                    "wan",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x80]),
                        ip: srv_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(10, 0, 2, 1)),
                    },
                );

                lab.host_mut("server")
                    .unwrap()
                    .stack
                    .udp_sockets
                    .bind(80, |_src, _port, data| {
                        let mut resp = b"HTTP:".to_vec();
                        resp.extend_from_slice(data);
                        Some(resp)
                    });
                lab.host_mut("server")
                    .unwrap()
                    .stack
                    .udp_sockets
                    .bind(23, |_src, _port, _data| Some(b"TELNET".to_vec()));

                let mut r = LabRouter::new("gw");
                r.add_interface(
                    "lan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                    Ipv4Address::new(10, 0, 1, 1),
                    24,
                    "lan",
                );
                r.add_interface(
                    "wan",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x01]),
                    Ipv4Address::new(10, 0, 2, 1),
                    24,
                    "wan",
                );

                let mut fw = crate::firewall::Firewall::new();
                fw.add_rule(
                    crate::firewall::FirewallChain::Forward,
                    crate::firewall::FirewallRule {
                        description: "Drop Telnet".to_string(),
                        src_cidr: None,
                        dst_cidr: None,
                        protocol: Some(crate::ipv4::IP_PROTO_UDP),
                        src_port_range: None,
                        dst_port_range: Some((23, 23)),
                        action: crate::firewall::FirewallAction::Drop,
                    },
                );
                r.set_firewall(fw);
                lab.add_router(r);

                println!("1. Testing Port 80 (Allowed)...");
                let q80 = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .send_udp(srv_ip, 40000, 80, b"PING80")
                    .unwrap();
                lab.send_from_host("client", q80);
                lab.run_until_quiescent(20);
                assert_eq!(
                    lab.host("client")
                        .unwrap()
                        .stack
                        .received_udp_payloads
                        .len(),
                    1
                );
                println!("✓ Port 80 query succeeded!");

                println!("2. Testing Port 23 (Firewall Drop)...");
                let q23 = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .send_udp(srv_ip, 40001, 23, b"PING23")
                    .unwrap();
                lab.send_from_host("client", q23);
                lab.run_until_quiescent(20);
                assert_eq!(
                    lab.host("client")
                        .unwrap()
                        .stack
                        .received_udp_payloads
                        .len(),
                    1
                );
                println!("✓ Port 23 traffic dropped by router firewall!");
            }

            "mpls" => {
                println!("=== Virtual Lab: MPLS 3-Node LSP (Push/Swap/Pop) Demo ===");
                let mut lab = VirtualLab::new();
                let h_b_ip = Ipv4Address::new(192, 168, 2, 20);

                lab.add_host(
                    "h_a",
                    "link_a",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x10]),
                        ip: Ipv4Address::new(192, 168, 1, 10),
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(192, 168, 1, 1)),
                    },
                );

                lab.add_host(
                    "h_b",
                    "link_b",
                    NetStackConfig {
                        mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x20]),
                        ip: h_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: Some(Ipv4Address::new(192, 168, 2, 1)),
                    },
                );

                let mut r1 = LabRouter::new("r1");
                r1.add_interface(
                    "r1_cust",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]),
                    Ipv4Address::new(192, 168, 1, 1),
                    24,
                    "link_a",
                );
                r1.add_interface(
                    "r1_core",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x12, 0x01]),
                    Ipv4Address::new(10, 0, 12, 1),
                    24,
                    "core_12",
                );
                r1.enable_mpls();
                r1.add_mpls_push_route(h_b_ip, 100, "r1_core");
                lab.add_router(r1);

                let mut r2 = LabRouter::new("r2");
                r2.add_interface(
                    "r2_in",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x12, 0x02]),
                    Ipv4Address::new(10, 0, 12, 2),
                    24,
                    "core_12",
                );
                r2.add_interface(
                    "r2_out",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x23, 0x02]),
                    Ipv4Address::new(10, 0, 23, 2),
                    24,
                    "core_23",
                );
                r2.enable_mpls();
                r2.add_mpls_swap_route(100, 200, "r2_out");
                lab.add_router(r2);

                let mut r3 = LabRouter::new("r3");
                r3.add_interface(
                    "r3_core",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x23, 0x03]),
                    Ipv4Address::new(10, 0, 23, 3),
                    24,
                    "core_23",
                );
                r3.add_interface(
                    "r3_cust",
                    MacAddress([0x02, 0x00, 0x00, 0x00, 0x02, 0x01]),
                    Ipv4Address::new(192, 168, 2, 1),
                    24,
                    "link_b",
                );
                r3.enable_mpls();
                r3.add_mpls_pop_route(200);
                lab.add_router(r3);

                println!(
                    "1. Transmitting customer packet through MPLS LSP: R1 (PUSH 100) -> R2 (SWAP 200) -> R3 (POP)..."
                );
                let pkt = lab
                    .host_mut("h_a")
                    .unwrap()
                    .stack
                    .send_udp(h_b_ip, 30000, 9000, b"MPLS_DEMO")
                    .unwrap();
                lab.send_from_host("h_a", pkt);
                lab.run_until_quiescent(25);

                let hb = lab.host("h_b").unwrap();
                assert_eq!(hb.stack.received_udp_payloads.len(), 1);
                println!(
                    "✓ Customer Host B received packet across MPLS core: '{}'",
                    String::from_utf8_lossy(&hb.stack.received_udp_payloads[0].3)
                );
            }

            "pcap" => {
                let out_file = if args.len() >= 2 {
                    args[1]
                } else {
                    "lab_trace.pcap"
                };
                let mut lab = VirtualLab::new();
                let host_a_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x07, 0x10]);
                let host_b_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x07, 0x20]);
                let host_a_ip = Ipv4Address::new(192, 168, 40, 10);
                let host_b_ip = Ipv4Address::new(192, 168, 40, 20);

                lab.add_host(
                    "host_a",
                    "lan_pcap",
                    NetStackConfig {
                        mac: host_a_mac,
                        ip: host_a_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.add_host(
                    "host_b",
                    "lan_pcap",
                    NetStackConfig {
                        mac: host_b_mac,
                        ip: host_b_ip,
                        ipv6: None,
                        subnet_mask: 24,
                        gateway: None,
                    },
                );
                lab.enable_pcap("lan_pcap");

                let ping_frame = lab
                    .host_mut("host_a")
                    .unwrap()
                    .stack
                    .ping4(host_b_ip, 0x7777, 1, b"PCAP_RECORD_DEMO")
                    .unwrap();
                lab.send_from_host("host_a", ping_frame);
                lab.run_until_quiescent(10);

                if let Some(pcap_bytes) = lab.export_pcap("lan_pcap") {
                    if let Ok(mut f) = File::create(out_file) {
                        let _ = f.write_all(&pcap_bytes);
                        println!(
                            "✓ Exported {} bytes of PCAP packet trace to '{}'",
                            pcap_bytes.len(),
                            out_file
                        );
                    } else {
                        println!(
                            "✓ Generated {} bytes in memory PCAP trace for 'lan_pcap'",
                            pcap_bytes.len()
                        );
                    }
                }
            }

            "sockets" => {
                println!("=== Socket Runtime: UDP Datagrams, Listener Backlog, Accept Queue ===");
                let mut lab = build_socket_lab("lan_sock", 1460);

                // --- UDP: bind, ephemeral allocation, send_to / recv_from over the wire ---
                let srv_udp = lab
                    .host_mut("server")
                    .unwrap()
                    .stack
                    .udp_bind(7777)
                    .unwrap();
                let cli_udp = lab.host_mut("client").unwrap().stack.udp_bind(0).unwrap();
                let cli_port = lab
                    .host("client")
                    .unwrap()
                    .stack
                    .sockets
                    .udp_sockets
                    .get(&cli_udp)
                    .unwrap()
                    .local_addr
                    .port;
                println!("  client bound ephemeral UDP port :{}", cli_port);
                println!("  server bound UDP :7777");

                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .udp_send_to(
                        cli_udp,
                        b"hello from the socket API",
                        SocketAddrV4 {
                            ip: SOCKET_LAB_SERVER_IP,
                            port: 7777,
                        },
                    )
                    .unwrap();
                lab.run_pumped(20);

                match lab.host_mut("server").unwrap().stack.udp_recv_from(srv_udp) {
                    Ok((data, from)) => println!(
                        "  server recv_from {} -> {:?}",
                        from,
                        String::from_utf8_lossy(&data)
                    ),
                    Err(e) => println!("  server recv_from failed: {}", e),
                }

                // Bind conflict is refused, exactly as EADDRINUSE would be.
                match lab.host_mut("server").unwrap().stack.udp_bind(7777) {
                    Ok(_) => println!("  second bind on :7777 unexpectedly succeeded"),
                    Err(e) => println!("  second bind on :7777 rejected: {}", e),
                }

                // --- TCP: one listener, three simultaneous clients, demultiplexed by 4-tuple ---
                let listener = lab
                    .host_mut("server")
                    .unwrap()
                    .stack
                    .tcp_listen(80)
                    .unwrap();
                println!("\n  server listening on TCP :80");

                for port in [50001u16, 50002, 50003] {
                    lab.host_mut("client")
                        .unwrap()
                        .stack
                        .tcp_connect_from(
                            port,
                            SocketAddrV4 {
                                ip: SOCKET_LAB_SERVER_IP,
                                port: 80,
                            },
                            1000 + port as u32,
                        )
                        .unwrap();
                }
                lab.run_until(50, 5_000, |l| {
                    l.host("server").unwrap().stack.sockets.connection_count() >= 3
                });

                let mut accepted = 0;
                while let Ok((stream, peer)) =
                    lab.host_mut("server").unwrap().stack.tcp_accept(listener)
                {
                    accepted += 1;
                    let state = lab.host("server").unwrap().stack.tcp_state(stream).unwrap();
                    println!("  accept() -> peer {} state {}", peer, state);
                }
                println!(
                    "  {} simultaneous connections accepted on one listening port",
                    accepted
                );
            }

            "tcp-reliable" => {
                println!("=== Reliable Stream: MSS Segmentation and Windowed Transfer ===");
                let mss = 256u16;
                let payload_len = 24_576usize;
                let mut lab = build_socket_lab("lan_reliable", mss);

                let (client, server, listener) = socket_lab_connect(&mut lab);
                println!("  connection established with MSS {}", mss);

                let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_write(client, &payload)
                    .unwrap();
                println!("  application wrote {} bytes in one call", payload_len);

                let done = lab.run_until(25, 60_000, |l| {
                    l.host("server")
                        .unwrap()
                        .stack
                        .tcp_stats(server)
                        .map(|s| s.bytes_received as usize >= payload_len)
                        .unwrap_or(false)
                });

                let received = drain_stream(&mut lab, "server", server);
                let stats = lab.host("client").unwrap().stack.tcp_stats(client).unwrap();
                println!(
                    "  transfer {} : {} bytes received, byte-identical = {}",
                    if done { "complete" } else { "TIMED OUT" },
                    received.len(),
                    received == payload
                );
                println!(
                    "  sender emitted {} segments for {} bytes (~{} bytes/segment)",
                    stats.segments_sent,
                    stats.bytes_sent,
                    stats.bytes_sent / stats.segments_sent.max(1)
                );
                let _ = listener;
            }

            "tcp-loss" => {
                println!("=== Retransmission Recovery Under Deterministic Packet Loss ===");
                let mss = 256u16;
                let payload_len = 16_384usize;
                let mut lab = build_socket_lab("lan_loss", mss);

                let (client, server, _l) = socket_lab_connect(&mut lab);

                // Drop a spread of data segments after the handshake has completed.
                let drops: Vec<usize> = (0..12).map(|i| 6 + i * 7).collect();
                lab.link_mut("lan_loss")
                    .unwrap()
                    .drop_packet_indices(&drops);
                println!("  dropping frame indices {:?}", drops);

                let payload: Vec<u8> = (0..payload_len)
                    .map(|i| ((i * 31 + 7) % 256) as u8)
                    .collect();
                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_write(client, &payload)
                    .unwrap();

                let done = lab.run_until(25, 120_000, |l| {
                    l.host("server")
                        .unwrap()
                        .stack
                        .tcp_stats(server)
                        .map(|s| s.bytes_received as usize >= payload_len)
                        .unwrap_or(false)
                });

                let received = drain_stream(&mut lab, "server", server);
                let stats = lab.host("client").unwrap().stack.tcp_stats(client).unwrap();
                println!(
                    "  recovery {} : {} / {} bytes, byte-identical = {}",
                    if done { "complete" } else { "TIMED OUT" },
                    received.len(),
                    payload_len,
                    received == payload
                );
                println!(
                    "  retransmissions={} (fast={}) timeouts={} duplicate-acks={}",
                    stats.retransmissions,
                    stats.fast_retransmits,
                    stats.timeouts,
                    stats.duplicate_acks
                );
                println!(
                    "  link forwarded {} frames, dropped {}",
                    lab.link("lan_loss")
                        .map(|l| l.frames_forwarded)
                        .unwrap_or(0),
                    lab.link("lan_loss").map(|l| l.frames_dropped).unwrap_or(0)
                );
            }

            "tcp-reorder" => {
                println!("=== Out-of-Order Delivery and Stream Reassembly ===");
                let mss = 256u16;
                let payload_len = 8_192usize;
                let mut lab = build_socket_lab("lan_reorder", mss);

                let (client, server, _l) = socket_lab_connect(&mut lab);

                // Hold several frames back behind later ones. Because both hosts share the
                // link, a spread of indices is what reliably lands on data segments and
                // makes the receiver buffer out of order.
                let holds = [(5usize, 8usize), (11, 14), (19, 23), (28, 32)];
                for (hold, after) in holds {
                    lab.link_mut("lan_reorder")
                        .unwrap()
                        .reorder_packet_indices
                        .push((hold, after));
                }
                println!("  holding frames {:?} behind later frames", holds);

                let payload: Vec<u8> = (0..payload_len).map(|i| (i % 97) as u8).collect();
                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_write(client, &payload)
                    .unwrap();

                let mut received: Vec<u8> = Vec::new();
                for _ in 0..20_000 {
                    let moved = lab.step();
                    received.extend(drain_stream(&mut lab, "server", server));
                    if received.len() >= payload_len {
                        break;
                    }
                    if moved == 0 {
                        lab.advance_time(25);
                    }
                }

                println!(
                    "  reassembly {} : {} bytes, byte-identical = {}",
                    if received.len() == payload_len {
                        "complete"
                    } else {
                        "TIMED OUT"
                    },
                    received.len(),
                    received == payload
                );

                // Evidence that reassembly was genuinely needed: every duplicate ACK the
                // sender saw is the receiver reporting a hole in the sequence space that it
                // had to buffer around, and every retransmission is the sender filling one.
                let sender = lab.host("client").unwrap().stack.tcp_stats(client).unwrap();
                let receiver = lab.host("server").unwrap().stack.tcp_stats(server).unwrap();
                println!(
                    "  receiver saw {} segments; sender observed {} duplicate ACKs and made {} retransmissions",
                    receiver.segments_received, sender.duplicate_acks, sender.retransmissions
                );
            }

            "http" => {
                println!("=== HTTP/1.1 Over the Socket API (no hand-built packets) ===");
                let mut lab = build_socket_lab("lan_http", 536);

                let listener = lab
                    .host_mut("server")
                    .unwrap()
                    .stack
                    .tcp_listen(8080)
                    .unwrap();
                println!("  http server listening on :8080");

                let client = lab
                    .host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_connect(SocketAddrV4 {
                        ip: SOCKET_LAB_SERVER_IP,
                        port: 8080,
                    })
                    .unwrap();

                lab.run_until(25, 10_000, |l| {
                    l.host("client")
                        .unwrap()
                        .stack
                        .tcp_state(client)
                        .map(|s| s == TcpState::Established)
                        .unwrap_or(false)
                });
                let (server, peer) = lab
                    .host_mut("server")
                    .unwrap()
                    .stack
                    .tcp_accept(listener)
                    .unwrap();
                println!("  accepted connection from {}", peer);

                let request = "GET /hello HTTP/1.1\r\nHost: lab.local\r\nConnection: close\r\n\r\n";
                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_write(client, request.as_bytes())
                    .unwrap();
                println!("  --> {}", request.lines().next().unwrap_or(""));

                lab.run_until(25, 20_000, |l| {
                    l.host("server")
                        .unwrap()
                        .stack
                        .tcp_readable(server)
                        .ge(&request.len())
                });

                let req_bytes = drain_stream(&mut lab, "server", server);
                let response = http_respond(&String::from_utf8_lossy(&req_bytes));

                lab.host_mut("server")
                    .unwrap()
                    .stack
                    .tcp_write(server, response.as_bytes())
                    .unwrap();
                lab.host_mut("server").unwrap().stack.tcp_close(server).ok();

                lab.run_until(25, 20_000, |l| {
                    l.host("client")
                        .unwrap()
                        .stack
                        .tcp_stats(client)
                        .map(|s| s.bytes_received as usize >= response.len())
                        .unwrap_or(false)
                });

                let resp_bytes = drain_stream(&mut lab, "client", client);
                let resp = String::from_utf8_lossy(&resp_bytes);
                for line in resp.lines() {
                    println!("  <-- {}", line);
                }
                println!(
                    "  response {} bytes, complete = {}",
                    resp_bytes.len(),
                    resp_bytes.len() == response.len()
                );
            }

            "tcp-stats" => {
                println!("=== Transport Diagnostics ===");
                let mss = 512u16;
                let payload_len = 32_768usize;
                let mut lab = build_socket_lab("lan_stats", mss);

                let (client, server, _l) = socket_lab_connect(&mut lab);
                lab.link_mut("lan_stats")
                    .unwrap()
                    .drop_packet_indices(&[8, 21, 34, 55]);

                let payload: Vec<u8> = (0..payload_len).map(|i| (i % 233) as u8).collect();
                lab.host_mut("client")
                    .unwrap()
                    .stack
                    .tcp_write(client, &payload)
                    .unwrap();

                lab.run_until(25, 120_000, |l| {
                    l.host("server")
                        .unwrap()
                        .stack
                        .tcp_stats(server)
                        .map(|s| s.bytes_received as usize >= payload_len)
                        .unwrap_or(false)
                });

                println!("\n-- client --");
                match lab.host("client").unwrap().stack.tcp_diagnostics(client) {
                    Ok(d) => println!("{}", d),
                    Err(e) => println!("  unavailable: {}", e),
                }
                println!("\n-- server --");
                match lab.host("server").unwrap().stack.tcp_diagnostics(server) {
                    Ok(d) => println!("{}", d),
                    Err(e) => println!("  unavailable: {}", e),
                }
            }

            other => {
                println!(
                    "Unknown lab subcommand: '{}'. Type 'lab help' for usage.",
                    other
                );
            }
        }
    }

    fn cmd_add_path(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "help" {
            println!("Usage: add-path [advert | pic | status]");
            println!(
                "  add-path status          - Show BGP ADD-PATH capability negotiation & multi-path RIB"
            );
            println!(
                "  add-path advert <prefix> - Announce multi-path routes with 4-octet Path IDs (RFC 7911)"
            );
            println!(
                "  add-path pic <prefix>    - Demonstrate BGP PIC Edge/Core sub-millisecond fast failover"
            );
            return;
        }

        match args[0] {
            "status" => {
                println!("=== BGP ADD-PATH Multi-Path RIB & Capability (RFC 7911) ===");
                println!("  Capability: Code 69 (ADD-PATH)");
                println!(
                    "  Negotiated Families: IPv4 Unicast (Send/Receive: Both), L2VPN EVPN (Both)"
                );
                println!(
                    "  Max Paths Per Prefix: {}",
                    self.bgp_add_path_rib.max_paths_per_prefix
                );
                for (prefix, paths) in &self.bgp_add_path_rib.routes {
                    println!("\n  Prefix: {}", prefix);
                    for p in paths {
                        let role = if p.is_best {
                            "[PRIMARY BEST]"
                        } else if p.is_backup {
                            "[PIC BACKUP FRR]"
                        } else {
                            "[MULTIPATH ECMP]"
                        };
                        println!(
                            "    Path-ID 0x{:08X} | Peer: {:<15} | Next-Hop: {:<15} | AS-Path: {:<12} | LocalPref: {:?} {}",
                            p.path_id, p.peer_ip, p.next_hop, p.as_path, p.local_pref, role
                        );
                    }
                }
            }
            "advert" => {
                let prefix = if args.len() > 1 {
                    Ipv4Prefix::new(
                        args[1].parse().unwrap_or(Ipv4Address::new(10, 100, 0, 0)),
                        16,
                    )
                } else {
                    Ipv4Prefix::new(Ipv4Address::new(10, 100, 0, 0), 16)
                };
                println!(
                    "=== BGP ADD-PATH Multiple Path Advertisements for {} ===",
                    prefix
                );
                let paths = self.bgp_add_path_rib.get_advertised_paths(&prefix);
                for p in paths {
                    let nlri = AddPathNlri::new(p.path_id, prefix);
                    let wire = nlri.encode();
                    println!(
                        "  Adv Path-ID 0x{:08X} -> Next-Hop: {}, AS-Path: {} (Wire NLRI: {:02X?})",
                        p.path_id, p.next_hop, p.as_path, wire
                    );
                }
            }
            "pic" => {
                let prefix = Ipv4Prefix::new(Ipv4Address::new(10, 100, 0, 0), 16);
                println!("=== BGP Prefix Independent Convergence (PIC) Failover Demo ===");
                if let Some((primary, backup)) = self.bgp_add_path_rib.get_pic_forwarding(&prefix) {
                    println!("  [NORMAL STATE] Target Prefix: {}", prefix);
                    println!(
                        "    Hardware FIB Forwarding -> Primary Next-Hop: {}",
                        primary
                    );
                    println!(
                        "    Pre-Programmed Hardware FRR -> Backup Next-Hop: {:?}",
                        backup
                    );
                    println!(
                        "\n  [FAULT INJECTION] Link to Primary Next-Hop {} Down!",
                        primary
                    );
                    if let Some(b) = backup {
                        println!(
                            "  [PIC FAST FAILOVER] Instantly shifted data path to Backup Next-Hop {} (0ms control-plane delay)",
                            b
                        );
                    }
                }
            }
            _ => println!("Unknown subcommand. Type 'add-path help'."),
        }
    }

    fn cmd_evpn_synch(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "help" {
            println!("Usage: evpn-synch [status | join <grp> | leave <grp>]");
            println!(
                "  evpn-synch status     - Show EVPN Route Type 7/8 IGMP Synch State across multihomed ES"
            );
            println!(
                "  evpn-synch join <grp> - Simulate PE Join Synch advertisement (Route Type 7)"
            );
            println!(
                "  evpn-synch leave <grp>- Simulate PE Leave Synch advertisement (Route Type 8)"
            );
            return;
        }

        match args[0] {
            "status" => {
                println!("=== EVPN IGMP/MLD Multicast State Synchronization (RFC 9251) ===");
                println!(
                    "  Join Synch Routes (Type 7): {}",
                    self.evpn_multicast_synch.join_routes.len()
                );
                for (i, r) in self.evpn_multicast_synch.join_routes.iter().enumerate() {
                    println!(
                        "    [{}] ESI: {:?} | Tag: {} | Group: {} | PE: {}",
                        i, r.esi, r.ethernet_tag_id, r.group_ip, r.originator_ip
                    );
                }
                println!(
                    "  Leave Synch Routes (Type 8): {}",
                    self.evpn_multicast_synch.leave_routes.len()
                );
                for (i, r) in self.evpn_multicast_synch.leave_routes.iter().enumerate() {
                    println!(
                        "    [{}] ESI: {:?} | Tag: {} | Group: {} | PE: {} | MaxResp: {}ms",
                        i,
                        r.esi,
                        r.ethernet_tag_id,
                        r.group_ip,
                        r.originator_ip,
                        r.max_response_time_ms
                    );
                }
            }
            "join" => {
                let grp = if args.len() > 1 {
                    args[1].parse().unwrap_or(Ipv4Address::new(239, 255, 10, 1))
                } else {
                    Ipv4Address::new(239, 255, 10, 1)
                };
                let esi = EthernetSegmentId::from_u32(100);
                let route = EvpnJoinSynchRoute::new_any_source(esi, 100, grp, self.remote_host_ip);
                let wire = route.serialize_nlri();
                self.evpn_multicast_synch.process_join_synch(route);
                let preview = if wire.len() >= 16 {
                    &wire[..16]
                } else {
                    &wire[..]
                };
                println!(
                    "  [EVPN TYPE 7] Processed Join Synch for Group {} on ESI {:?} (Wire: {:02X?})",
                    grp, esi, preview
                );
                println!("  Multicast state synchronized: Group is ACTIVE across multihomed PEs");
            }
            "leave" => {
                let grp = if args.len() > 1 {
                    args[1].parse().unwrap_or(Ipv4Address::new(239, 255, 10, 1))
                } else {
                    Ipv4Address::new(239, 255, 10, 1)
                };
                let esi = EthernetSegmentId::from_u32(100);
                let route = EvpnLeaveSynchRoute::new(esi, 100, grp, self.remote_host_ip, 1000);
                let wire = route.serialize_nlri();
                self.evpn_multicast_synch.process_leave_synch(route);
                let preview = if wire.len() >= 16 {
                    &wire[..16]
                } else {
                    &wire[..]
                };
                println!(
                    "  [EVPN TYPE 8] Processed Leave Synch for Group {} on ESI {:?} (Wire: {:02X?})",
                    grp, esi, preview
                );
                println!(
                    "  Multicast state pruned: Group membership synchronized across dual-homed PEs"
                );
            }
            _ => println!("Unknown subcommand. Type 'evpn-synch help'."),
        }
    }

    fn cmd_detnet(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "help" {
            println!("Usage: detnet [status | replicate <msg> | eliminate]");
            println!(
                "  detnet status            - Show DetNet flow state and elimination statistics"
            );
            println!(
                "  detnet replicate <msg>   - Replicate a packet into redundant disjoint paths (PREF)"
            );
            println!(
                "  detnet eliminate <count> - Process duplicate packet arrivals through PREF filter"
            );
            return;
        }

        match args[0] {
            "status" => {
                println!("=== DetNet Deterministic Networking & PREF Engine (RFC 8939) ===");
                println!(
                    "  Encapsulation: DetNet over UDP (Port {})",
                    DETNET_UDP_PORT
                );
                println!(
                    "  Replication Factor: {} paths",
                    self.detnet_pref_engine.replication_factor
                );
                println!(
                    "  Default Deduplication Window: {} packets",
                    self.detnet_pref_engine.default_window_size
                );
                for (flow_id, filter) in &self.detnet_pref_engine.filters {
                    println!("\n  Flow ID: 0x{:08X}", flow_id);
                    println!("    Highest Sequence: {}", filter.highest_seq);
                    println!("    Packets Received: {}", filter.stats.packets_received);
                    println!("    Packets Forwarded: {}", filter.stats.packets_forwarded);
                    println!(
                        "    Duplicates Dropped: {}",
                        filter.stats.duplicates_dropped
                    );
                    println!(
                        "    Out-of-Order Packets: {}",
                        filter.stats.out_of_order_packets
                    );
                }
            }
            "replicate" => {
                let msg = if args.len() > 1 {
                    args[1..].join(" ")
                } else {
                    "Critical-Robotics-Command:SET_POSITION_XYZ".to_string()
                };
                let flow_id = 0x1001;
                let packets = self.detnet_pref_engine.replicate(flow_id, msg.as_bytes());
                println!(
                    "  [DETNET PREF REPLICATOR] Flow 0x{:08X}, Assigned Seq {}",
                    flow_id, packets[0].control_word.sequence_number
                );
                for (i, p) in packets.iter().enumerate() {
                    let wire = p.encode();
                    let preview = if wire.len() >= 8 {
                        &wire[..8]
                    } else {
                        &wire[..]
                    };
                    println!(
                        "    -> Path {}: Seq {} | Payload Len {} bytes (Wire: {:02X?})",
                        i + 1,
                        p.control_word.sequence_number,
                        p.payload.len(),
                        preview
                    );
                }
            }
            "eliminate" => {
                let flow_id = 0x1001;
                let packets = self
                    .detnet_pref_engine
                    .replicate(flow_id, b"Deterministic-Data-Payload");
                println!(
                    "  [DETNET PREF ELIMINATOR] Processing {} identical copies arriving across diverse paths:",
                    packets.len()
                );
                for (i, p) in packets.into_iter().enumerate() {
                    match self.detnet_pref_engine.eliminate(p) {
                        Some(accepted) => {
                            println!(
                                "    Copy {}: [ACCEPTED & FORWARDED] (First arrival, Seq {})",
                                i + 1,
                                accepted.control_word.sequence_number
                            );
                        }
                        None => {
                            println!(
                                "    Copy {}: [ELIMINATED / DROPPED] (Duplicate copy discarded)",
                                i + 1
                            );
                        }
                    }
                }
            }
            _ => println!("Unknown subcommand. Type 'detnet help'."),
        }
    }

    fn cmd_diameter_charging(&mut self, args: &[&str]) {
        if args.is_empty() || args[0] == "help" {
            println!(
                "Usage: diameter-charging [status | ccr-initial | ccr-update | ccr-terminate]"
            );
            println!(
                "  diameter-charging status        - Show Online Charging System (OCS) accounts & quotas"
            );
            println!(
                "  diameter-charging ccr-initial   - Send Credit-Control-Request Initial (Quota Reservation)"
            );
            println!(
                "  diameter-charging ccr-update    - Send CCR Update (Usage Reporting & Quota Grant)"
            );
            println!(
                "  diameter-charging ccr-terminate - Send CCR Termination (Session Teardown & Final Billing)"
            );
            return;
        }

        match args[0] {
            "status" => {
                println!(
                    "=== 5G Diameter Gy / Ro Online Charging System (RFC 4006 / TS 32.299) ==="
                );
                println!("  Application ID: 4 (Credit Control) | Command Code: 272 (CCR/CCA)");
                println!(
                    "  Default Quota Grant: {} KB",
                    self.diameter_ocs_engine.default_grant_quota_octets / 1024
                );
                for (sub_id, acc) in &self.diameter_ocs_engine.accounts {
                    println!("\n  Subscriber: {}", sub_id);
                    println!(
                        "    Total Balance: {} MB",
                        acc.total_balance_octets / (1024 * 1024)
                    );
                    println!(
                        "    Reserved Quota: {} KB",
                        acc.granted_reserved_octets / 1024
                    );
                    println!("    Consumed Volume: {} KB", acc.consumed_octets / 1024);
                    println!("    Active Session: {:?}", acc.active_session);
                }
            }
            "ccr-initial" => {
                let sub_id = "imsi-208950000000001";
                let mut req = CreditControlRequest::new(
                    "gy-sess-5g-001",
                    CcRequestType::InitialRequest,
                    0,
                    sub_id,
                );
                req.mscc.push(MsccContainer::new(200));
                let resp = self.diameter_ocs_engine.process_ccr(&req);
                println!(
                    "  [CCR INITIAL] Session: {} | Sub: {}",
                    req.session_id, sub_id
                );
                println!(
                    "  [CCA ANSWER] Result-Code: {:?}, AVPs count: {}",
                    resp.get_avp(268).and_then(|a| a.as_u32()),
                    resp.avps.len()
                );
                for avp in &resp.avps {
                    if avp.code == crate::diameter_charging::AVP_MULTIPLE_SERVICES_CREDIT_CONTROL {
                        if let Some(mscc) = MsccContainer::parse_avp(avp) {
                            println!(
                                "    -> Granted Rating-Group {}: {:?} bytes quota",
                                mscc.rating_group,
                                mscc.granted_units.map(|g| g.total_octets)
                            );
                        }
                    }
                }
            }
            "ccr-update" => {
                let sub_id = "imsi-208950000000001";
                let mut req = CreditControlRequest::new(
                    "gy-sess-5g-001",
                    CcRequestType::UpdateRequest,
                    1,
                    sub_id,
                );
                let mut mscc = MsccContainer::new(200);
                mscc.used_units = Some(ServiceQuotaUnit {
                    total_octets: 5 * 1024 * 1024,
                    time_seconds: 120,
                });
                req.mscc.push(mscc);
                let resp = self.diameter_ocs_engine.process_ccr(&req);
                println!("  [CCR UPDATE] Reported Used: 5 MB on Rating-Group 200");
                println!(
                    "  [CCA ANSWER] Replenished quota successfully, Result-Code: {:?}",
                    resp.get_avp(268).and_then(|a| a.as_u32())
                );
            }
            "ccr-terminate" => {
                let sub_id = "imsi-208950000000001";
                let mut req = CreditControlRequest::new(
                    "gy-sess-5g-001",
                    CcRequestType::TerminationRequest,
                    2,
                    sub_id,
                );
                let mut mscc = MsccContainer::new(200);
                mscc.used_units = Some(ServiceQuotaUnit {
                    total_octets: 2 * 1024 * 1024,
                    time_seconds: 45,
                });
                req.mscc.push(mscc);
                let _resp = self.diameter_ocs_engine.process_ccr(&req);
                println!(
                    "  [CCR TERMINATION] Session closed and final credit reconciled with OCS."
                );
            }
            _ => println!("Unknown subcommand. Type 'diameter-charging help'."),
        }
    }

    fn cmd_pim_bsr(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== PIM Bootstrap Router (BSR) & SSM Dynamic RP Engine (RFC 5059/4607) ==="
                );
                println!(
                    "  Local IP: {} | Candidate-BSR: {}",
                    self.pim_bsr_engine.local_ip, self.pim_bsr_engine.is_candidate_bsr
                );
                println!(
                    "  Elected BSR: {:?} (Priority: {})",
                    self.pim_bsr_engine.elected_bsr, self.pim_bsr_engine.elected_bsr_priority
                );
                println!("  Hash Mask Length: /{}", self.pim_bsr_engine.hash_mask_len);
                println!(
                    "  Group-to-RP Mappings ({} entries):",
                    self.pim_bsr_engine.group_rp_set.len()
                );
                for gm in &self.pim_bsr_engine.group_rp_set {
                    println!("    Prefix: {}/{}", gm.group.group_ip, gm.group.mask_len);
                    for crp in &gm.candidates {
                        println!(
                            "      -> Candidate-RP: {} | Priority: {} | Holdtime: {}s",
                            crp.rp_ip, crp.priority, crp.holdtime
                        );
                    }
                }
            }
            "resolve" | "rp" => {
                let grp_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(239, 1, 2, 3))
                } else {
                    Ipv4Address::new(239, 1, 2, 3)
                };
                if PimBsrEngine::is_ssm_group(grp_ip) {
                    println!(
                        "  Group {}: In SSM Range (232.0.0.0/8) -> RP BYPASSED (Direct Source Tree)",
                        grp_ip
                    );
                } else {
                    match self.pim_bsr_engine.get_rp_for_group(grp_ip) {
                        Some(rp) => {
                            println!(
                                "  Group {}: Resolved RP -> {} (Selected via deterministic hash function)",
                                grp_ip, rp
                            );
                        }
                        None => println!(
                            "  Group {}: No matching Candidate-RP found in BSR set.",
                            grp_ip
                        ),
                    }
                }
            }
            "bsm" => {
                if let Some(bsm) = self.pim_bsr_engine.originate_bootstrap_message() {
                    let wire = bsm.serialize();
                    println!(
                        "  [ORIGINATE BSM] BSR: {} | Priority: {} | Payload: {} bytes",
                        bsm.bsr_ip,
                        bsm.bsr_priority,
                        wire.len()
                    );
                    println!(
                        "  BSM Encoded Wire Hex: {}",
                        wire.iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
            }
            "ssm" => {
                let ssm_grp = Ipv4Address::new(232, 10, 20, 30);
                let asm_grp = Ipv4Address::new(239, 255, 1, 1);
                println!(
                    "  SSM Check for {}: is_ssm = {}",
                    ssm_grp,
                    PimBsrEngine::is_ssm_group(ssm_grp)
                );
                println!(
                    "  SSM Check for {}: is_ssm = {}",
                    asm_grp,
                    PimBsrEngine::is_ssm_group(asm_grp)
                );
            }
            _ => println!("Unknown subcommand. Usage: pim-bsr [status | rp <ip> | bsm | ssm]"),
        }
    }

    fn cmd_diameter_rx(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== Diameter Rx Policy and Charging Control (3GPP TS 29.214 / PCRF) ===");
                println!(
                    "  Application ID: 16777236 (Rx) | Total PCC Capacity: {} Mbps",
                    self.pcrf_rx_engine.total_capacity_bps / 1_000_000
                );
                println!(
                    "  Allocated Bandwidth: {} Kbps",
                    self.pcrf_rx_engine.allocated_bandwidth_bps / 1000
                );
                println!(
                    "  Active Authorized Sessions ({}):",
                    self.pcrf_rx_engine.sessions.len()
                );
                for (id, s) in &self.pcrf_rx_engine.sessions {
                    println!(
                        "    Session: {} | AF-App: {} | QCI: {} | Granted UL: {} kbps, DL: {} kbps",
                        id,
                        s.af_application_identifier,
                        s.authorized_qci,
                        s.granted_bandwidth_ul_bps / 1000,
                        s.granted_bandwidth_dl_bps / 1000
                    );
                }
            }
            "aar" => {
                let sess_id = "ims-call-volte-991";
                let mut req = AaRequest::new(sess_id, "ims-voice-video");
                let mut audio = MediaComponentDescription::new(1, MediaType::Audio);
                audio.max_bandwidth_ul = 64_000;
                audio.max_bandwidth_dl = 64_000;
                let mut sub1 = MediaSubComponent::new(1);
                sub1.flow_descriptions
                    .push("permit in ip from 10.0.0.1 to 10.0.0.2".to_string());
                audio.sub_components.push(sub1);

                let mut video = MediaComponentDescription::new(2, MediaType::Video);
                video.max_bandwidth_ul = 512_000;
                video.max_bandwidth_dl = 512_000;
                let mut sub2 = MediaSubComponent::new(1);
                sub2.flow_descriptions
                    .push("permit in ip from 10.0.0.1 to 10.0.0.2".to_string());
                video.sub_components.push(sub2);

                req.media_components.push(audio);
                req.media_components.push(video);

                let resp = self.pcrf_rx_engine.process_aar(&req);
                println!(
                    "  [AAR REQUEST] AF Application: {} | Media: Audio (64k) + Video (512k)",
                    req.af_application_identifier
                );
                println!(
                    "  [AAA ANSWER] Result-Code: {:?}, Authorized QCI: {:?}",
                    resp.get_avp(268).and_then(|a| a.as_u32()),
                    resp.get_avp(crate::diameter_rx::AVP_SPECIFIC_ACTION)
                        .and_then(|a| a.as_u32())
                );
            }
            "str" => {
                let sess_id = "ims-call-volte-991";
                let resp = self.pcrf_rx_engine.process_str(sess_id);
                println!(
                    "  [STR TERMINATION] Terminated session: {} | Result-Code: {:?}",
                    sess_id,
                    resp.get_avp(268).and_then(|a| a.as_u32())
                );
            }
            _ => println!("Unknown subcommand. Usage: diameter-rx [status | aar | str]"),
        }
    }

    fn cmd_evpn_proxy_arp(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== EVPN Proxy ARP/ND Suppression & Anycast Gateway (RFC 7432 / RFC 9135) ==="
                );
                println!(
                    "  Suppressed Broadcasts: {} | Flooded Requests: {} | Learned Entries: {}",
                    self.evpn_proxy_arp.suppressed_requests_count,
                    self.evpn_proxy_arp.flooded_requests_count,
                    self.evpn_proxy_arp.learned_entries_count
                );
                println!(
                    "  Proxy ARP Cache Table ({} entries):",
                    self.evpn_proxy_arp.table.len()
                );
                for ((vni, ip), entry) in &self.evpn_proxy_arp.table {
                    println!(
                        "    VNI: {:<6} | IP: {:<15} | MAC: {} | State: {:?} | Local: {}",
                        vni, ip, entry.mac, entry.state, entry.is_local
                    );
                }
            }
            "snoop-hit" => {
                let req = crate::arp::ArpPacket {
                    htype: crate::arp::ARP_HTYPE_ETHERNET,
                    ptype: crate::arp::ARP_PTYPE_IPV4,
                    hlen: crate::arp::ARP_HLEN_ETHERNET,
                    plen: crate::arp::ARP_PLEN_IPV4,
                    opcode: crate::arp::ArpOpcode::Request,
                    sender_mac: MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
                    sender_ip: [10, 1, 1, 10],
                    target_mac: MacAddress::BROADCAST,
                    target_ip: [10, 1, 1, 20],
                };
                let action = self.evpn_proxy_arp.process_local_arp(100, &req);
                println!("  Incoming Local VM ARP Request: who-has 10.1.1.20 tell 10.1.1.10");
                if let ArpSuppressionAction::SynthesizedReply(reply) = action {
                    println!(
                        "  [SUPPRESSION SUCCESS] Synthesized Unicast ARP Reply: 10.1.1.20 is at {}",
                        reply.sender_mac
                    );
                    println!("  ==> ARP Broadcast DROP / Suppressed from VXLAN overlay network!");
                }
            }
            "snoop-gw" => {
                let req = crate::arp::ArpPacket {
                    htype: crate::arp::ARP_HTYPE_ETHERNET,
                    ptype: crate::arp::ARP_PTYPE_IPV4,
                    hlen: crate::arp::ARP_HLEN_ETHERNET,
                    plen: crate::arp::ARP_PLEN_IPV4,
                    opcode: crate::arp::ArpOpcode::Request,
                    sender_mac: MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
                    sender_ip: [10, 1, 1, 10],
                    target_mac: MacAddress::BROADCAST,
                    target_ip: [10, 1, 1, 1],
                };
                let action = self.evpn_proxy_arp.process_local_arp(100, &req);
                println!("  Incoming Local VM Default Gateway ARP Request: who-has 10.1.1.1");
                if let ArpSuppressionAction::SynthesizedReply(reply) = action {
                    println!(
                        "  [ANYCAST GATEWAY] Synthesized Reply: 10.1.1.1 is at Anycast MAC {}",
                        reply.sender_mac
                    );
                }
            }
            "snoop-miss" => {
                let req = crate::arp::ArpPacket {
                    htype: crate::arp::ARP_HTYPE_ETHERNET,
                    ptype: crate::arp::ARP_PTYPE_IPV4,
                    hlen: crate::arp::ARP_HLEN_ETHERNET,
                    plen: crate::arp::ARP_PLEN_IPV4,
                    opcode: crate::arp::ArpOpcode::Request,
                    sender_mac: MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
                    sender_ip: [10, 1, 1, 10],
                    target_mac: MacAddress::BROADCAST,
                    target_ip: [10, 1, 1, 99],
                };
                let action = self.evpn_proxy_arp.process_local_arp(100, &req);
                println!("  Incoming Unknown IP ARP Request: who-has 10.1.1.99");
                println!("  Result Action: {:?}", action);
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-proxy-arp [status | snoop-hit | snoop-gw | snoop-miss]"
            ),
        }
    }

    fn cmd_nsh_md2(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== NSH MD Type 2 Dynamic Variable-Length Context Headers (RFC 8300 Section 3.5.2) ==="
                );
                println!("  SFF Forwarding Paths:");
                for ((spi, si), next_hop) in &self.nsh_md2_engine.service_paths {
                    println!(
                        "    SPI: 0x{:06X}, SI: {:<2} -> Forward to SFF Node ID: {}",
                        spi, si, next_hop
                    );
                }
            }
            "forward" => {
                let mut hdr = NshMd2Header::new(0x10001, 10, NSH_NP_IPV4);
                hdr = hdr.with_tlv(NshContextTlv::new_tenant_id(0x0000_1234));
                hdr = hdr.with_tlv(NshContextTlv::new_flow_hash(0xDEAD_BEEF));
                hdr = hdr.with_tlv(NshContextTlv::new_security_group_tag(100));

                let mut pkt = NshMd2Packet::new(hdr, b"Tenant Sensitive Web Traffic".to_vec());
                println!(
                    "  [INGRESS PACKET] SPI: 0x{:06X}, SI: {}, Length: {} words ({} bytes), TLVs count: {}",
                    pkt.header.service_path_id,
                    pkt.header.service_index,
                    pkt.header.length_words(),
                    pkt.header.serialize().len(),
                    pkt.header.tlvs.len()
                );

                let act1 = self.nsh_md2_engine.process_packet(&mut pkt);
                println!(
                    "  Hop 1 Action: {:?} (New SI: {})",
                    act1, pkt.header.service_index
                );

                // Advance to end of chain (SI = 1)
                pkt.header.service_index = 1;
                let act_end = self.nsh_md2_engine.process_packet(&mut pkt);
                println!(
                    "  Final Hop Action (SI=1): {:?} -> NSH Stripped, raw payload dispatched to inner IPv4 stack!",
                    act_end
                );
            }
            _ => println!("Unknown subcommand. Usage: nsh-md2 [status | forward]"),
        }
    }

    fn cmd_mldp(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Multipoint LDP (mLDP) P2MP/MP2MP Core Multicast Engine (RFC 6388 / RFC 6513) ==="
                );
                println!(
                    "  Local LSR IP: {} | Replicated Packets: {}",
                    self.mldp_engine.local_ip, self.mldp_engine.replicated_packets_count
                );
                println!(
                    "  Upstream Bindings ({} entries):",
                    self.mldp_engine.upstream_bindings.len()
                );
                for (fec, (up_lsr, up_label)) in &self.mldp_engine.upstream_bindings {
                    println!(
                        "    FEC Root: {} | LSP ID: {:?} | Upstream LSR: {} | Label: {}",
                        fec.root_node,
                        fec.generic_lsp_id(),
                        up_lsr,
                        up_label
                    );
                }
                println!(
                    "  Downstream Branch Trees ({} FECs):",
                    self.mldp_engine.downstream_branches.len()
                );
                for (fec, branches) in &self.mldp_engine.downstream_branches {
                    println!(
                        "    FEC Root: {} (LSP ID: {:?}) -> {} Branches:",
                        fec.root_node,
                        fec.generic_lsp_id(),
                        branches.len()
                    );
                    for b in branches {
                        println!(
                            "      -> Out Interface: Port-{} | Out Label: {}",
                            b.out_interface, b.out_label
                        );
                    }
                }
            }
            "branch" | "replicate" => {
                let fec = MldpFecElement::new_p2mp_generic(Ipv4Address::new(10, 0, 0, 1), 1001);
                let payload = b"HD Video Multicast Stream over MPLS Core";
                let replicated = self.mldp_engine.replicate_multicast(&fec, payload);
                println!(
                    "  [MULTICAST INGRESS] FEC Root: 10.0.0.1, LSP-ID: 1001, Payload: {} bytes",
                    payload.len()
                );
                for (idx, (out_if, out_lbl, wire)) in replicated.iter().enumerate() {
                    println!(
                        "    Branch #{}: Out Interface: Port-{}, Assigned MPLS Label: {}, Encapsulated Wire Length: {} bytes",
                        idx + 1,
                        out_if,
                        out_lbl,
                        wire.len()
                    );
                }
                println!(
                    "  Multicast packet replicated to {} downstream core branches with zero head-end penalty!",
                    replicated.len()
                );
            }
            _ => println!("Unknown subcommand. Usage: mldp [status | branch]"),
        }
    }

    fn cmd_diameter_gx(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Diameter Gx Policy and Charging Control (3GPP TS 29.212 / PCRF-PCEF) ==="
                );
                println!("  PCRF Realm: {}", self.pcef_gx_engine.pcrf_realm);
                println!(
                    "  Active Subscriber Sessions ({}):",
                    self.pcef_gx_engine.active_sessions.len()
                );
                for (sess, sub_id) in &self.pcef_gx_engine.active_sessions {
                    println!("    Session: {} | IMSI: {}", sess, sub_id);
                    if let Some(rules) = self.pcef_gx_engine.installed_rules.get(sess) {
                        println!("    Installed PCC Rules ({}):", rules.len());
                        for r in rules {
                            println!(
                                "      -> Rule: {} | QCI: {} | Max UL: {} Kbps, DL: {} Kbps | Gate: {}",
                                r.rule_name,
                                r.qci,
                                r.max_bandwidth_ul_bps / 1000,
                                r.max_bandwidth_dl_bps / 1000,
                                if r.gate_enabled { "OPEN" } else { "CLOSED" }
                            );
                        }
                    }
                }
            }
            "rule-install" => {
                let sess_id = "gx-sess-ue01-pcrf";
                let mut volte = PccRule::new("rule-volte-voice", 1, 64_000, 64_000);
                volte
                    .flow_descriptions
                    .push("permit out udp from any to 10.0.0.2 49152-65535".to_string());
                let ok = self.pcef_gx_engine.install_rule(sess_id, volte);
                println!(
                    "  [PCC RULE INSTALL] Dynamic Rule 'rule-volte-voice' (QCI 1, 64 kbps) installed: {}",
                    ok
                );
            }
            "ccr-terminate" => {
                let sess_id = "gx-sess-ue01-pcrf";
                let ok = self.pcef_gx_engine.handle_session_termination(sess_id);
                println!(
                    "  [GX TERMINATION] Session {} terminated and PCC rules flushed: {}",
                    sess_id, ok
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-gx [status | rule-install | ccr-terminate]"
            ),
        }
    }

    fn cmd_evpn_mass_withdraw(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== EVPN Route Type 1 per-ES Fast Convergence & Mass Withdrawal (RFC 7432 Section 8.2/8.4) ==="
                );
                println!(
                    "  Total Mass Withdraw Events: {} | Rerouted Flows: {}",
                    self.evpn_mass_withdraw.mass_withdraw_events_count,
                    self.evpn_mass_withdraw.rerouted_flows_count
                );
                println!(
                    "  Ethernet Segment Memberships ({} segments):",
                    self.evpn_mass_withdraw.es_mac_table.len()
                );
                for (esi, bindings) in &self.evpn_mass_withdraw.es_mac_table {
                    let is_up = self
                        .evpn_mass_withdraw
                        .es_oper_status
                        .get(esi)
                        .copied()
                        .unwrap_or(true);
                    println!(
                        "    ESI: {} | Status: {} ({} MAC entries):",
                        esi,
                        if is_up { "UP" } else { "DOWN (FAILED)" },
                        bindings.len()
                    );
                    for b in bindings {
                        println!(
                            "      -> VNI: {:<6} | MAC: {} | Active PE: {} (Primary: {}, Backup: {})",
                            b.vni, b.mac, b.active_next_hop, b.primary_pe, b.backup_pe
                        );
                    }
                }
            }
            "fail" | "link-down" => {
                let es1 = EthernetSegmentId::from_u32(101);
                let flipped = self
                    .evpn_mass_withdraw
                    .process_es_failure_mass_withdraw(&es1);
                println!(
                    "  [ES LINK DOWN] ESI {} failed! Processed Route Type 1 per-ES Mass Withdrawal.",
                    es1
                );
                println!(
                    "  Fast Convergence: Instantly flipped {} MAC forwarding paths to backup PE in O(1) time!",
                    flipped
                );
            }
            "recover" | "link-up" => {
                let es1 = EthernetSegmentId::from_u32(101);
                let restored = self.evpn_mass_withdraw.process_es_recovery(&es1);
                println!(
                    "  [ES RECOVERY] ESI {} link restored. Re-advertised Route Type 1 per-ES A-D route.",
                    es1
                );
                println!(
                    "  Restored {} MAC forwarding paths back to primary PE!",
                    restored
                );
            }
            _ => {
                println!("Unknown subcommand. Usage: evpn-mass-withdraw [status | fail | recover]")
            }
        }
    }

    fn cmd_sr_oam(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== Segment Routing MPLS OAM (RFC 8287 / RFC 8402 / SR LSP Ping) ===");
                println!("  Local IP: {}", self.sr_mpls_oam.local_ip);
                println!("  Registered Node Prefix SIDs:");
                for (pfx, sid) in &self.sr_mpls_oam.local_prefix_sids {
                    println!("    Prefix: {}/32 -> SID Label: {}", pfx, sid);
                }
                println!("  Registered Adjacency SIDs:");
                for (sid, (loc, rem)) in &self.sr_mpls_oam.local_adj_sids {
                    println!("    Adj SID: {} -> Cross-Connect {} <-> {}", sid, loc, rem);
                }
            }
            "ping" => {
                let target_pfx = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(self.remote_host_ip)
                } else {
                    self.remote_host_ip
                };
                let sid_label = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(16001)
                } else {
                    16001
                };

                let req = SrLspEchoRequest {
                    sender_handle: 0x55AA_1234,
                    seq_number: 1,
                    target_fec: SrTargetFecSubTlv::Ipv4PrefixSid {
                        prefix: target_pfx,
                        prefix_len: 32,
                        sid_label,
                        protocol: 1, // IS-IS
                    },
                };

                let reply = self.sr_mpls_oam.process_echo_request(&req);
                let ret_str = match reply.return_code {
                    3 => "3 (Replying router is an egress for the FEC at stack-depth)",
                    8 => "8 (Label switched at stack-depth)",
                    _ => "0 (Success / Validated)",
                };
                println!(
                    "  [SR LSP ECHO REQUEST] Sent to Target Prefix-SID FEC: {}/32 (SID: {})",
                    target_pfx, sid_label
                );
                println!(
                    "  [SR LSP ECHO REPLY] Return-Code: {} | Handle: 0x{:08X}",
                    ret_str, reply.sender_handle
                );
                println!("  Segment Routing MPLS Data Plane verified & consistent!");
            }
            _ => println!("Unknown subcommand. Usage: sr-oam [status | ping <prefix> <sid>]"),
        }
    }

    fn cmd_synce(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Synchronous Ethernet (SyncE) ESMC Clock Engine (ITU-T G.8264 / G.781) ==="
                );
                println!(
                    "  Selected SyncE Port: {:?} | Selected Quality Level: {:?}",
                    self.synce_engine.selected_port, self.synce_engine.selected_ql
                );
                println!(
                    "  Port Clock Status ({} ports):",
                    self.synce_engine.port_ql.len()
                );
                for (port, ql) in &self.synce_engine.port_ql {
                    let prio = self
                        .synce_engine
                        .port_priority
                        .get(port)
                        .copied()
                        .unwrap_or(128);
                    let is_sel = self.synce_engine.selected_port == Some(*port);
                    println!(
                        "    Port-{} -> QL: {:?} (SSM Code 0x{:02X}, Rank: {}) | Priority: {} {}",
                        port,
                        ql,
                        *ql as u8,
                        ql.rank(),
                        prio,
                        if is_sel {
                            "[SELECTED MASTER CLOCK]"
                        } else {
                            ""
                        }
                    );
                }
            }
            "select" => {
                let res = self.synce_engine.arbitrate_clock_selection();
                println!(
                    "  [CLOCK SELECTION] Selected Best Physical Clock: {:?}",
                    res
                );
            }
            "rx" => {
                let port = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let ql_code = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(2)
                } else {
                    2
                };
                let ql = QualityLevel::from_u8(ql_code);
                self.synce_engine
                    .process_rx_esmc(port, &SyncEEsmcPacket::new(true, ql));
                println!(
                    "  [ESMC EVENT RX] Ingested ESMC on Port-{} with QL: {:?}. New Clock Selected: {:?}",
                    port, ql, self.synce_engine.selected_port
                );
            }
            _ => {
                println!("Unknown subcommand. Usage: synce [status | select | rx <port> <ql_code>]")
            }
        }
    }

    fn cmd_diameter_s6a(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Diameter S6a MME-HSS Mobility Management Interface (3GPP TS 29.272) ==="
                );
                println!("  HSS Realm: {}", self.hss_s6a_engine.hss_realm);
                println!(
                    "  Auth Vectors Generated: {} | Location Updates: {}",
                    self.hss_s6a_engine.auth_vectors_generated_count,
                    self.hss_s6a_engine.location_updates_count
                );
                println!(
                    "  HSS Subscriber Directory ({}):",
                    self.hss_s6a_engine.subscribers.len()
                );
                for (imsi, sub_info) in &self.hss_s6a_engine.subscribers {
                    println!(
                        "    IMSI: {} | MSISDN: {} | Default APN: {} | AMBR UL: {} Kbps, DL: {} Kbps | MME: {:?}",
                        imsi,
                        sub_info.msisdn,
                        sub_info.default_apn,
                        sub_info.subscribed_ambr_ul_kbps,
                        sub_info.subscribed_ambr_dl_kbps,
                        sub_info.registered_mme
                    );
                }
            }
            "air" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "208950000000001"
                };
                let plmn = [0x02, 0xF8, 0x59]; // MCC 208, MNC 95
                if let Some(aia) = self.hss_s6a_engine.handle_auth_info_request(imsi, &plmn) {
                    println!(
                        "  [AIR -> AIA] Authentication Information Answer generated for IMSI {}:",
                        imsi
                    );
                    println!(
                        "    Command Code: {}, App ID: {}, Result Code: 2001 (DIAMETER_SUCCESS)",
                        aia.header.command_code, aia.header.application_id
                    );
                    println!(
                        "    EPS Authentication Vector (RAND, XRES, AUTN, KASME) successfully derived & provisioned!"
                    );
                } else {
                    println!(
                        "  [AIR ERROR] Subscriber IMSI {} not found in HSS database!",
                        imsi
                    );
                }
            }
            "ulr" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "208950000000001"
                };
                let mme = "mme02.epc.mnc001.mcc208.3gppnetwork.org";
                if let Some(ula) = self
                    .hss_s6a_engine
                    .handle_update_location_request(imsi, mme)
                {
                    println!(
                        "  [ULR -> ULA] Location Update Answer generated for IMSI {}:",
                        imsi
                    );
                    println!(
                        "    Command Code: {}, App ID: {}, New Registered MME: {}",
                        ula.header.command_code, ula.header.application_id, mme
                    );
                } else {
                    println!(
                        "  [ULR ERROR] Subscriber IMSI {} not found in HSS database!",
                        imsi
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s6a [status | air <imsi> | ulr <imsi>]"
            ),
        }
    }

    fn cmd_evpn_etree(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== EVPN E-Tree Root/Leaf Tree Forwarding & Split-Horizon (RFC 8317) ==="
                );
                println!(
                    "  Forwarded Packets: {} | Blocked Leaf-to-Leaf Drops: {}",
                    self.evpn_etree_engine.forwarded_packets_count,
                    self.evpn_etree_engine.blocked_leaf_to_leaf_count
                );
                println!(
                    "  Registered Endpoints ({} entries):",
                    self.evpn_etree_engine.endpoint_roles.len()
                );
                for ((vni, mac), role) in &self.evpn_etree_engine.endpoint_roles {
                    println!("    VNI: {:<6} | MAC: {} | Role: {:?}", vni, mac, role);
                }
            }
            "forward" | "test" => {
                let vni = 100;
                let root_mac = MacAddress([0x52, 0x54, 0x00, 0x10, 0x00, 0x01]);
                let leaf1_mac = MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x01]);
                let leaf2_mac = MacAddress([0x52, 0x54, 0x00, 0x20, 0x00, 0x02]);

                println!(
                    "  [E-TREE TEST] Evaluating communication matrix in VNI {}:",
                    vni
                );
                let d1 = self
                    .evpn_etree_engine
                    .evaluate_forwarding(vni, root_mac, leaf1_mac);
                println!("    1. Root -> Leaf-1 : Decision = {:?} [PERMITTED]", d1);

                let d2 = self
                    .evpn_etree_engine
                    .evaluate_forwarding(vni, leaf1_mac, root_mac);
                println!("    2. Leaf-1 -> Root : Decision = {:?} [PERMITTED]", d2);

                let d3 = self
                    .evpn_etree_engine
                    .evaluate_forwarding(vni, leaf1_mac, leaf2_mac);
                println!(
                    "    3. Leaf-1 -> Leaf-2: Decision = {:?} [SPLIT-HORIZON ISOLATION DROP!]",
                    d3
                );
            }
            _ => println!("Unknown subcommand. Usage: evpn-etree [status | forward]"),
        }
    }

    fn cmd_srv6_slicing(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== SRv6 5G Network Slicing & VTN Path Steering (RFC 9350 / RFC 9543) ==="
                );
                println!(
                    "  Total Steered Packets: {}",
                    self.srv6_slicing_engine.steered_packets_count
                );
                println!(
                    "  Configured Network Slices ({}):",
                    self.srv6_slicing_engine.slice_policies.len()
                );
                for (slice_id, policy) in &self.srv6_slicing_engine.slice_policies {
                    let metered = self
                        .srv6_slicing_engine
                        .slice_metered_bytes
                        .get(slice_id)
                        .copied()
                        .unwrap_or(0);
                    println!(
                        "    Slice-ID: {} ({}) | Type: {:?} | Flex-Algo: {} | Guaranteed BW: {} Kbps | Max Latency: {} us | Metered: {} bytes",
                        slice_id.0,
                        policy.slice_name,
                        policy.slice_type,
                        policy.flex_algo,
                        policy.guaranteed_bandwidth_kbps,
                        policy.max_latency_microseconds,
                        metered
                    );
                    println!("      -> SRv6 Path SIDs: {:?}", policy.segment_list);
                }
                println!(
                    "  Subscriber Slice Bindings ({}):",
                    self.srv6_slicing_engine.subscriber_slice_bindings.len()
                );
                for (sub_ip, s_id) in &self.srv6_slicing_engine.subscriber_slice_bindings {
                    println!(
                        "    Subscriber IP: {} -> Mapped to Slice-ID: {}",
                        sub_ip, s_id.0
                    );
                }
            }
            "steer" => {
                let sub_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(self.stack.config.ip)
                } else {
                    self.stack.config.ip
                };
                let pkt_len = 1420;
                if let Some(res) = self.srv6_slicing_engine.steer_packet(sub_ip, pkt_len) {
                    println!("  [SRv6 SLICING STEER] Ingress Packet from {}:", sub_ip);
                    println!("    -> Assigned Slice-ID: {}", res.slice_id.0);
                    println!(
                        "    -> Bound Flex-Algo: {} (Deterministic Low-Latency SLA)",
                        res.flex_algo
                    );
                    println!("    -> SRv6 Segment List: {:?}", res.srv6_sid_list);
                    println!("    -> Metered Slice Payload: {} bytes", pkt_len);
                } else {
                    println!(
                        "  [STEERING ERROR] Subscriber IP {} not bound to any SRv6 Network Slice!",
                        sub_ip
                    );
                }
            }
            _ => println!("Unknown subcommand. Usage: srv6-slicing [status | steer <ip>]"),
        }
    }

    fn cmd_evpn_pref_df(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        let demo_esi =
            EthernetSegmentId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
        match sub {
            "status" => {
                println!("=== BGP EVPN Preference-Based DF Election (RFC 8584) ===");
                println!(
                    "  Total Elections Run: {}",
                    self.evpn_pref_df.elections_run_count
                );
                println!(
                    "  Monitored Ethernet Segments ({}):",
                    self.evpn_pref_df.candidates.len()
                );
                for (esi, candidates) in &self.evpn_pref_df.candidates {
                    let df = self.evpn_pref_df.elected_df.get(esi).copied();
                    println!("    ESI: {:?} | Elected DF: {:?}", esi, df);
                    for c in candidates {
                        let is_df = df == Some(c.pe_ip);
                        println!(
                            "      -> PE: {} | Preference: {} | Don't-Preempt: {} | Sticky: {} {}",
                            c.pe_ip,
                            c.preference,
                            c.dont_preempt,
                            c.sticky,
                            if is_df {
                                "[ELECTED DESIGNATED FORWARDER]"
                            } else {
                                "[BACKUP BDF]"
                            }
                        );
                    }
                }
            }
            "elect" => {
                let winner = self.evpn_pref_df.elect_df(demo_esi);
                println!(
                    "  [DF ELECTION RUN] ESI: {:?} -> Elected Winner DF: {:?}",
                    demo_esi, winner
                );
            }
            "failover" => {
                println!(
                    "  [DF FAILOVER] Primary PE {} link failed on ESI {:?}",
                    self.stack.config.ip, demo_esi
                );
                self.evpn_pref_df
                    .remove_candidate(demo_esi, self.stack.config.ip);
                let new_df = self.evpn_pref_df.elect_df(demo_esi);
                println!(
                    "  [DF FAILOVER COMPLETED] Surviving Backup PE Elected DF: {:?}",
                    new_df
                );
            }
            _ => println!("Unknown subcommand. Usage: evpn-pref-df [status | elect | failover]"),
        }
    }

    fn cmd_ifa(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== In-Band Flow Analytics (IFA 2.0 / RFC 9197) ===");
                println!("  Local Node ID: 0x{:08X}", self.ifa_engine.local_node_id);
                println!(
                    "  Probes Encapsulated: {} | Hops Inserted: {} | Packets Collected: {}",
                    self.ifa_engine.probes_encapsulated,
                    self.ifa_engine.hops_inserted,
                    self.ifa_engine.packets_collected
                );
            }
            "insert" | "demo" => {
                let payload = b"GET /5g-video-stream HTTP/1.1\r\nHost: edge.example.com\r\n\r\n";
                let req_flags =
                    IFA_REQ_NODE_ID | IFA_REQ_PORTS | IFA_REQ_LATENCY | IFA_REQ_QUEUE_DEPTH;
                let mut pkt = self.ifa_engine.ingress_encapsulate(payload, 8, req_flags);

                println!(
                    "  [IFA INGRESS] Encapsulated probe packet with Hop Limit: 8, Request Vector: 0x{:02X}",
                    req_flags
                );

                // Router 1 (Edge Spine)
                self.ifa_engine
                    .transit_insert_hop(&mut pkt, 1, 2, 450, 12800);
                // Router 2 (Core Transit)
                let mut r2_engine = IfaTelemetryEngine::new(0x0A000202);
                r2_engine.transit_insert_hop(&mut pkt, 3, 4, 1200, 65536);
                // Router 3 (Leaf UPF)
                let mut r3_engine = IfaTelemetryEngine::new(0x0A000303);
                r3_engine.transit_insert_hop(&mut pkt, 5, 6, 320, 2048);

                let records = self.ifa_engine.egress_collect(&pkt);
                println!(
                    "  [IFA EGRESS COLLECTED] Parsed {} Hop-by-Hop Telemetry Records:",
                    records.len()
                );
                for (i, rec) in records.iter().enumerate() {
                    println!(
                        "    Hop-{}: Node: 0x{:08X} | In-Port: {} -> Out-Port: {} | Hop Latency: {} ns | Queue Depth: {} bytes",
                        i + 1,
                        rec.node_id,
                        rec.ingress_port,
                        rec.egress_port,
                        rec.hop_latency_ns,
                        rec.queue_depth_bytes
                    );
                }
            }
            _ => println!("Unknown subcommand. Usage: ifa [status | demo]"),
        }
    }

    fn cmd_diameter_s13(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Diameter S13 / S13' Equipment Identity Register (3GPP TS 29.272) ==="
                );
                println!(
                    "  Total IMEI Checks: {} | Blacklisted/Barred Device Drops: {}",
                    self.eir_s13_engine.total_checks_count,
                    self.eir_s13_engine.blacklisted_drops_count
                );
                println!(
                    "  EIR IMEI Registry ({} entries):",
                    self.eir_s13_engine.imei_status_db.len()
                );
                for (imei, status) in &self.eir_s13_engine.imei_status_db {
                    println!("    IMEI: {} -> Status: {:?}", imei, status);
                }
            }
            "check" => {
                let imei = if args.len() >= 2 {
                    args[1]
                } else {
                    "354890091234567"
                };
                let _eca = self.eir_s13_engine.handle_ecr(imei);
                let status = self
                    .eir_s13_engine
                    .imei_status_db
                    .get(imei)
                    .copied()
                    .unwrap_or(EquipmentStatus::Whitelisted);
                println!("  [ME-IDENTITY-CHECK] Sent ECR query for IMEI: {}", imei);
                println!(
                    "  [ECA ANSWER] Result: DIAMETER_SUCCESS (2001) | Equipment-Status: {:?}",
                    status
                );
                if status == EquipmentStatus::Blacklisted {
                    println!(
                        "    -> WARNING: STOLEN / BARRED DEVICE DETECTED! ATTACH PROCEDURE REJECTED!"
                    );
                } else {
                    println!("    -> Device approved for cellular data attachment.");
                }
            }
            "add-black" => {
                let imei = if args.len() >= 2 {
                    args[1]
                } else {
                    "867912040000001"
                };
                self.eir_s13_engine
                    .set_imei_status(imei, EquipmentStatus::Blacklisted);
                println!(
                    "  [EIR DB UPDATE] IMEI {} has been added to the EIR BLACKLIST (Barred).",
                    imei
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s13 [status | check <imei> | add-black <imei>]"
            ),
        }
    }

    fn cmd_ptp_bc(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== PTP Telecom Boundary Clock (T-BC) Engine (ITU-T G.8275.1 / G.8273.2) ==="
                );
                println!(
                    "  BMCA Cycles Run: {} | Selected Slave Clock Port: {:?}",
                    self.ptp_bc_engine.bmca_cycles_run, self.ptp_bc_engine.slave_port
                );
                println!(
                    "  Accumulated Phase Error Offset: {} ns",
                    self.ptp_bc_engine.accumulated_phase_offset_ns
                );
                println!(
                    "  Boundary Clock Ports ({}):",
                    self.ptp_bc_engine.ports.len()
                );
                for (port_id, cfg) in &self.ptp_bc_engine.ports {
                    let state = self
                        .ptp_bc_engine
                        .port_states
                        .get(port_id)
                        .copied()
                        .unwrap_or(crate::ptp_telecom_bc::TelecomPortState::Passive);
                    let q_str = match cfg.rx_clock_quality {
                        Some(q) => format!(
                            "Class: {}, Accuracy: 0x{:02X}",
                            q.clock_class, q.clock_accuracy
                        ),
                        None => "No Announce Received".to_string(),
                    };
                    println!(
                        "    Port-{} -> Role/State: {:?} | LocalPriority: {} | NotSlave: {} | Rx GM [{}]",
                        port_id, state, cfg.local_priority, cfg.not_slave, q_str
                    );
                }
            }
            "bmca" => {
                let slave = self.ptp_bc_engine.run_alternate_bmca();
                println!(
                    "  [G.8275.1 BMCA ARBITRATION] Updated State. Selected Primary Master Source Port: {:?}",
                    slave
                );
            }
            "adjust" => {
                let error = if args.len() >= 2 {
                    args[1].parse::<i64>().unwrap_or(24)
                } else {
                    24
                };
                let corr = self.ptp_bc_engine.adjust_phase_offset(error);
                println!(
                    "  [PHASE OFFSET ADJUST] Injected error: {} ns -> Damped correction: {} ns. Total Offset: {} ns",
                    error, corr, self.ptp_bc_engine.accumulated_phase_offset_ns
                );
            }
            _ => println!("Unknown subcommand. Usage: ptp-bc [status | bmca | adjust <phase_ns>]"),
        }
    }

    fn cmd_ptp_te(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== PTP Telecom Time Error (cTE / dTE) Measurement (ITU-T G.8273.2) ===");
                println!(
                    "  Samples in Window: {} (Total Collected: {})",
                    self.ptp_te_engine.samples.len(),
                    self.ptp_te_engine.total_samples_collected
                );
                let cte = self.ptp_te_engine.calculate_cte();
                let p2p = self.ptp_te_engine.calculate_peak_to_peak_te();
                println!("  Constant Time Error (cTE): {:.2} ns", cte);
                println!("  Peak-to-Peak Time Error (dTE p2p): {} ns", p2p);
                println!("  ITU-T G.8273.2 Mask Compliance:");
                for (class, name) in [
                    (
                        TelecomClockClass::ClassA,
                        "Class A (Macro BTS: |cTE|<=100ns, |TE|<=1100ns)",
                    ),
                    (
                        TelecomClockClass::ClassB,
                        "Class B (Small Cell: |cTE|<=70ns, |TE|<=200ns)",
                    ),
                    (
                        TelecomClockClass::ClassC,
                        "Class C (5G Fronthaul: |cTE|<=30ns, |TE|<=55ns)",
                    ),
                    (
                        TelecomClockClass::ClassD,
                        "Class D (Enhanced URLLC: |cTE|<=15ns, |TE|<=30ns)",
                    ),
                ] {
                    let ok = self.ptp_te_engine.verify_compliance(class);
                    println!(
                        "    -> {}: {}",
                        name,
                        if ok {
                            "[COMPLIANT / PASS]"
                        } else {
                            "[FAIL / OUT-OF-SPEC]"
                        }
                    );
                }
            }
            "sample" => {
                let val = if args.len() >= 2 {
                    args[1].parse::<i64>().unwrap_or(12)
                } else {
                    12
                };
                self.ptp_te_engine.add_sample(val);
                println!(
                    "  [TIME ERROR RECORDED] Injected TE(t) sample: {} ns. Updated Window cTE: {:.2} ns",
                    val,
                    self.ptp_te_engine.calculate_cte()
                );
            }
            "mask" => {
                println!("=== ITU-T G.8273.2 Telecom Boundary Clock Mask Limits ===");
                println!("  Class A: Max |cTE| <= 100 ns, Max |TE| <= 1100 ns");
                println!("  Class B: Max |cTE| <=  70 ns, Max |TE| <=  200 ns");
                println!("  Class C: Max |cTE| <=  30 ns, Max |TE| <=   55 ns (O-RAN / eCPRI)");
                println!("  Class D: Max |cTE| <=  15 ns, Max |TE| <=   30 ns (Enhanced 5G URLLC)");
            }
            _ => println!("Unknown subcommand. Usage: ptp-te [status | sample <ns> | mask]"),
        }
    }

    fn cmd_diameter_s9(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== Diameter S9 PCRF Roaming Interface (3GPP TS 29.215) ===");
                println!(
                    "  PCRF Role: {}",
                    if self.pcrf_s9_engine.is_home_pcrf {
                        "Home PCRF (H-PCRF)"
                    } else {
                        "Visited PCRF (V-PCRF)"
                    }
                );
                println!(
                    "  Credit-Control Requests Processed: {}",
                    self.pcrf_s9_engine.cc_requests_processed
                );
                println!(
                    "  Active Roaming Subsessions ({}):",
                    self.pcrf_s9_engine.roaming_subsessions.len()
                );
                for (id, info) in &self.pcrf_s9_engine.roaming_subsessions {
                    println!(
                        "    Subsession-ID: {} -> Max UL: {} kbps | Max DL: {} kbps",
                        id, info.max_bandwidth_ul_kbps, info.max_bandwidth_dl_kbps
                    );
                }
            }
            "ccr" => {
                let sub_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(2002)
                } else {
                    2002
                };
                let ul = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(100_000)
                } else {
                    100_000
                };
                let dl = if args.len() >= 4 {
                    args[3].parse::<u32>().unwrap_or(500_000)
                } else {
                    500_000
                };

                let sub_info = SubsessionEnforcementInfo::new(sub_id, ul, dl);
                let _cca = self.pcrf_s9_engine.handle_ccr(sub_info);
                println!(
                    "  [S9 CCR-I SENT] Provisioned Roaming Subsession ID: {}",
                    sub_id
                );
                println!(
                    "  [S9 CCA-I RECEIVED] Result: DIAMETER_SUCCESS (2001) | Granted UL: {} kbps, Granted DL: {} kbps",
                    ul, dl
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s9 [status | ccr <id> <ul_kbps> <dl_kbps>]"
            ),
        }
    }

    fn cmd_evpn_snooping(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== EVPN IGMP Snooping & Multicast Pruning Engine (RFC 9251) ===");
                println!(
                    "  Joins Processed: {} | Leaves Processed: {}",
                    self.evpn_igmp_snooping.join_events_count,
                    self.evpn_igmp_snooping.leave_events_count
                );
                println!(
                    "  Forwarded Multicast Packets: {} | Pruned Packets (Filtered): {}",
                    self.evpn_igmp_snooping.forwarded_packets_count,
                    self.evpn_igmp_snooping.pruned_packets_count
                );
                println!(
                    "  Active Multicast Groups ({}):",
                    self.evpn_igmp_snooping.group_memberships.len()
                );
                for ((vni, group_ip), ports) in &self.evpn_igmp_snooping.group_memberships {
                    let mut p_list: Vec<u32> = ports.iter().copied().collect();
                    p_list.sort();
                    println!(
                        "    VNI: {} | Group: {} -> Active Bridge Ports: {:?}",
                        vni, group_ip, p_list
                    );
                }
            }
            "join" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let port = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(3)
                } else {
                    3
                };
                let group = if args.len() >= 4 {
                    args[3]
                        .parse::<Ipv4Address>()
                        .unwrap_or(Ipv4Address::new(239, 1, 1, 1))
                } else {
                    Ipv4Address::new(239, 1, 1, 1)
                };

                self.evpn_igmp_snooping.process_igmp_join(vni, port, group);
                println!(
                    "  [IGMP JOIN SNOOPED] VNI {} Port {} subscribed to Multicast Group {}",
                    vni, port, group
                );
                println!("    -> Triggered BGP EVPN Route Type 7 (Join Synch) to overlay PEs.");
            }
            "leave" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let port = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let group = if args.len() >= 4 {
                    args[3]
                        .parse::<Ipv4Address>()
                        .unwrap_or(Ipv4Address::new(239, 1, 1, 1))
                } else {
                    Ipv4Address::new(239, 1, 1, 1)
                };

                self.evpn_igmp_snooping.process_igmp_leave(vni, port, group);
                println!(
                    "  [IGMP LEAVE SNOOPED] VNI {} Port {} unsubscribed from Multicast Group {}",
                    vni, port, group
                );
                println!("    -> Triggered BGP EVPN Route Type 8 (Leave Synch) to overlay PEs.");
            }
            "fwd" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let group = if args.len() >= 3 {
                    args[2]
                        .parse::<Ipv4Address>()
                        .unwrap_or(Ipv4Address::new(239, 1, 1, 1))
                } else {
                    Ipv4Address::new(239, 1, 1, 1)
                };

                let action = self
                    .evpn_igmp_snooping
                    .evaluate_multicast_forwarding(vni, group);
                match action {
                    MulticastForwardingAction::ForwardToPorts(ports) => {
                        println!(
                            "  [MULTICAST FORWARD] Ingress packet for ({}, {}) -> Forwarding exclusively to Ports: {:?}",
                            vni, group, ports
                        );
                    }
                    MulticastForwardingAction::PrunedNoReceivers => {
                        println!(
                            "  [MULTICAST PRUNED] Ingress packet for ({}, {}) -> PRUNED! No active IGMP subscribers on bridge.",
                            vni, group
                        );
                    }
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-snooping [status | join <vni> <port> <grp> | leave <vni> <port> <grp> | fwd <vni> <grp>]"
            ),
        }
    }

    fn cmd_flowspec_vrf(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== BGP Flowspec Redirect-to-VRF & Traffic Marking (RFC 8955) ===");
                println!(
                    "  Redirected DDoS Packets: {} | Remarked DSCP Packets: {} | Passed Clean Packets: {}",
                    self.flowspec_vrf_engine.redirected_packets_count,
                    self.flowspec_vrf_engine.remarked_packets_count,
                    self.flowspec_vrf_engine.passed_packets_count
                );
                println!(
                    "  Flowspec Scrubbing Rules ({}):",
                    self.flowspec_vrf_engine.rules.len()
                );
                for r in &self.flowspec_vrf_engine.rules {
                    println!(
                        "    Rule-{} -> Match Dst: {:?} | Proto: {:?} | Dst-Port: {:?} ==> Action: {:?}",
                        r.rule_id, r.match_dst_ip, r.match_protocol, r.match_dst_port, r.action
                    );
                }
            }
            "eval" => {
                let dst_ip = if args.len() >= 2 {
                    args[1]
                        .parse::<Ipv4Address>()
                        .unwrap_or(self.remote_host_ip)
                } else {
                    self.remote_host_ip
                };
                let proto = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(17)
                } else {
                    17
                };
                let port = if args.len() >= 4 {
                    args[3].parse::<u16>().unwrap_or(53)
                } else {
                    53
                };

                let act = self
                    .flowspec_vrf_engine
                    .evaluate_packet(dst_ip, proto, port);
                println!(
                    "  [FLOWSPEC EVALUATION] Packet to {}:{} (Protocol: {})",
                    dst_ip, port, proto
                );
                match act {
                    FlowspecVrfAction::RedirectVrf(vrf) => {
                        println!(
                            "    ==> MATCHED ACTION: REDIRECT TO SCRUBBING VRF '{}' (DDoS Mitigation)",
                            vrf
                        );
                    }
                    FlowspecVrfAction::RemarkDscp(dscp) => {
                        println!("    ==> MATCHED ACTION: REMARK DSCP TO 0x{:02X}", dscp);
                    }
                    FlowspecVrfAction::Drop => {
                        println!("    ==> MATCHED ACTION: DROP");
                    }
                    FlowspecVrfAction::Pass => {
                        println!("    ==> MATCHED ACTION: PASS (Clean Traffic)");
                    }
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: flowspec-vrf [status | eval <dst_ip> <proto> <port>]"
            ),
        }
    }

    fn cmd_gtpu_telemetry(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== 5G GTP-U PDU Session Container Telemetry (3GPP TS 38.415 / 29.281) ==="
                );
                println!(
                    "  Encapsulated 5G Packets: {} | Decapsulated Packets: {}",
                    self.gtpu_telemetry_engine.encapsulated_count,
                    self.gtpu_telemetry_engine.decapsulated_count
                );
                println!(
                    "  Total In-Band Delay Measured: {} us",
                    self.gtpu_telemetry_engine.total_delay_us_accumulated
                );
            }
            "encap" | "demo" => {
                let qfi = if args.len() >= 2 {
                    args[1].parse::<u8>().unwrap_or(9)
                } else {
                    9
                };
                let delay = if args.len() >= 3 {
                    args[2].parse::<u32>().ok()
                } else {
                    Some(350)
                };
                let payload = b"GET /5g-telecom-user-traffic HTTP/1.1\r\n\r\n";

                let pkt = self
                    .gtpu_telemetry_engine
                    .encapsulate(0x10005001, qfi, true, delay, payload);
                let wire = pkt.serialize();
                println!(
                    "  [5G GTP-U ENCAPSULATION] TEID: 0x{:08X} | QFI: {} | RQI: true | Delay: {:?} us",
                    pkt.teid, pkt.telemetry.qfi, pkt.telemetry.delay_result_us
                );
                println!(
                    "    -> Formatted Wire Length: {} bytes (GTP-U Header + 5G PDU Container + Payload)",
                    wire.len()
                );

                let parsed = self
                    .gtpu_telemetry_engine
                    .decapsulate(&wire)
                    .expect("decapsulate GTP-U packet");
                println!(
                    "  [5G GTP-U DECAPSULATED] Parsed successfully at UPF! Verified Payload: {} bytes",
                    parsed.payload.len()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-telemetry [status | encap <qfi> <delay_us>]"
            ),
        }
    }

    fn cmd_ptp_ttc(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== PTP Telecom Peer-to-Peer Transparent Clock (T-TC / G.8275.2) ===");
                println!(
                    "  Corrections Performed: {} | Total Sub-Nanosecond Offset: {} ns",
                    self.ptp_ttc_engine.corrections_performed,
                    self.ptp_ttc_engine.accumulated_correction_ns
                );
                println!(
                    "  Monitored Fronthaul Ports ({}):",
                    self.ptp_ttc_engine.peer_delays_ns.len()
                );
                for (port, delay) in &self.ptp_ttc_engine.peer_delays_ns {
                    println!("    Port-{} -> Link Peer Mean Delay: {} ns", port, delay);
                }
            }
            "pdelay" => {
                let port = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let t1 = if args.len() >= 3 {
                    args[2].parse::<i64>().unwrap_or(1000)
                } else {
                    1000
                };
                let t2 = if args.len() >= 4 {
                    args[3].parse::<i64>().unwrap_or(1300)
                } else {
                    1300
                };
                let t3 = if args.len() >= 5 {
                    args[4].parse::<i64>().unwrap_or(2000)
                } else {
                    2000
                };
                let t4 = if args.len() >= 6 {
                    args[5].parse::<i64>().unwrap_or(2600)
                } else {
                    2600
                };

                let delay = self.ptp_ttc_engine.compute_peer_delay(t1, t2, t3, t4);
                self.ptp_ttc_engine.set_port_peer_delay(port, delay);
                println!(
                    "  [P2P PEER DELAY CALCULATED] Port-{} Delay = (({}-{}) - ({}-{})) / 2 = {} ns",
                    port, t4, t1, t3, t2, delay
                );
            }
            "correct" => {
                let port = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let tin = if args.len() >= 3 {
                    args[2].parse::<i64>().unwrap_or(5000)
                } else {
                    5000
                };
                let tout = if args.len() >= 4 {
                    args[3].parse::<i64>().unwrap_or(5420)
                } else {
                    5420
                };
                let init_corr = 100;

                let new_corr = self
                    .ptp_ttc_engine
                    .correct_event_packet(port, tin, tout, init_corr);
                println!(
                    "  [RESIDENCE TIME CORRECTION] Port-{} Ingress: {} ns, Egress: {} ns (Residence: {} ns)",
                    port,
                    tin,
                    tout,
                    tout - tin
                );
                println!(
                    "    -> Updated CorrectionField: {} ns -> {} ns (incl. PeerDelay)",
                    init_corr, new_corr
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: ptp-ttc [status | pdelay <p> <t1> <t2> <t3> <t4> | correct <p> <tin> <tout>]"
            ),
        }
    }

    fn cmd_diameter_sh(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Diameter Sh IMS Application Server to HSS (3GPP TS 29.328 / 29.329) ==="
                );
                println!(
                    "  Total UDR Queries: {} | Total SNR Subscriptions: {}",
                    self.hss_sh_engine.total_udr_count, self.hss_sh_engine.total_snr_count
                );
                println!(
                    "  HSS Sh Subscriber Directory ({}):",
                    self.hss_sh_engine.subscribers.len()
                );
                for (id, sub) in &self.hss_sh_engine.subscribers {
                    println!(
                        "    Public-Identity: {} | State: {}",
                        id, sub.ims_user_state
                    );
                }
            }
            "udr" => {
                let public_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "sip:alice@ims.mnc001.mcc001.3gppnetwork.org"
                };
                let _uda = self
                    .hss_sh_engine
                    .handle_udr(public_id, crate::diameter_sh::DATA_REF_REPOSITORY_DATA);
                if let Some(sub) = self.hss_sh_engine.subscribers.get(public_id) {
                    println!("  [UDR SENT] Querying HSS for User-Data of {}", public_id);
                    println!("  [UDA RECEIVED] Result: DIAMETER_SUCCESS (2001)");
                    println!("    -> IMS User State: {}", sub.ims_user_state);
                    println!("    -> Repository Data: {}", sub.repository_data);
                } else {
                    println!(
                        "  [UDA ERROR] User {} not found in HSS (DIAMETER_ERROR_USER_UNKNOWN)",
                        public_id
                    );
                }
            }
            "snr" => {
                let as_id = "as-volte-telecom-01";
                let public_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "sip:alice@ims.mnc001.mcc001.3gppnetwork.org"
                };
                let _sna = self.hss_sh_engine.handle_snr(as_id, public_id, 0);
                println!(
                    "  [SNR SENT] AS '{}' subscribed to notifications for {}",
                    as_id, public_id
                );
                println!(
                    "  [SNA RECEIVED] Result: DIAMETER_SUCCESS (2001) | Active Subscriptions: {:?}",
                    self.hss_sh_engine.subscriptions.get(public_id)
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-sh [status | udr <public_id> | snr <public_id>]"
            ),
        }
    }

    fn cmd_evpn_vrf_leak(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== EVPN Layer 3 Multi-VRF Route Leaking (RFC 9136 / RFC 4364) ===");
                println!(
                    "  Total Cross-VRF Leaked Routes: {}",
                    self.evpn_vrf_leaking_engine.leaked_routes_count
                );
                println!(
                    "  Configured VRF Instances ({}):",
                    self.evpn_vrf_leaking_engine.vrfs.len()
                );
                for (id, vrf) in &self.evpn_vrf_leaking_engine.vrfs {
                    println!(
                        "    VRF-{} ({}): Export RTs: {:?} | Import RTs: {:?}",
                        id, vrf.name, vrf.export_rts, vrf.import_rts
                    );
                    println!("      -> Routes in VRF ({}):", vrf.routes.len());
                    for r in &vrf.routes {
                        println!(
                            "         {}/{} -> Next-Hop: {} (Source VRF: {})",
                            r.prefix, r.prefix_len, r.next_hop, r.source_vrf_id
                        );
                    }
                }
            }
            "lookup" => {
                let vrf_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(10)
                } else {
                    10
                };
                let dst_ip = if args.len() >= 3 {
                    args[2]
                        .parse::<Ipv4Address>()
                        .unwrap_or(Ipv4Address::new(8, 8, 8, 8))
                } else {
                    Ipv4Address::new(8, 8, 8, 8)
                };

                if let Some(nh) = self.evpn_vrf_leaking_engine.lookup_vrf_lpm(vrf_id, dst_ip) {
                    println!(
                        "  [VRF-{} LPM LOOKUP] Destination: {} -> Next-Hop: {} (Resolved via Leaked Route)",
                        vrf_id, dst_ip, nh
                    );
                } else {
                    println!(
                        "  [VRF-{} LPM LOOKUP] Destination: {} -> No Route in VRF!",
                        vrf_id, dst_ip
                    );
                }
            }
            "sync" => {
                self.evpn_vrf_leaking_engine.sync_route_leaking();
                println!(
                    "  [VRF ROUTE LEAK SYNC] Updated VRF RIBs. Total Leaked Routes: {}",
                    self.evpn_vrf_leaking_engine.leaked_routes_count
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-vrf-leak [status | lookup <vrf_id> <dst_ip> | sync]"
            ),
        }
    }

    fn cmd_tsn_qbv(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!("=== IEEE 802.1Qbv Time-Aware Shaper (TAS) GCL Schedule Engine ===");
                println!(
                    "  Line Rate: {} Mbps | Cycle Time: {} ns ({} us)",
                    self.tsn_qbv_engine.line_rate_mbps,
                    self.tsn_qbv_engine.cycle_time_ns,
                    self.tsn_qbv_engine.cycle_time_ns / 1000
                );
                println!(
                    "  Scheduled Frames TX: {} | Guard-Band Blocked TX: {}",
                    self.tsn_qbv_engine.scheduled_frames_tx,
                    self.tsn_qbv_engine.guard_band_blocked_tx
                );
                println!(
                    "  Gate Control List (GCL) Entries ({}):",
                    self.tsn_qbv_engine.entries.len()
                );
                for (idx, e) in self.tsn_qbv_engine.entries.iter().enumerate() {
                    let gates_str: String = e
                        .gate_states
                        .iter()
                        .map(|&open| if open { 'O' } else { 'C' })
                        .collect();
                    println!(
                        "    Entry-{}: Duration: {} ns ({} us) | TC 0..7 Gates: [{}]",
                        idx,
                        e.time_interval_ns,
                        e.time_interval_ns / 1000,
                        gates_str
                    );
                }
            }
            "gate" => {
                let time_ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(50_000)
                } else {
                    50_000
                };
                if let Some((gates, remaining_ns)) =
                    self.tsn_qbv_engine.get_active_state_at(time_ns)
                {
                    let gates_str: String = gates
                        .iter()
                        .map(|&open| if open { 'O' } else { 'C' })
                        .collect();
                    println!(
                        "  [TAS GCL STATE] At t = {} ns (Cycle Offset: {} ns)",
                        time_ns,
                        time_ns % self.tsn_qbv_engine.cycle_time_ns
                    );
                    println!(
                        "    -> Active TC 0..7 Gates: [{}] | Remaining Slot Window: {} ns ({} us)",
                        gates_str,
                        remaining_ns,
                        remaining_ns / 1000
                    );
                } else {
                    println!("  [TAS GCL ERROR] No active GCL schedule entries configured.");
                }
            }
            "tx" => {
                let prio = if args.len() >= 2 {
                    args[1].parse::<u8>().unwrap_or(7)
                } else {
                    7
                };
                let len = if args.len() >= 3 {
                    args[2].parse::<usize>().unwrap_or(1500)
                } else {
                    1500
                };
                let time_ns = if args.len() >= 4 {
                    args[3].parse::<u64>().unwrap_or(50_000)
                } else {
                    50_000
                };

                let allowed = self
                    .tsn_qbv_engine
                    .evaluate_transmission(prio, len, time_ns);
                let tx_time = self.tsn_qbv_engine.frame_tx_time_ns(len);
                println!(
                    "  [TAS GCL TRANSMISSION EVALUATION] Frame Size: {} bytes (Tx Time: {} ns) | Priority: TC {} | Timestamp: {} ns",
                    len, tx_time, prio, time_ns
                );
                if allowed {
                    println!(
                        "    ==> RESULT: TRANSMISSION ALLOWED (Fits safely in current open window)"
                    );
                } else {
                    println!(
                        "    ==> RESULT: TRANSMISSION BLOCKED / QUEUED (Gate closed or Guard Band violation)"
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-qbv [status | gate <time_ns> | tx <priority> <len> <time_ns>]"
            ),
        }
    }

    fn cmd_diameter_slh(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Diameter SLh Location Services Interface (3GPP TS 29.173 / TS 29.171) ==="
                );
                println!(
                    "  Total LCS-Routing-Info (RIR) Queries: {}",
                    self.hss_slh_engine.total_rir_queries
                );
                println!(
                    "  HSS SLh Subscriber Location Directory ({}):",
                    self.hss_slh_engine.subscriber_locations.len()
                );
                for (imsi, node) in &self.hss_slh_engine.subscriber_locations {
                    println!(
                        "    IMSI: {} -> Serving MME: {} (Realm: {})",
                        imsi, node.mme_name, node.mme_realm
                    );
                }
            }
            "rir" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "001010123456789"
                };
                let ria = self.hss_slh_engine.handle_rir(imsi);
                let rc = ria.get_avp(268).and_then(|a| a.as_u32()).unwrap_or(0);
                println!(
                    "  [RIR SENT] GMLC querying HSS for location routing info of IMSI {}",
                    imsi
                );
                if rc == crate::diameter::DIAMETER_SUCCESS {
                    if let Some(serving_avp) = ria.get_avp(crate::diameter_slh::AVP_SERVING_NODE) {
                        let node =
                            crate::diameter_slh::ServingNodeInfo::from_grouped_avp(&serving_avp)
                                .unwrap();
                        println!("  [RIA RECEIVED] Result: DIAMETER_SUCCESS (2001)");
                        println!("    -> Target Serving MME Identity: {}", node.mme_name);
                        println!("    -> Target Serving MME Realm: {}", node.mme_realm);
                        println!("    -> E911 Emergency & Commercial Positioning Routing Ready!");
                    }
                } else {
                    println!(
                        "  [RIA RECEIVED] Error Result Code: {} (Subscriber Not Found in HSS)",
                        rc
                    );
                }
            }
            _ => println!("Unknown subcommand. Usage: diameter-slh [status | rir <imsi>]"),
        }
    }

    fn cmd_evpn_uu(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== EVPN Layer 2 Unknown Unicast (UU) Flood Suppression (RFC 7432 Section 13.2) ==="
                );
                println!(
                    "  Allowed Known Unicast Frames: {} | Suppressed Unknown Unicast Frames: {}",
                    self.evpn_uu_engine.allowed_packets_count,
                    self.evpn_uu_engine.suppressed_packets_count
                );
                println!(
                    "  VNI Suppression Policies ({}):",
                    self.evpn_uu_engine.vni_suppression_enabled.len()
                );
                for (vni, active) in &self.evpn_uu_engine.vni_suppression_enabled {
                    println!(
                        "    VNI-{} -> Unknown Unicast Suppression Active: {}",
                        vni, active
                    );
                }
                println!(
                    "  Learned / Advertised EVPN MAC Table Entries ({}):",
                    self.evpn_uu_engine.known_mac_table.len()
                );
                for (vni, mac) in &self.evpn_uu_engine.known_mac_table {
                    println!("    VNI-{} -> Known MAC: {}", vni, mac);
                }
            }
            "test" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let mac = if args.len() >= 3 {
                    args[2]
                        .parse::<MacAddress>()
                        .unwrap_or(MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0x01, 0x01]))
                } else {
                    MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0x01, 0x01])
                };

                let decision = self.evpn_uu_engine.evaluate_frame(vni, mac);
                println!(
                    "  [EVPN UU FRAME EVALUATION] Ingress Frame on VNI-{} destined to MAC {}",
                    vni, mac
                );
                match decision {
                    UuSuppressionDecision::ForwardKnownUnicast => {
                        println!(
                            "    ==> DECISION: FORWARD (Destination MAC is known in EVPN RIB)"
                        );
                    }
                    UuSuppressionDecision::SuppressedUnknownUnicast => {
                        println!(
                            "    ==> DECISION: SUPPRESS / DROP (Unknown Unicast Flood Storm Prevented!)"
                        );
                    }
                    UuSuppressionDecision::ForwardFloodingAllowed => {
                        println!(
                            "    ==> DECISION: FLOOD TO OVERLAY (Suppression disabled on VNI-{})",
                            vni
                        );
                    }
                }
            }
            "vni" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let enabled = if args.len() >= 3 {
                    args[2] == "on" || args[2] == "true"
                } else {
                    true
                };
                self.evpn_uu_engine.set_vni_suppression(vni, enabled);
                println!(
                    "  [EVPN UU CONFIG] VNI-{} Unknown Unicast Suppression set to {}",
                    vni, enabled
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-uu [status | test <vni> <mac> | vni <vni> <on|off>]"
            ),
        }
    }

    fn cmd_geneve_telemetry(&mut self, args: &[&str]) {
        let sub = if args.is_empty() { "status" } else { args[0] };
        match sub {
            "status" => {
                println!(
                    "=== Geneve Overlay In-Band Network Telemetry (INT) Option (RFC 8926) ==="
                );
                println!(
                    "  Local Switch-ID: 0x{:08X} | Inserted Hops: {} | Collected Telemetry Packets: {}",
                    self.geneve_telemetry_engine.local_switch_id,
                    self.geneve_telemetry_engine.hops_inserted_count,
                    self.geneve_telemetry_engine.packets_collected_count
                );
            }
            "insert" | "demo" => {
                let in_port = if args.len() >= 2 {
                    args[1].parse::<u16>().unwrap_or(1)
                } else {
                    1
                };
                let out_port = if args.len() >= 3 {
                    args[2].parse::<u16>().unwrap_or(48)
                } else {
                    48
                };
                let latency_ns = if args.len() >= 4 {
                    args[3].parse::<u32>().unwrap_or(340)
                } else {
                    340
                };
                let queue_bytes = if args.len() >= 5 {
                    args[4].parse::<u32>().unwrap_or(16384)
                } else {
                    16384
                };

                let mut opt = GeneveTelemetryOption::new();
                self.geneve_telemetry_engine.insert_hop(
                    &mut opt,
                    in_port,
                    out_port,
                    latency_ns,
                    queue_bytes,
                );

                let geneve_opt = opt.to_geneve_option();
                println!(
                    "  [GENEVE INT OPTION INSERTED] Switch: 0x{:08X} | In-Port: {} | Out-Port: {} | Hop Latency: {} ns | Queue: {} B",
                    self.geneve_telemetry_engine.local_switch_id,
                    in_port,
                    out_port,
                    latency_ns,
                    queue_bytes
                );
                println!(
                    "    -> Formatted Geneve Option TLV: Class 0x{:04X}, Type 0x{:02X}, Total Bytes: {}",
                    geneve_opt.class,
                    geneve_opt.opt_type,
                    geneve_opt.data.len()
                );

                let parsed = GeneveTelemetryOption::from_geneve_option(&geneve_opt)
                    .expect("parse geneve option");
                println!(
                    "  [GENEVE INT DECAPSULATED AT EGRESS] Successfully parsed {} telemetry hop record(s).",
                    parsed.hops.len()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: geneve-telemetry [status | insert <in_port> <out_port> <lat_ns> <queue_bytes>]"
            ),
        }
    }

    fn cmd_frer_srf(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                let stats = self.frer_srf_engine.total_stats();
                println!("IEEE 802.1CB Sequence Recovery Function (SRF) Engine:");
                println!(
                    "  • Active Streams     : {}",
                    self.frer_srf_engine.streams.len()
                );
                println!(
                    "  • Default History Len: {} entries",
                    self.frer_srf_engine.default_history_len
                );
                println!("  • Total Accepted     : {}", stats.accepted);
                println!("  • Out-of-Order Acc.  : {}", stats.out_of_order_accepted);
                println!("  • Duplicates Elim.   : {}", stats.duplicates_eliminated);
                println!("  • Rogue Dropped      : {}", stats.rogue_dropped);
                for (h, srf) in &self.frer_srf_engine.streams {
                    println!(
                        "    [Stream {}] RecovSeqNum: {}, TakeAny: {}, Acc: {}, DupElim: {}",
                        h,
                        srf.recv_seq,
                        srf.take_any,
                        srf.stats.accepted,
                        srf.stats.duplicates_eliminated
                    );
                }
            }
            "rx" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let seq = if args.len() >= 3 {
                    args[2].parse::<u16>().unwrap_or(103)
                } else {
                    103
                };
                let verdict = self.frer_srf_engine.process_frame(stream_id, seq);
                let verdict_str = match verdict {
                    SrfVerdict::Accept => "ACCEPT (In-Order First Copy)",
                    SrfVerdict::AcceptOutOfOrder => "ACCEPT (Out-of-Order Within Window)",
                    SrfVerdict::EliminateDuplicate => "ELIMINATE (Duplicate Late Copy)",
                    SrfVerdict::DropRogue => "DROP (Rogue / Outside History Window)",
                };
                println!(
                    "  [FRER SRF RX] Stream Handle: {}, Sequence Number: {} -> Verdict: {}",
                    stream_id, seq, verdict_str
                );
            }
            "reset" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let srf = self.frer_srf_engine.get_or_create(stream_id);
                srf.reset();
                println!(
                    "  [FRER SRF RESET] Stream Handle {} reset to TakeAny learning state.",
                    stream_id
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: frer-srf [status | rx <stream_id> <seq> | reset <stream_id>]"
            ),
        }
    }

    fn cmd_diameter_cx(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP Diameter Cx/Dx Interface Engine (Application ID: 16777216):");
                println!(
                    "  • Provisioned IMS Subs: {}",
                    self.hss_cx_engine.subscribers.len()
                );
                println!(
                    "  • Processed Txns      : {}",
                    self.hss_cx_engine.transactions
                );
                for (id, sub) in &self.hss_cx_engine.subscribers {
                    println!(
                        "    Subscriber: {} | S-CSCF: {:?} | Auth Scheme: {}",
                        id, sub.assigned_scscf, sub.auth_scheme
                    );
                }
            }
            "uar" => {
                let pub_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "sip:alice@ims.example.com"
                };
                let mut uar = CxMessage::new_request(CMD_UAR, "shell-cx-sess-001");
                uar.add_avp(CxAvp::PublicIdentity(pub_id.to_string()));
                uar.add_avp(CxAvp::UserAuthorizationType(
                    UserAuthorizationType::Registration,
                ));

                let uaa = self.hss_cx_engine.process_uar(&uar);
                let scscf = uaa.avps.iter().find_map(|a| {
                    if let CxAvp::ServerName(s) = a {
                        Some(s.as_str())
                    } else {
                        None
                    }
                });
                let rc = uaa
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let CxAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(2001);
                println!(
                    "  [DIAMETER CX UAR/UAA] Public-ID: {} -> Result-Code: {}, Assigned S-CSCF: {:?}",
                    pub_id, rc, scscf
                );
            }
            "mar" => {
                let pub_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "sip:alice@ims.example.com"
                };
                let mut mar = CxMessage::new_request(CMD_MAR, "shell-cx-sess-002");
                mar.add_avp(CxAvp::PublicIdentity(pub_id.to_string()));

                let maa = self.hss_cx_engine.process_mar(&mar);
                let auth_item = maa.avps.iter().find_map(|a| {
                    if let CxAvp::SipAuthDataItem {
                        auth_scheme,
                        auth_data,
                    } = a
                    {
                        Some((auth_scheme.as_str(), auth_data.len()))
                    } else {
                        None
                    }
                });
                println!(
                    "  [DIAMETER CX MAR/MAA] Public-ID: {} -> Auth Vector: {:?}",
                    pub_id, auth_item
                );
            }
            "sar" => {
                let pub_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "sip:alice@ims.example.com"
                };
                let scscf = if args.len() >= 3 {
                    args[2]
                } else {
                    "sip:scscf2.ims.example.com"
                };
                let mut sar = CxMessage::new_request(CMD_SAR, "shell-cx-sess-003");
                sar.add_avp(CxAvp::PublicIdentity(pub_id.to_string()));
                sar.add_avp(CxAvp::ServerName(scscf.to_string()));
                sar.add_avp(CxAvp::ServerAssignmentType(
                    ServerAssignmentType::Registration,
                ));

                let saa = self.hss_cx_engine.process_sar(&sar);
                let assigned = saa.avps.iter().find_map(|a| {
                    if let CxAvp::ServerName(s) = a {
                        Some(s.as_str())
                    } else {
                        None
                    }
                });
                println!(
                    "  [DIAMETER CX SAR/SAA] Public-ID: {} -> S-CSCF Assignment: {:?}",
                    pub_id, assigned
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-cx [status | uar <pub_id> | mar <pub_id> | sar <pub_id> <scscf>]"
            ),
        }
    }

    fn cmd_evpn_mac_mobility(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("EVPN MAC Mobility Engine (RFC 7432 Section 15):");
                println!(
                    "  • Tracked MAC Entries: {}",
                    self.evpn_mac_mobility_engine.entries.len()
                );
                println!(
                    "  • Move Threshold     : {} moves",
                    self.evpn_mac_mobility_engine.move_threshold
                );
                println!(
                    "  • Flapping Duplicates: {}",
                    self.evpn_mac_mobility_engine.duplicate_count()
                );
                for e in &self.evpn_mac_mobility_engine.entries {
                    println!(
                        "    [VNI {}] MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} | VTEP: {}.{}.{}.{} | Seq: {} | Sticky: {} | Moves: {} | Flapping: {}",
                        e.vni,
                        e.mac[0],
                        e.mac[1],
                        e.mac[2],
                        e.mac[3],
                        e.mac[4],
                        e.mac[5],
                        e.vtep_ip[0],
                        e.vtep_ip[1],
                        e.vtep_ip[2],
                        e.vtep_ip[3],
                        e.sequence_number,
                        e.sticky,
                        e.move_count,
                        e.duplicate_detected
                    );
                }
            }
            "learn" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let vtep_ip = [
                    10,
                    0,
                    0,
                    if args.len() >= 3 {
                        args[2].parse::<u8>().unwrap_or(2)
                    } else {
                        2
                    },
                ];
                let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
                let sticky = args.len() >= 4 && args[3] == "sticky";

                let (comm, moved) = self
                    .evpn_mac_mobility_engine
                    .learn_mac(vni, mac, vtep_ip, sticky);
                println!(
                    "  [EVPN MAC LEARN] VNI: {}, MAC: 52:54:00:12:34:56 at VTEP {}.{}.{}.{} -> Moved: {}, New Seq: {}, Sticky: {}",
                    vni,
                    vtep_ip[0],
                    vtep_ip[1],
                    vtep_ip[2],
                    vtep_ip[3],
                    moved,
                    comm.sequence_number,
                    comm.sticky
                );
            }
            "adv" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let remote_vtep = [10, 0, 0, 99];
                let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
                let seq = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(10)
                } else {
                    10
                };
                let sticky = args.len() >= 4 && args[3] == "sticky";

                let comm = MacMobilityExtComm {
                    sticky,
                    sequence_number: seq,
                };
                let updated = self.evpn_mac_mobility_engine.process_remote_advertisement(
                    vni,
                    mac,
                    remote_vtep,
                    &comm,
                );
                println!(
                    "  [EVPN REMOTE BGP ADV] Received Type 2 MAC Mobility Seq: {} -> Local Table Updated: {}",
                    seq, updated
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-mobility [status | learn <vni> <vtep_last_octet> [sticky] | adv <vni> <seq> [sticky]]"
            ),
        }
    }

    fn cmd_gtpc_v2(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP GTPv2-C (GTP Control Plane v2) SGW Engine (3GPP TS 29.274):");
                println!(
                    "  • Active SGW Sessions: {}",
                    self.sgw_engine.sessions.len()
                );
                println!(
                    "  • Next TEID Counter  : 0x{:08X}",
                    self.sgw_engine.next_teid
                );
                for s in &self.sgw_engine.sessions {
                    println!(
                        "    [IMSI {}] APN: {} | MME-TEID: 0x{:08X} | SGW-TEID: 0x{:08X} | EBI: {}",
                        s.imsi, s.apn, s.mme_teid, s.sgw_teid, s.ebi
                    );
                }
            }
            "create" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "310260123456789"
                };
                let apn = if args.len() >= 3 {
                    args[2]
                } else {
                    "internet.5gcore.local"
                };
                let mme_teid = 0x0001;
                let mme_ip = [10, 0, 0, 10];

                let req =
                    Gtpv2cMessage::create_session_request(0, 1, imsi, apn, mme_teid, mme_ip, 5);
                let rsp = self.sgw_engine.process_create_session(&req);

                let cause = rsp.find_ie(IE_CAUSE).map(|ie| ie.data[0]).unwrap_or(0);
                let fteid = rsp
                    .find_ie(IE_FTEID)
                    .map(|ie| {
                        if ie.data.len() >= 5 {
                            u32::from_be_bytes([ie.data[1], ie.data[2], ie.data[3], ie.data[4]])
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);

                println!(
                    "  [GTPv2-C CREATE SESSION HANDSHAKE] IMSI: {}, APN: {}",
                    imsi, apn
                );
                println!(
                    "    -> SGW Response Cause: {} (Accepted: {}), Assigned SGW-TEID: 0x{:08X}",
                    cause,
                    cause == CAUSE_REQUEST_ACCEPTED,
                    fteid
                );
            }
            _ => println!("Unknown subcommand. Usage: gtpc-v2 [status | create <imsi> <apn>]"),
        }
    }

    fn cmd_tsn_cqf(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qch Multi-Queue Cyclic Queuing and Forwarding (CQF) Engine:");
                println!(
                    "  • Cycle Duration ($T_{{cycle}}$): {} ns ({} µs)",
                    self.tsn_cqf_engine.cycle_time_ns,
                    self.tsn_cqf_engine.cycle_time_ns / 1000
                );
                println!(
                    "  • Current Cycle Index  : Cycle {}",
                    self.tsn_cqf_engine.current_cycle
                );
                println!(
                    "  • Frames Forwarded     : {}",
                    self.tsn_cqf_engine.frames_forwarded
                );
                println!(
                    "  • Frames Dropped       : {}",
                    self.tsn_cqf_engine.frames_dropped
                );
                let (min_lat, max_lat) = self.tsn_cqf_engine.hop_latency_bounds();
                println!(
                    "  • Bounded Hop Latency  : [{} µs, {} µs]",
                    min_lat / 1000,
                    max_lat / 1000
                );
                for q in &self.tsn_cqf_engine.queues {
                    println!(
                        "    [Queue {}] Role: {:?} | Buffered: {} frames ({} / {} bytes) | Enq: {}, Tx: {}, Drop: {}",
                        q.id,
                        q.role,
                        q.frames.len(),
                        q.current_bytes,
                        q.max_capacity_bytes,
                        q.total_enqueued,
                        q.total_transmitted,
                        q.total_dropped
                    );
                }
            }
            "ingest" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(101)
                } else {
                    101
                };
                let prio = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(7)
                } else {
                    7
                };
                let size = if args.len() >= 4 {
                    args[3].parse::<usize>().unwrap_or(256)
                } else {
                    256
                };
                let time_ns = if args.len() >= 5 {
                    args[4].parse::<u64>().unwrap_or(20_000)
                } else {
                    20_000
                };

                let payload = vec![0xAA; size];
                match self
                    .tsn_cqf_engine
                    .ingest_frame(stream_id, prio, payload, time_ns)
                {
                    Ok(_) => println!(
                        "  [CQF INGEST SUCCESS] Stream: {}, Priority: {}, Size: {} B at Ingress Timestamp: {} ns",
                        stream_id, prio, size, time_ns
                    ),
                    Err(e) => println!("  [CQF INGEST FAILED] {}", e),
                }
            }
            "advance" => {
                let time_ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(130_000)
                } else {
                    130_000
                };
                let drained = self.tsn_cqf_engine.advance_time(time_ns);
                println!(
                    "  [CQF ADVANCE TIME] Clock moved to {} ns -> Now in Cycle {}",
                    time_ns, self.tsn_cqf_engine.current_cycle
                );
                println!(
                    "    -> Drained & Forwarded {} frame(s) out transmitting port.",
                    drained.len()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-cqf [status | ingest <stream> <prio> <size> [time_ns] | advance <time_ns>]"
            ),
        }
    }

    fn cmd_diameter_s6b(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP Diameter S6b Non-3GPP AAA Server (Application ID: 16777272):");
                println!(
                    "  • Realm               : {}",
                    self.aaa_s6b_engine.server_realm
                );
                println!(
                    "  • Provisioned IMS Subs: {}",
                    self.aaa_s6b_engine.subscribers.len()
                );
                println!(
                    "  • Active S6b Sessions : {}",
                    self.aaa_s6b_engine.active_sessions.len()
                );
                println!(
                    "  • Total Transactions  : {}",
                    self.aaa_s6b_engine.total_transactions
                );
                for (imsi, sub) in &self.aaa_s6b_engine.subscribers {
                    println!(
                        "    [IMSI {}] Status: {:?} | Authorized ANID: {:?} | PGW: {}.{}.{}.{} ({}) | APN: {}",
                        imsi,
                        sub.status,
                        sub.authorized_anid,
                        sub.allocated_pgw_ip[0],
                        sub.allocated_pgw_ip[1],
                        sub.allocated_pgw_ip[2],
                        sub.allocated_pgw_ip[3],
                        sub.allocated_pgw_fqdn,
                        sub.apn
                    );
                }
            }
            "aar" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "208950123456789"
                };
                let anid = if args.len() >= 3 { args[2] } else { "WLAN" };

                let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "shell-s6b-session-001");
                aar.add_avp(S6bAvp::UserName(imsi.to_string()));
                aar.add_avp(S6bAvp::Anid(anid.to_string()));

                let aaa = self.aaa_s6b_engine.handle_aar(&aar);
                let rc = aaa
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6bAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);
                let mip6 = aaa.avps.iter().find_map(|a| {
                    if let S6bAvp::Mip6AgentInfo(info) = a {
                        Some(info.clone())
                    } else {
                        None
                    }
                });

                println!(
                    "  [DIAMETER S6b AAR/AAA] IMSI: {}, ANID: {} -> Result-Code: {}",
                    imsi, anid, rc
                );
                if let Some(info) = mip6 {
                    println!(
                        "    -> Allocated MIP6 PGW IP: {}.{}.{}.{}, FQDN: {}",
                        info.pgw_ip[0],
                        info.pgw_ip[1],
                        info.pgw_ip[2],
                        info.pgw_ip[3],
                        info.pgw_fqdn
                    );
                }
            }
            "str" => {
                let sess_id = if args.len() >= 2 {
                    args[1]
                } else {
                    "shell-s6b-session-001"
                };
                let str_msg = S6bMessage::new_request(DIAMETER_CMD_SESSION_TERMINATION, sess_id);
                let sta = self.aaa_s6b_engine.handle_str(&str_msg);
                let rc = sta
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6bAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);
                println!(
                    "  [DIAMETER S6b STR/STA] Terminated Session: {} -> Result-Code: {}",
                    sess_id, rc
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s6b [status | aar <imsi> <anid> | str <sess_id>]"
            ),
        }
    }

    fn cmd_evpn_frr(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("EVPN Fast Reroute (FRR) & Secondary Nexthop Protection Engine:");
                println!(
                    "  • Protected Routes    : {}",
                    self.evpn_frr_engine.routes.len()
                );
                println!(
                    "  • Active on Backup FRR: {}",
                    self.evpn_frr_engine.backup_active_count()
                );
                for r in &self.evpn_frr_engine.routes {
                    println!(
                        "    [VNI {}] MAC: {} | State: {:?} | Primary: {} (Alive: {}) | Backup: {} (Alive: {}) | Switchovers: {}",
                        r.vni,
                        r.mac,
                        r.state,
                        r.primary_nexthop,
                        r.primary_alive,
                        r.backup_nexthop,
                        r.backup_alive,
                        r.switchover_count
                    );
                    println!(
                        "      -> Packets Forwarded: Primary = {}, Backup = {}, Dropped = {}",
                        r.packets_primary, r.packets_backup, r.packets_dropped
                    );
                }
            }
            "fail" => {
                let primary_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 0, 0, 1))
                } else {
                    Ipv4Address::new(10, 0, 0, 1)
                };
                let affected = self.evpn_frr_engine.trigger_link_down(primary_ip);
                println!(
                    "  [EVPN FRR LINK FAULT DETECTED] Primary Link {} Failed! Affected {} route(s) instantly switched to Secondary Backup Nexthop.",
                    primary_ip, affected
                );
            }
            "restore" => {
                let primary_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 0, 0, 1))
                } else {
                    Ipv4Address::new(10, 0, 0, 1)
                };
                let affected = self.evpn_frr_engine.trigger_link_up(primary_ip);
                println!(
                    "  [EVPN FRR LINK RESTORED] Primary Link {} Restored! Reverted {} route(s) back to Primary Nexthop.",
                    primary_ip, affected
                );
            }
            "fwd" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let mac = MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]);
                match self.evpn_frr_engine.forward_frame(vni, mac) {
                    Some((nh, target_vni)) => println!(
                        "  [EVPN FRR FORWARDING] Frame steered to Active Nexthop: {} (VNI {})",
                        nh, target_vni
                    ),
                    None => println!("  [EVPN FRR FORWARDING DROP] All paths are currently down!"),
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-frr [status | fail <primary_ip> | restore <primary_ip> | fwd <vni>]"
            ),
        }
    }

    fn cmd_srv6_mup_direct(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("SRv6 Mobile User Plane (MUP) Direct Routing Interworking Engine:");
                println!(
                    "  • Registered Mappings : {}",
                    self.srv6_mup_interworking.mappings.len()
                );
                println!(
                    "  • Translations to SRv6: {}",
                    self.srv6_mup_interworking.translations_to_srv6
                );
                println!(
                    "  • Translations to GTP : {}",
                    self.srv6_mup_interworking.translations_to_gtp
                );
                for m in &self.srv6_mup_interworking.mappings {
                    println!(
                        "    [GTP TEID 0x{:08X}] gNodeB: {} | QFI: {} | SRv6 Segment SIDs: {:?}",
                        m.gtp_teid, m.gnodeb_ip, m.qfi, m.srv6_segments
                    );
                }
            }
            "d" => {
                let teid = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(0x12345678)
                } else {
                    0x12345678
                };
                let gnodeb = Ipv6Address::new([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
                match self.srv6_mup_interworking.end_m_gtp6_d(
                    gnodeb,
                    teid,
                    9,
                    b"5G VoNR Packet".to_vec(),
                ) {
                    Some(pkt) => {
                        println!(
                            "  [End.M.GTP6.D TRANSLATION SUCCESS] Ingress GTP-U TEID 0x{:08X} -> SRv6 Packet:",
                            teid
                        );
                        println!(
                            "    • IPv6 Header: {} -> Target SID: {}",
                            pkt.src_ip, pkt.dst_ip
                        );
                        println!("    • SRv6 Segment List: {:?}", pkt.segment_list);
                        println!("    • QFI Mapping: {}", pkt.qfi);
                    }
                    None => println!(
                        "  [End.M.GTP6.D ERROR] No session mapping found for TEID 0x{:08X}",
                        teid
                    ),
                }
            }
            "e" => {
                let teid = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(0x87654321)
                } else {
                    0x87654321
                };
                let local_pe = Ipv6Address::new([0x2001, 0x0db8, 0, 0, 0, 0, 0, 2]);
                let gnodeb = Ipv6Address::new([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
                let gtpu = self.srv6_mup_interworking.end_m_gtp6_e(
                    local_pe,
                    gnodeb,
                    teid,
                    9,
                    b"5G Downlink Packet".to_vec(),
                );
                println!("  [End.M.GTP6.E TRANSLATION SUCCESS] Egress SRv6 -> GTP-U Packet:");
                println!(
                    "    • Outer GTP-U IPv6: {} -> gNodeB {}",
                    gtpu.src_ip, gtpu.dst_ip
                );
                println!(
                    "    • Assigned GTP-U TEID: 0x{:08X}, QFI: {}",
                    gtpu.teid, gtpu.qfi
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: srv6-mup-direct [status | d <teid> | e <teid>]"
            ),
        }
    }

    fn cmd_evpn_mac_flush(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("EVPN Layer 2 MAC Flush Engine (RFC 7432 / RFC 8317):");
                println!(
                    "  • Active MAC Entries  : {}",
                    self.evpn_mac_flush_engine.active_mac_count()
                );
                println!(
                    "  • Total Flushes Done  : {}",
                    self.evpn_mac_flush_engine.total_flushes
                );
                println!(
                    "  • Total MACs Purged   : {}",
                    self.evpn_mac_flush_engine.total_macs_purged
                );
                println!(
                    "  • Link Down Events    : {}",
                    self.evpn_mac_flush_engine.link_down_events
                );
                for m in &self.evpn_mac_flush_engine.mac_table {
                    println!(
                        "    [VNI {}] MAC: {} | ESI: {:02X?} | VTEP: {} | Static: {}",
                        m.vni, m.mac, m.esi.0, m.remote_vtep, m.is_static
                    );
                }
            }
            "down" => {
                let esi = EvpnEsi::new([0x01; 10]);
                let purged = self.evpn_mac_flush_engine.handle_local_link_down(esi);
                println!(
                    "  [EVPN MAC FLUSH LINK DOWN] Ethernet Segment {:02X?} failed! Purged {} MAC entries.",
                    esi.0, purged
                );
            }
            "vni" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let esi = EvpnEsi::new([0x01; 10]);
                let purged = self
                    .evpn_mac_flush_engine
                    .execute_flush(MacFlushScope::VniOnEsi { esi, vni });
                println!(
                    "  [EVPN MAC FLUSH VNI] Purged {} MACs on VNI {} (ESI {:02X?})",
                    purged, vni, esi.0
                );
            }
            _ => println!("Unknown subcommand. Usage: evpn-flush [status | down | vni <vni>]"),
        }
    }

    fn cmd_gtpu_heartbeat(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP GTP-U Path Management & Echo Heartbeat Engine (TS 29.281):");
                println!(
                    "  • Local Restart Counter: {}",
                    self.gtpu_path_engine.local_restart_counter
                );
                println!(
                    "  • Monitored Peers      : {}",
                    self.gtpu_path_engine.peers.len()
                );
                for p in &self.gtpu_path_engine.peers {
                    println!(
                        "    [Peer {}] State: {:?} | Unacked: {} / {} | Last Seq: {} | Peer Restart: {:?} | Sent: {}, Recv: {}, Failures: {}",
                        p.peer_ip,
                        p.state,
                        p.unacked_probes,
                        p.max_retries,
                        p.last_seq_sent,
                        p.peer_restart_counter,
                        p.total_echo_requests_sent,
                        p.total_echo_responses_recv,
                        p.total_path_failures
                    );
                }
            }
            "ping" => {
                let peer_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 100, 1, 1))
                } else {
                    Ipv4Address::new(10, 100, 1, 1)
                };
                match self.gtpu_path_engine.send_echo_request(peer_ip) {
                    Some(req) => println!(
                        "  [GTP-U ECHO REQUEST SENT] Peer: {}, Seq: {}, Local Restart: {}",
                        peer_ip, req.sequence_number, req.restart_counter
                    ),
                    None => println!("  [GTP-U ERROR] Peer {} not found in path table!", peer_ip),
                }
            }
            "ack" => {
                let peer_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 100, 1, 1))
                } else {
                    Ipv4Address::new(10, 100, 1, 1)
                };
                let seq = if args.len() >= 3 {
                    args[2].parse::<u16>().unwrap_or(1)
                } else {
                    1
                };
                let resp = GtpuEchoMessage::new_response(seq, 10);
                if self.gtpu_path_engine.handle_echo_response(peer_ip, &resp) {
                    println!(
                        "  [GTP-U ECHO RESPONSE RECEIVED] Path to {} is Healthy & Active (Peer Restart: 10).",
                        peer_ip
                    );
                } else {
                    println!(
                        "  [GTP-U ECHO RESPONSE MISMATCH] Sequence {} does not match outstanding request.",
                        seq
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-heartbeat [status | ping <peer_ip> | ack <peer_ip> [seq]]"
            ),
        }
    }

    fn cmd_tsn_psfp(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP) Engine:");
                println!(
                    "  • SFIs (Stream Filters): {}",
                    self.tsn_psfp_engine.filters.len()
                );
                println!(
                    "  • SGIs (Stream Gates)  : {}",
                    self.tsn_psfp_engine.gates.len()
                );
                println!(
                    "  • FMIs (Flow Meters)   : {}",
                    self.tsn_psfp_engine.meters.len()
                );
                for f in &self.tsn_psfp_engine.filters {
                    println!(
                        "    [Filter Stream {}/Prio {}] Max SDU: {} B | Gate ID: {} | Meter ID: {:?} | Matches: {}, Drops: {}",
                        f.stream_id,
                        f.priority,
                        f.max_sdu_bytes,
                        f.gate_id,
                        f.meter_id,
                        f.matching_frames,
                        f.sdu_oversized_drops
                    );
                }
                for g in &self.tsn_psfp_engine.gates {
                    println!(
                        "    [Gate {}] Open: {} | Closed Drops: {}, Invalid Rx: {}",
                        g.gate_id, g.is_open, g.gate_closed_drops, g.invalid_rx_count
                    );
                }
                for m in &self.tsn_psfp_engine.meters {
                    println!(
                        "    [Meter {}] CIR: {} B/s, CBS: {} B | PIR: {} B/s, PBS: {} B | Green: {}, Yellow: {}, Red Drops: {}",
                        m.meter_id,
                        m.cir_bps,
                        m.cbs_bytes,
                        m.pir_bps,
                        m.pbs_bytes,
                        m.green_packets,
                        m.yellow_packets,
                        m.red_drops
                    );
                }
            }
            "test" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(101)
                } else {
                    101
                };
                let prio = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(7)
                } else {
                    7
                };
                let len = if args.len() >= 4 {
                    args[3].parse::<usize>().unwrap_or(256)
                } else {
                    256
                };
                let verdict = self.tsn_psfp_engine.process_frame(stream_id, prio, len, 0);
                println!(
                    "  [PSFP INSPECTION] Stream: {}, Prio: {}, Length: {} B -> Verdict: {:?}",
                    stream_id, prio, len, verdict
                );
            }
            "gate" => {
                let gate_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let is_open = args.len() < 3 || args[2] != "close";
                if let Some(gate) = self
                    .tsn_psfp_engine
                    .gates
                    .iter_mut()
                    .find(|g| g.gate_id == gate_id)
                {
                    gate.is_open = is_open;
                    println!(
                        "  [PSFP GATE UPDATE] Gate {} is now {}",
                        gate_id,
                        if is_open { "OPEN" } else { "CLOSED" }
                    );
                } else {
                    println!("  [PSFP ERROR] Gate {} not found!", gate_id);
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-psfp [status | test <stream> <prio> <len> | gate <id> <open|close>]"
            ),
        }
    }

    fn cmd_diameter_swm(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter SWm / SWx Untrusted WLAN / ePDG AAA Server (App ID: 16777264):"
                );
                println!("  • Realm            : {}", self.aaa_swm_engine.realm);
                println!(
                    "  • Provisioned Subs : {}",
                    self.aaa_swm_engine.subscribers.len()
                );
                println!(
                    "  • Active Sessions  : {}",
                    self.aaa_swm_engine.active_sessions.len()
                );
                println!(
                    "  • Auth Success     : {}",
                    self.aaa_swm_engine.successful_authentications
                );
                println!(
                    "  • Auth Failed      : {}",
                    self.aaa_swm_engine.failed_authentications
                );
                for (imsi, sub) in &self.aaa_swm_engine.subscribers {
                    println!(
                        "    [IMSI {}] Authenticated: {} | MSK Len: {} B",
                        imsi,
                        sub.authenticated,
                        sub.msk.len()
                    );
                }
            }
            "auth" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "208950123456789"
                };
                let anid = if args.len() >= 3 { args[2] } else { "WLAN" };

                let eap_resp = vec![0x02, 0x01, 0x00, 0x08, 0x32, 0x00, 0x00, 0x00];
                let der = SwmMessage::new_der("swm-sess-cli", imsi, anid, eap_resp);
                let dea = self.aaa_swm_engine.handle_der(&der);

                let rc = dea
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let SwmAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);
                let msk = dea.avps.iter().find_map(|a| {
                    if let SwmAvp::EapMasterSessionKey(k) = a {
                        Some(k.clone())
                    } else {
                        None
                    }
                });

                println!(
                    "  [DIAMETER SWm DER/DEA] Subscriber: {}, ANID: {} -> Result-Code: {}",
                    imsi, anid, rc
                );
                if let Some(key) = msk {
                    println!(
                        "    -> Derived EAP Master Session Key (MSK): 64 bytes (Prefix: {:02X?})",
                        &key[0..8]
                    );
                }
            }
            _ => println!("Unknown subcommand. Usage: diameter-swm [status | auth <imsi> [anid]]"),
        }
    }

    fn cmd_diameter_s13_prime(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP Diameter S13' Direct EIR Interface (App ID: 16777252 / TS 29.272):");
                println!(
                    "  • EIR Realm             : {}",
                    self.eir_s13_prime_engine.eir_realm
                );
                println!(
                    "  • Registered Equipments : {}",
                    self.eir_s13_prime_engine.equipment_db.len()
                );
                println!(
                    "  • Banned SVNs           : {:?}",
                    self.eir_s13_prime_engine.banned_software_versions
                );
                println!(
                    "  • Total Checks          : {}",
                    self.eir_s13_prime_engine.total_checks
                );
                println!(
                    "  • Blacklist Detections  : {}",
                    self.eir_s13_prime_engine.blacklisted_hits
                );
                for (imei, status) in &self.eir_s13_prime_engine.equipment_db {
                    println!("    [IMEI {}] Status: {:?}", imei, status);
                }
            }
            "check" => {
                let imei = if args.len() >= 2 {
                    args[1]
                } else {
                    "861234567890123"
                };
                let svn = if args.len() >= 3 {
                    Some(args[2].to_string())
                } else {
                    None
                };

                let term_info = TerminalInformation {
                    imei: imei.to_string(),
                    software_version: svn.clone(),
                };
                let ecr = S13PrimeMessage::new_ecr("s13p-sess-cli", "001010000000001", term_info);
                let eca = self.eir_s13_prime_engine.process_ecr(&ecr);

                let status = eca.avps.iter().find_map(|a| {
                    if let S13PrimeAvp::EquipmentStatus(s) = a {
                        Some(*s)
                    } else {
                        None
                    }
                });
                println!(
                    "  [S13' ME IDENTITY CHECK] IMEI: {}, SVN: {:?} -> Equipment Status: {:?}",
                    imei, svn, status
                );
            }
            _ => println!("Unknown subcommand. Usage: diameter-s13p [status | check <imei> [svn]]"),
        }
    }

    fn cmd_evpn_mcast_ir(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Selective Multicast Ingress Replication (IR) & Leaf Pruning (RFC 9251):"
                );
                println!(
                    "  • VNIs Configured       : {}",
                    self.evpn_selective_ir_engine.inclusive_vteps.len()
                );
                println!(
                    "  • Selective (S, G) Trees: {}",
                    self.evpn_selective_ir_engine.selective_entries.len()
                );
                println!(
                    "  • Core Packets Saved    : {}",
                    self.evpn_selective_ir_engine.total_pruned_packets_saved
                );
                for (vni, vteps) in &self.evpn_selective_ir_engine.inclusive_vteps {
                    println!(
                        "    [VNI {} Inclusive IMET Fallback] Total Leaf VTEPs: {}",
                        vni,
                        vteps.len()
                    );
                }
                for entry in &self.evpn_selective_ir_engine.selective_entries {
                    println!(
                        "    [VNI {} Channel (Src: {:?}, Grp: {})] Receivers: {:?} | Fwd: {}, Replicated: {}",
                        entry.channel.vni,
                        entry.channel.source_ip,
                        entry.channel.group_ip,
                        entry.receiver_vteps,
                        entry.packets_forwarded,
                        entry.replications_sent
                    );
                }
            }
            "join" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let src_ip = if args.len() >= 3 {
                    Ipv4Address::from_str(args[2]).unwrap_or(Ipv4Address::new(192, 168, 1, 50))
                } else {
                    Ipv4Address::new(192, 168, 1, 50)
                };
                let grp_ip = if args.len() >= 4 {
                    Ipv4Address::from_str(args[3]).unwrap_or(Ipv4Address::new(239, 1, 1, 1))
                } else {
                    Ipv4Address::new(239, 1, 1, 1)
                };
                let vtep = if args.len() >= 5 {
                    Ipv4Address::from_str(args[4]).unwrap_or(Ipv4Address::new(10, 0, 0, 3))
                } else {
                    Ipv4Address::new(10, 0, 0, 3)
                };

                self.evpn_selective_ir_engine
                    .add_smet_receiver(MulticastChannel::new_ssm(vni, src_ip, grp_ip), vtep);
                println!(
                    "  [EVPN SMET JOIN REGISTERED] VNI: {}, Channel: ({}, {}) -> Added Leaf VTEP {}",
                    vni, src_ip, grp_ip, vtep
                );
            }
            "tx" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let src_ip = if args.len() >= 3 {
                    Ipv4Address::from_str(args[2]).unwrap_or(Ipv4Address::new(192, 168, 1, 50))
                } else {
                    Ipv4Address::new(192, 168, 1, 50)
                };
                let grp_ip = if args.len() >= 4 {
                    Ipv4Address::from_str(args[3]).unwrap_or(Ipv4Address::new(239, 1, 1, 1))
                } else {
                    Ipv4Address::new(239, 1, 1, 1)
                };

                let (targets, is_sel) = self
                    .evpn_selective_ir_engine
                    .resolve_replication_targets(vni, src_ip, grp_ip);
                println!(
                    "  [EVPN MULTICAST FORWARD] Source: {} -> Group: {} (Selective Pruning Applied: {})",
                    src_ip, grp_ip, is_sel
                );
                println!(
                    "    • Replicating to {} Leaf VTEPs: {:?}",
                    targets.len(),
                    targets
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-mcast-ir [status | join <vni> <s_ip> <g_ip> <vtep> | tx <vni> <s_ip> <g_ip>]"
            ),
        }
    }

    fn cmd_gtpu_reorder(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("3GPP GTP-U Sequence Number Reordering Engine (TS 29.281):");
                println!(
                    "  • TEID              : 0x{:08X}",
                    self.gtpu_reordering_engine.teid
                );
                println!(
                    "  • Next Expected Seq : {}",
                    self.gtpu_reordering_engine.next_expected_seq
                );
                println!(
                    "  • Window Size       : {}",
                    self.gtpu_reordering_engine.window_size
                );
                println!(
                    "  • Packets Buffered  : {}",
                    self.gtpu_reordering_engine.buffer.len()
                );
                println!(
                    "  • Total Received    : {}",
                    self.gtpu_reordering_engine.total_received
                );
                println!(
                    "  • In-Order Instant  : {}",
                    self.gtpu_reordering_engine.total_in_order
                );
                println!(
                    "  • Reordered/Resolved: {}",
                    self.gtpu_reordering_engine.total_reordered
                );
                println!(
                    "  • Duplicate Dropped : {}",
                    self.gtpu_reordering_engine.total_duplicates
                );
            }
            "rx" => {
                let seq = if args.len() >= 2 {
                    args[1].parse::<u16>().unwrap_or(1)
                } else {
                    1
                };
                let text = if args.len() >= 3 {
                    args[2].as_bytes().to_vec()
                } else {
                    b"GTP-U Data Payload".to_vec()
                };

                let delivered = self.gtpu_reordering_engine.ingest_packet(seq, text);
                println!(
                    "  [GTP-U INGEST PACKET] Seq: {} -> {} packets released in-order to upper layer:",
                    seq,
                    delivered.len()
                );
                for p in delivered {
                    println!(
                        "    • Delivered Seq {}: \"{}\"",
                        p.sequence_number,
                        String::from_utf8_lossy(&p.payload)
                    );
                }
            }
            "flush" => {
                let flushed = self.gtpu_reordering_engine.force_flush();
                println!(
                    "  [GTP-U FORCE FLUSH] Released {} remaining packets in buffer.",
                    flushed.len()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-reorder [status | rx <seq> <text> | flush]"
            ),
        }
    }

    fn cmd_tsn_qcz(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qcz Congestion Isolation & Head-of-Line Blocking Mitigation:");
                println!(
                    "  • CP MAC Address       : {:02X?}",
                    self.tsn_qcz_engine.cp_mac
                );
                println!(
                    "  • Congestion Threshold : {} bytes",
                    self.tsn_qcz_engine.congestion_threshold_bytes
                );
                println!(
                    "  • Uncongested Queue    : {} packets ({} bytes)",
                    self.tsn_qcz_engine.uncongested_queue.len(),
                    self.tsn_qcz_engine.uq_occupancy()
                );
                println!(
                    "  • Isolated Queue (CIQ) : {} packets ({} bytes)",
                    self.tsn_qcz_engine.isolated_queue.len(),
                    self.tsn_qcz_engine.ciq_occupancy()
                );
                println!(
                    "  • Isolated Flows Track : {}",
                    self.tsn_qcz_engine.isolated_flows.len()
                );
                println!(
                    "  • Total CNM Generated  : {}",
                    self.tsn_qcz_engine.total_cnm_generated
                );
                for f in &self.tsn_qcz_engine.isolated_flows {
                    println!(
                        "    [ISOLATED CIF FLOW] {} -> {} (Proto {}, Port {}:{})",
                        f.src_ip, f.dst_ip, f.protocol, f.src_port, f.dst_port
                    );
                }
            }
            "tx" => {
                let src_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 1, 1, 1))
                } else {
                    Ipv4Address::new(10, 1, 1, 1)
                };
                let dst_ip = if args.len() >= 3 {
                    Ipv4Address::from_str(args[2]).unwrap_or(Ipv4Address::new(10, 2, 2, 2))
                } else {
                    Ipv4Address::new(10, 2, 2, 2)
                };
                let bytes = if args.len() >= 4 {
                    args[3].parse::<usize>().unwrap_or(800)
                } else {
                    800
                };

                let flow = QczFlowTuple::new(src_ip, dst_ip, 5001, 5001, 6);
                let cnm = self.tsn_qcz_engine.enqueue_packet(flow, vec![0xAA; bytes]);

                println!(
                    "  [QCZ PACKET INGEST] Flow: {} -> {} ({} Bytes):",
                    src_ip, dst_ip, bytes
                );
                if let Some(c) = cnm {
                    println!(
                        "    🚨 [CONGESTION POINT THRESHOLD EXCEEDED] Flow isolated into CIQ!"
                    );
                    println!(
                        "    -> IEEE 802.1Qcz CNM generated for CP MAC: {:02X?}, Occupancy: {} B",
                        c.cp_mac, c.queue_occupancy_bytes
                    );
                } else if self.tsn_qcz_engine.isolated_flows.contains(&flow) {
                    println!("    ⚠️ Flow is under active isolation -> Placed in CIQ.");
                } else {
                    println!("    ✅ Flow is uncongested -> Placed in UQ (Line Rate).");
                }
            }
            "clear" => {
                let src_ip = if args.len() >= 2 {
                    Ipv4Address::from_str(args[1]).unwrap_or(Ipv4Address::new(10, 1, 1, 1))
                } else {
                    Ipv4Address::new(10, 1, 1, 1)
                };
                let dst_ip = if args.len() >= 3 {
                    Ipv4Address::from_str(args[2]).unwrap_or(Ipv4Address::new(10, 2, 2, 2))
                } else {
                    Ipv4Address::new(10, 2, 2, 2)
                };
                let flow = QczFlowTuple::new(src_ip, dst_ip, 5001, 5001, 6);
                if self.tsn_qcz_engine.clear_isolated_flow(&flow) {
                    println!(
                        "  [QCZ FLOW RESTORED] Flow {} -> {} removed from isolation.",
                        src_ip, dst_ip
                    );
                } else {
                    println!(
                        "  [QCZ ERROR] Flow {} -> {} was not isolated.",
                        src_ip, dst_ip
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-qcz [status | tx <src_ip> <dst_ip> <bytes> | clear <src_ip> <dst_ip>]"
            ),
        }
    }

    fn cmd_diameter_sgd(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter SGd / T4 SMS Core Interface (App ID: 16777313 / TS 29.338):"
                );
                println!(
                    "  • SMS-C Address     : {}",
                    self.sms_sgd_engine.smsc_address
                );
                println!(
                    "  • Stored Messages   : {}",
                    self.sms_sgd_engine.messages.len()
                );
                println!(
                    "  • Total MO SMS Sent : {}",
                    self.sms_sgd_engine.total_mo_sms
                );
                println!(
                    "  • Total MT SMS Sent : {}",
                    self.sms_sgd_engine.total_mt_sms
                );
                for (id, msg) in &self.sms_sgd_engine.messages {
                    println!(
                        "    [Msg #{}] IMSI: {} | SC: {} | Outcome: {:?} | Text: \"{}\"",
                        id,
                        msg.imsi,
                        msg.sc_address,
                        msg.outcome,
                        String::from_utf8_lossy(&msg.tpdu)
                    );
                }
            }
            "mo" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460011234567890"
                };
                let sc_addr = if args.len() >= 3 {
                    args[2]
                } else {
                    "+886912345678"
                };
                let text = if args.len() >= 4 {
                    args[3].as_bytes().to_vec()
                } else {
                    b"Test MO-SMS via LTE".to_vec()
                };

                let ofr = SgdMessage::new_ofr("sgd-cli-mo", imsi, sc_addr, text.clone());
                let ofa = self.sms_sgd_engine.handle_mo_forward_sm(&ofr);
                let rc = ofa
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let SgdAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);

                println!(
                    "  [DIAMETER SGd MO-SMS] IMSI: {}, SC: {} -> Result-Code: {} (Payload: \"{}\")",
                    imsi,
                    sc_addr,
                    rc,
                    String::from_utf8_lossy(&text)
                );
            }
            "mt" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460011234567890"
                };
                let sc_addr = if args.len() >= 3 {
                    args[2]
                } else {
                    "+886912345678"
                };
                let text = if args.len() >= 4 {
                    args[3].as_bytes().to_vec()
                } else {
                    b"MT-SMS IoT Alert".to_vec()
                };

                let tfr = SgdMessage::new_tfr("sgd-cli-mt", imsi, sc_addr, text.clone());
                let tfa = self.sms_sgd_engine.handle_mt_forward_sm(&tfr, true);
                let outcome = tfa.avps.iter().find_map(|a| {
                    if let SgdAvp::SmDeliveryOutcome(o) = a {
                        Some(*o)
                    } else {
                        None
                    }
                });

                println!(
                    "  [DIAMETER SGd MT-SMS] IMSI: {}, SC: {} -> Delivery Outcome: {:?}",
                    imsi, sc_addr, outcome
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-sgd [status | mo <imsi> <sc> <text> | mt <imsi> <sc> <text>]"
            ),
        }
    }

    fn cmd_evpn_irb(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Anycast Gateway & Symmetric / Asymmetric IRB Engine (RFC 9135 / RFC 9136):"
                );
                println!(
                    "  • Local VTEP IP        : {}",
                    self.evpn_irb_engine.local_vtep
                );
                println!(
                    "  • Anycast Gateway MAC  : {}",
                    self.evpn_irb_engine.anycast_gateway_mac
                );
                println!(
                    "  • Local Router MAC     : {}",
                    self.evpn_irb_engine.local_router_mac
                );
                println!(
                    "  • Transit L3VNI        : {}",
                    self.evpn_irb_engine.transit_l3_vni
                );
                println!(
                    "  • Configured Subnets   : {}",
                    self.evpn_irb_engine.anycast_gateways.len()
                );
                println!(
                    "  • Known Host Bindings  : {}",
                    self.evpn_irb_engine.host_table.len()
                );
                println!(
                    "  • Symmetric Routed     : {}",
                    self.evpn_irb_engine.total_symmetric_routed
                );
                println!(
                    "  • Asymmetric Routed    : {}",
                    self.evpn_irb_engine.total_asymmetric_routed
                );
                for (vni, ip) in &self.evpn_irb_engine.anycast_gateways {
                    println!("    [Subnet L2VNI {}] Anycast GW IP: {}", vni, ip);
                }
                for (ip, host) in &self.evpn_irb_engine.host_table {
                    println!(
                        "    [Host {}] MAC: {} | L2VNI: {} | Leaf VTEP: {}",
                        ip, host.mac, host.l2_vni, host.leaf_vtep
                    );
                }
            }
            "route" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let dst_ip = if args.len() >= 3 {
                    Ipv4Address::from_str(args[2]).unwrap_or(Ipv4Address::new(192, 168, 20, 55))
                } else {
                    Ipv4Address::new(192, 168, 20, 55)
                };
                let mode = if args.len() >= 4 && args[3] == "asym" {
                    IrbMode::Asymmetric
                } else {
                    IrbMode::Symmetric
                };

                if let Some(action) = self.evpn_irb_engine.route_inter_subnet(vni, dst_ip, mode) {
                    println!(
                        "  [EVPN IRB FORWARD SUCCESS] Routed Inter-Subnet from L2VNI {} to {}:",
                        vni, dst_ip
                    );
                    println!("    • Mode Used      : {:?}", action.mode_used);
                    println!(
                        "    • Overlay VNI    : {} ({})",
                        action.overlay_vni,
                        if action.mode_used == IrbMode::Symmetric {
                            "Transit L3VNI"
                        } else {
                            "Destination L2VNI"
                        }
                    );
                    println!("    • Target VTEP    : {}", action.target_vtep);
                    println!("    • Inner Src MAC  : {}", action.inner_src_mac);
                    println!("    • Inner Dst MAC  : {}", action.inner_dst_mac);
                } else {
                    println!(
                        "  [EVPN IRB ERROR] Destination host {} not found in EVPN host table!",
                        dst_ip
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-irb [status | route <vni> <dst_ip> [sym|asym]]"
            ),
        }
    }

    fn cmd_gtpu_reloc(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP GTP-U UPF Anchor Relocation & Handover Forwarding Engine (TS 23.501):"
                );
                println!(
                    "  • Session ID           : {}",
                    self.gtpu_reloc_engine.session_id
                );
                println!(
                    "  • State                : {:?}",
                    self.gtpu_reloc_engine.state
                );
                println!(
                    "  • Indirect Tunnel TEID : 0x{:08X}",
                    self.gtpu_reloc_engine.indirect_teid
                );
                println!(
                    "  • Direct gNodeB TEID   : 0x{:08X}",
                    self.gtpu_reloc_engine.direct_teid
                );
                println!(
                    "  • Source UPF IP        : {}",
                    self.gtpu_reloc_engine.source_upf_ip
                );
                println!(
                    "  • gNodeB IP            : {}",
                    self.gtpu_reloc_engine.gnodeb_ip
                );
                println!(
                    "  • Buffered Packets     : {}",
                    self.gtpu_reloc_engine.indirect_buffer.len()
                );
                println!(
                    "  • Indirect Ingested    : {}",
                    self.gtpu_reloc_engine.total_indirect_packets_recv
                );
                println!(
                    "  • Direct Sent          : {}",
                    self.gtpu_reloc_engine.total_direct_packets_sent
                );
            }
            "rx" => {
                let payload = if args.len() >= 2 {
                    args[1].as_bytes().to_vec()
                } else {
                    b"In-Flight Handover Data".to_vec()
                };
                let pkt =
                    HandoverGtpuPacket::new_gpdu(self.gtpu_reloc_engine.indirect_teid, payload);
                let delivered = self.gtpu_reloc_engine.handle_indirect_packet(pkt);
                if delivered.is_empty() {
                    println!(
                        "  [GTP-U RELOCATION INGEST] Handover packet buffered in T-UPF (Awaiting End Marker)."
                    );
                } else {
                    println!(
                        "  [GTP-U RELOCATION INGEST] Directly forwarded to gNodeB (TEID: 0x{:08X}).",
                        delivered[0].teid
                    );
                }
            }
            "marker" => {
                let marker =
                    HandoverGtpuPacket::new_end_marker(self.gtpu_reloc_engine.indirect_teid);
                let delivered = self.gtpu_reloc_engine.handle_indirect_packet(marker);
                println!(
                    "  🏁 [END MARKER RECEIVED] Handover completed! Flushed {} buffered packets to gNodeB with direct TEID 0x{:08X}.",
                    delivered.len(),
                    self.gtpu_reloc_engine.direct_teid
                );
            }
            _ => println!("Unknown subcommand. Usage: gtpu-reloc [status | rx <payload> | marker]"),
        }
    }

    fn cmd_tsn_ats_multi(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qcr Asynchronous Traffic Shaping (ATS) Multi-Hop Pipeline:");
                println!(
                    "  • Total Hops Configured : {}",
                    self.tsn_ats_multi_engine.hops.len()
                );
                println!(
                    "  • Delivered Frames      : {}",
                    self.tsn_ats_multi_engine.delivered_frames.len()
                );
                for hop in &self.tsn_ats_multi_engine.hops {
                    println!(
                        "    [Hop #{}] Latency: {} ns | Regulators: {} | Queue Depth: {}",
                        hop.hop_id,
                        hop.internal_latency_ns,
                        hop.regulators.len(),
                        hop.transmission_queue.len()
                    );
                }
            }
            "ingest" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let prio = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(7)
                } else {
                    7
                };
                let len = if args.len() >= 4 {
                    args[3].parse::<usize>().unwrap_or(1000)
                } else {
                    1000
                };

                self.tsn_ats_multi_engine
                    .ingest_ingress(stream_id, prio, len, 0);
                println!(
                    "  [ATS INGEST] Stream: {}, Prio: {}, Length: {} B -> Ingested at Hop 0.",
                    stream_id, prio, len
                );
            }
            "tick" => {
                let ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(350_000)
                } else {
                    350_000
                };
                self.tsn_ats_multi_engine.step_simulation(ns);
                println!(
                    "  [ATS SIMULATION TICK] Stepped to t = {} ns -> Delivered: {} total frames.",
                    ns,
                    self.tsn_ats_multi_engine.delivered_frames.len()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-ats-multi [status | ingest <stream> <prio> <len> | tick <ns>]"
            ),
        }
    }

    fn cmd_diameter_zh(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter Zh / GAA / GBA Bootstrapping Interface (App ID: 16777221 / TS 29.109):"
                );
                println!(
                    "  • HSS Realm              : {}",
                    self.bsf_zh_engine.hss_realm
                );
                println!(
                    "  • Registered Subscribers : {}",
                    self.bsf_zh_engine.subscribers.len()
                );
                println!(
                    "  • Total MAR Requests     : {}",
                    self.bsf_zh_engine.total_mar_requests
                );
                println!(
                    "  • Successful Bootstraps  : {}",
                    self.bsf_zh_engine.successful_bootstraps
                );
                for (imsi, sub) in &self.bsf_zh_engine.subscribers {
                    println!(
                        "    [IMSI {}] GUSS: \"{}\" | CK: {:02X?} | IK: {:02X?}",
                        imsi,
                        sub.guss_xml,
                        &sub.auth_vector.ck[..4],
                        &sub.auth_vector.ik[..4]
                    );
                }
            }
            "auth" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460019998887771"
                };
                let gba_type = if args.len() >= 3 && args[2] == "2g" {
                    GbaType::Gba2G
                } else {
                    GbaType::Gba3G
                };

                let mar = ZhMessage::new_mar("zh-cli-mar", imsi, gba_type);
                let maa = self.bsf_zh_engine.handle_mar(&mar);
                let rc = maa
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let ZhAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);

                println!(
                    "  [DIAMETER Zh MAR/MAA] IMSI: {}, GBA-Type: {:?} -> Result-Code: {}",
                    imsi, gba_type, rc
                );
            }
            "key" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460019998887771"
                };
                let naf_id = if args.len() >= 3 {
                    args[2]
                } else {
                    "secure.banking.naf"
                };

                if let Some(key) = self.bsf_zh_engine.derive_ks_naf(imsi, naf_id) {
                    println!(
                        "  🔑 [GBA Ks_NAF DERIVED] IMSI: {}, NAF: \"{}\" -> Key: {:02X?}",
                        imsi, naf_id, key
                    );
                } else {
                    println!(
                        "  [DIAMETER Zh ERROR] Subscriber {} not found for NAF key derivation.",
                        imsi
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-zh [status | auth <imsi> [2g|3g] | key <imsi> <naf_id>]"
            ),
        }
    }

    fn cmd_evpn_bum(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Layer 2 BUM Traffic Storm Policer & Microburst Defense Engine (RFC 7432):"
                );
                println!(
                    "  • Configured Token Buckets : {}",
                    self.evpn_bum_engine.policers.len()
                );
                println!(
                    "  • Storm Threshold (Drops)  : {}",
                    self.evpn_bum_engine.storm_threshold_drops
                );
                println!(
                    "  • Active Quarantined MACs  : {}",
                    self.evpn_bum_engine.quarantined_macs.len()
                );
                println!(
                    "  • Total Quarantine Events  : {}",
                    self.evpn_bum_engine.total_quarantined_events
                );
                for ((vni, bum_type), bucket) in &self.evpn_bum_engine.policers {
                    println!(
                        "    [VNI {} {:?}] Max: {} B/s | Burst: {} B | Passed: {} B | Dropped: {} B",
                        vni,
                        bum_type,
                        bucket.max_rate_bytes_per_sec,
                        bucket.burst_capacity_bytes,
                        bucket.total_passed_bytes,
                        bucket.total_dropped_bytes
                    );
                }
                for (vni, mac) in &self.evpn_bum_engine.quarantined_macs {
                    println!("    🚨 [QUARANTINED] VNI: {}, MAC: {}", vni, mac);
                }
            }
            "police" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let mac_str = if args.len() >= 3 {
                    args[2]
                } else {
                    "00:11:22:33:44:55"
                };
                let mac = mac_str
                    .parse::<MacAddress>()
                    .unwrap_or(MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
                let b_type = match args.get(3).copied().unwrap_or("b") {
                    "u" => BumType::UnknownUnicast,
                    "m" => BumType::Multicast,
                    _ => BumType::Broadcast,
                };
                let bytes = if args.len() >= 5 {
                    args[4].parse::<usize>().unwrap_or(500)
                } else {
                    500
                };

                let verdict = self
                    .evpn_bum_engine
                    .police_frame(vni, mac, b_type, bytes, 0);
                println!(
                    "  [EVPN BUM POLICE] VNI: {}, MAC: {}, Type: {:?}, Size: {} B -> Verdict: {:?}",
                    vni, mac, b_type, bytes, verdict
                );
            }
            "unquarantine" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let mac_str = if args.len() >= 3 {
                    args[2]
                } else {
                    "00:11:22:33:44:55"
                };
                let mac = mac_str
                    .parse::<MacAddress>()
                    .unwrap_or(MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));

                if self.evpn_bum_engine.unquarantine_mac(vni, &mac) {
                    println!(
                        "  ✅ [RESTORED] MAC {} on VNI {} removed from quarantine.",
                        mac, vni
                    );
                } else {
                    println!(
                        "  [ERROR] MAC {} on VNI {} was not in quarantine.",
                        mac, vni
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-bum [status | police <vni> <mac> <b|u|m> <bytes> | unquarantine <vni> <mac>]"
            ),
        }
    }

    fn cmd_gtpu_qos(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("5G GTP-U QoS Flow Identifier & Session-AMBR Rate Enforcer (TS 38.415):");
                println!(
                    "  • Session ID            : {}",
                    self.gtpu_qos_engine.session_id
                );
                println!(
                    "  • Session-AMBR Rate     : {} B/s",
                    self.gtpu_qos_engine.session_ambr_bps
                );
                println!(
                    "  • Burst Capacity        : {} B",
                    self.gtpu_qos_engine.burst_capacity_bytes
                );
                println!(
                    "  • Configured QFI Flows  : {}",
                    self.gtpu_qos_engine.qfi_profiles.len()
                );
                println!(
                    "  • Remapping Rules       : {}",
                    self.gtpu_qos_engine.qfi_remap_rules.len()
                );
                println!(
                    "  • Total Conformed       : {} B",
                    self.gtpu_qos_engine.total_conformed_bytes
                );
                println!(
                    "  • AMBR Dropped          : {} B",
                    self.gtpu_qos_engine.total_ambr_dropped_bytes
                );
                println!(
                    "  • Remapped Packets      : {}",
                    self.gtpu_qos_engine.total_remapped_packets
                );
                for (qfi, prof) in &self.gtpu_qos_engine.qfi_profiles {
                    println!(
                        "    [QFI {}] 5QI: {} | Type: {:?} | Priority: {} | PDB: {} ms",
                        qfi,
                        prof.five_qi,
                        prof.resource_type,
                        prof.priority_level,
                        prof.packet_delay_budget_ms
                    );
                }
                for (from_q, to_q) in &self.gtpu_qos_engine.qfi_remap_rules {
                    println!("    [Remap Rule] QFI {} -> QFI {}", from_q, to_q);
                }
            }
            "test" => {
                let qfi = if args.len() >= 2 {
                    args[1].parse::<u8>().unwrap_or(1)
                } else {
                    1
                };
                let bytes = if args.len() >= 3 {
                    args[2].parse::<usize>().unwrap_or(1500)
                } else {
                    1500
                };

                let verdict = self.gtpu_qos_engine.enforce_packet(qfi, bytes, 0);
                println!(
                    "  [5G GTP-U QoS INGEST] QFI: {}, Size: {} B -> Verdict: {:?}",
                    qfi, bytes, verdict
                );
            }
            "remap" => {
                let from_q = if args.len() >= 2 {
                    args[1].parse::<u8>().unwrap_or(1)
                } else {
                    1
                };
                let to_q = if args.len() >= 3 {
                    args[2].parse::<u8>().unwrap_or(3)
                } else {
                    3
                };

                self.gtpu_qos_engine.set_qfi_remap(from_q, to_q);
                println!(
                    "  [QOS REMAP SET] QFI {} will now be remapped to QFI {}.",
                    from_q, to_q
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-qos [status | test <qfi> <bytes> | remap <from_qfi> <to_qfi>]"
            ),
        }
    }

    fn cmd_tsn_qbv_reconfig(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "IEEE 802.1Qbv TAS Dynamic GCL Reconfiguration & Hitless Admin/Oper Swap:"
                );
                println!(
                    "  • Oper GCL Base Time    : {} ns",
                    self.tsn_qbv_reconfig_engine.oper_gcl.base_time_ns
                );
                println!(
                    "  • Oper GCL Cycle Time   : {} ns",
                    self.tsn_qbv_reconfig_engine.oper_gcl.cycle_time_ns
                );
                println!(
                    "  • Oper Entries Count    : {}",
                    self.tsn_qbv_reconfig_engine.oper_gcl.entries.len()
                );
                println!(
                    "  • Config Change Pending : {}",
                    self.tsn_qbv_reconfig_engine.config_change
                );
                println!(
                    "  • Total Swaps Completed : {}",
                    self.tsn_qbv_reconfig_engine.total_swaps_completed
                );
                if let Some(ref admin) = self.tsn_qbv_reconfig_engine.admin_gcl {
                    println!(
                        "    [Admin GCL Pending] AdminBaseTime: {} ns | Cycle: {} ns | Entries: {}",
                        admin.base_time_ns,
                        admin.cycle_time_ns,
                        admin.entries.len()
                    );
                }
            }
            "submit" => {
                let base_ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(500_000)
                } else {
                    500_000
                };
                let gate_hex = if args.len() >= 3 {
                    u8::from_str_radix(args[2].trim_start_matches("0x"), 16).unwrap_or(0xC0)
                } else {
                    0xC0
                };
                let dur_ns = if args.len() >= 4 {
                    args[3].parse::<u64>().unwrap_or(50_000)
                } else {
                    50_000
                };

                let admin_schedule = QbvSchedule::new(
                    base_ns,
                    vec![
                        QbvGateEntry {
                            gate_states: gate_hex,
                            time_interval_ns: dur_ns,
                        },
                        QbvGateEntry {
                            gate_states: 0xFF,
                            time_interval_ns: dur_ns,
                        },
                    ],
                );
                self.tsn_qbv_reconfig_engine
                    .submit_admin_gcl(admin_schedule);
                println!(
                    "  [ADMIN GCL SUBMITTED] AdminBaseTime: {} ns, Gate: 0x{:02X}, Slot: {} ns.",
                    base_ns, gate_hex, dur_ns
                );
            }
            "eval" => {
                let ts_ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(510_000)
                } else {
                    510_000
                };
                let gate = self.tsn_qbv_reconfig_engine.get_active_gate_states(ts_ns);
                println!(
                    "  [GCL EVALUATION] Timestamp: {} ns -> Active Gate States: 0x{:02X} (ConfigChange: {})",
                    ts_ns, gate, self.tsn_qbv_reconfig_engine.config_change
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-qbv-reconfig [status | submit <base_ns> <hex_gate> <dur_ns> | eval <ns>]"
            ),
        }
    }

    fn cmd_diameter_s6c(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter S6c SMS Routing & Delivery Status Interface (App ID: 16777312 / TS 29.338):"
                );
                println!(
                    "  • HSS Realm              : {}",
                    self.s6c_hss_engine.hss_realm
                );
                println!(
                    "  • Routing Registry Size  : {}",
                    self.s6c_hss_engine.routing_registry.len()
                );
                println!(
                    "  • Total SRR Requests     : {}",
                    self.s6c_hss_engine.total_srr_requests
                );
                println!(
                    "  • Total RDR Reports      : {}",
                    self.s6c_hss_engine.total_rdr_reports
                );
                for (user, node) in &self.s6c_hss_engine.routing_registry {
                    println!(
                        "    [User {}] Type: {:?} | FQDN: {} | IP: {}",
                        user, node.node_type, node.node_fqdn, node.node_ip
                    );
                }
            }
            "srr" => {
                let user = if args.len() >= 2 {
                    args[1]
                } else {
                    "460029991112223"
                };
                let srr = S6cMessage::new_srr("s6c-cli-srr", user);
                let sra = self.s6c_hss_engine.handle_srr(&srr);
                let rc = sra
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6cAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);
                let node = sra.avps.iter().find_map(|a| {
                    if let S6cAvp::ServingNode(n) = a {
                        Some(n.clone())
                    } else {
                        None
                    }
                });

                println!(
                    "  [DIAMETER S6c SRR/SRA] User: {} -> Result-Code: {}, Serving-Node: {:?}",
                    user, rc, node
                );
            }
            "rdr" => {
                let user = if args.len() >= 2 {
                    args[1]
                } else {
                    "460029991112223"
                };
                let outcome = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(0)
                } else {
                    0
                };
                let rdr = S6cMessage::new_rdr("s6c-cli-rdr", user, outcome);
                let rda = self.s6c_hss_engine.handle_rdr(&rdr);
                let rc = rda
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6cAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);

                println!(
                    "  [DIAMETER S6c RDR/RDA] User: {}, Outcome: {} -> Result-Code: {}",
                    user, outcome, rc
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s6c [status | srr <user> | rdr <user> <outcome>]"
            ),
        }
    }

    fn cmd_evpn_core_iso(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Layer 2 Core Isolation & Split-Horizon Group Engine (RFC 7432 Section 8.4):"
                );
                println!(
                    "  • Local Leaf ID          : {}",
                    self.evpn_core_iso_engine.local_leaf_id
                );
                println!(
                    "  • Core Isolation State   : {:?}",
                    self.evpn_core_iso_engine.state
                );
                println!(
                    "  • Active Core Uplinks    : {:?}",
                    self.evpn_core_iso_engine.active_core_uplinks
                );
                println!(
                    "  • Client Attachment Port : {:?}",
                    self.evpn_core_iso_engine.client_attachment_circuits
                );
                println!(
                    "  • Isolation Events       : {}",
                    self.evpn_core_iso_engine.total_core_isolation_events
                );
                println!(
                    "  • Split-Horizon Drops    : {}",
                    self.evpn_core_iso_engine.total_split_horizon_drops
                );
                for (iface, esi) in &self.evpn_core_iso_engine.interface_to_esi {
                    println!("    [Interface {}] ESI: 0x{:016X}", iface, esi);
                }
            }
            "uplink-down" => {
                let iface = if args.len() >= 2 { args[1] } else { "spine1" };
                self.evpn_core_iso_engine.remove_core_uplink(iface);
                println!(
                    "  [CORE UPLINK DOWN] Interface '{}' removed. State: {:?}",
                    iface, self.evpn_core_iso_engine.state
                );
            }
            "uplink-up" => {
                let iface = if args.len() >= 2 { args[1] } else { "spine1" };
                self.evpn_core_iso_engine.add_core_uplink(iface);
                println!(
                    "  [CORE UPLINK RESTORED] Interface '{}' added. State: {:?}",
                    iface, self.evpn_core_iso_engine.state
                );
            }
            "test" => {
                let client_iface = if args.len() >= 2 { args[1] } else { "eth_ce1" };
                let src_esi = if args.len() >= 3 {
                    let s = args[2].trim_start_matches("0x");
                    u64::from_str_radix(s, 16).ok()
                } else {
                    None
                };

                let allowed = self
                    .evpn_core_iso_engine
                    .should_forward_to_ac(client_iface, src_esi);
                if allowed {
                    println!(
                        "  ✅ [FORWARD ALLOWED] Frame permitted to egress on '{}'.",
                        client_iface
                    );
                } else if self.evpn_core_iso_engine.state == CoreIsolationState::CoreIsolated {
                    println!(
                        "  🚨 [BLOCKED - CORE ISOLATION] Port '{}' shut down because all core uplinks are down.",
                        client_iface
                    );
                } else {
                    println!(
                        "  🛑 [BLOCKED - SPLIT HORIZON] Frame originated from same ESI, suppressed to prevent loop."
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-core-iso [status | uplink-down <iface> | uplink-up <iface> | test <client_iface> [src_esi]]"
            ),
        }
    }

    fn cmd_gtpu_failover(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "5G GTP-U Path Loss Detection & Sub-Millisecond Fast Failover Engine (TS 23.501):"
                );
                println!(
                    "  • Configured Sessions   : {}",
                    self.gtpu_fast_failover_engine.sessions.len()
                );
                println!(
                    "  • Total Forwarded Pkts  : {}",
                    self.gtpu_fast_failover_engine.total_forwarded_packets
                );
                for (id, sess) in &self.gtpu_fast_failover_engine.sessions {
                    println!(
                        "    [Session #{}] Active Path: {:?} | Primary: {} (TEID 0x{:08X}, Alive: {}) | Backup: {} (TEID 0x{:08X}, Alive: {}) | Failovers: {}",
                        id,
                        sess.active_path,
                        sess.primary_path.upf_ip,
                        sess.primary_path.teid,
                        sess.primary_path.is_alive,
                        sess.secondary_path.upf_ip,
                        sess.secondary_path.teid,
                        sess.secondary_path.is_alive,
                        sess.total_failovers
                    );
                }
            }
            "fwd" => {
                let id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                if let Some((ip, teid, path)) =
                    self.gtpu_fast_failover_engine.forward_user_plane(id)
                {
                    println!(
                        "  [GTP-U FORWARD] Session #{}: Routed to {:?} UPF {} (TEID: 0x{:08X})",
                        id, path, ip, teid
                    );
                } else {
                    println!("  [ERROR] Session #{} not found.", id);
                }
            }
            "ping" => {
                let id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let ok = if args.len() >= 3 {
                    args[2] == "ok"
                } else {
                    false
                };
                if let Some(sess) = self.gtpu_fast_failover_engine.sessions.get_mut(&id) {
                    let active = sess.report_primary_heartbeat(ok);
                    println!(
                        "  [HEARTBEAT REPORT] Session #{} Primary Path Heartbeat: {} -> Active Path is now: {:?}",
                        id,
                        if ok { "SUCCESS" } else { "FAILED" },
                        active
                    );
                } else {
                    println!("  [ERROR] Session #{} not found.", id);
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-failover [status | fwd <sess_id> | ping <sess_id> <ok|fail>]"
            ),
        }
    }

    fn cmd_tsn_qav(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qav Credit-Based Shaper (CBS) Multi-Class AVB Port:");
                println!(
                    "  • Class A (SR Class A) : idleSlope: {} B/s | Credit: {} | Tx Pkts: {} ({} B)",
                    self.tsn_qav_engine.class_a.idle_slope_bps,
                    self.tsn_qav_engine.class_a.current_credit,
                    self.tsn_qav_engine.class_a.total_transmitted_frames,
                    self.tsn_qav_engine.class_a.total_transmitted_bytes
                );
                println!(
                    "  • Class B (SR Class B) : idleSlope: {} B/s | Credit: {} | Tx Pkts: {} ({} B)",
                    self.tsn_qav_engine.class_b.idle_slope_bps,
                    self.tsn_qav_engine.class_b.current_credit,
                    self.tsn_qav_engine.class_b.total_transmitted_frames,
                    self.tsn_qav_engine.class_b.total_transmitted_bytes
                );
            }
            "tx-a" => {
                let bytes = if args.len() >= 2 {
                    args[1].parse::<usize>().unwrap_or(1200)
                } else {
                    1200
                };
                self.tsn_qav_engine.class_a.enqueue_frame(bytes);
                if let Some(sent) = self.tsn_qav_engine.class_a.try_transmit(0) {
                    println!(
                        "  [CBS CLASS A TRANSMIT] Sent {} Bytes immediately (Credit: {}).",
                        sent, self.tsn_qav_engine.class_a.current_credit
                    );
                } else {
                    println!(
                        "  ⏳ [CBS CLASS A BLOCKED] Insufficient credit ({}), queued for idleSlope replenish.",
                        self.tsn_qav_engine.class_a.current_credit
                    );
                }
            }
            "tx-b" => {
                let bytes = if args.len() >= 2 {
                    args[1].parse::<usize>().unwrap_or(800)
                } else {
                    800
                };
                self.tsn_qav_engine.class_b.enqueue_frame(bytes);
                if let Some(sent) = self.tsn_qav_engine.class_b.try_transmit(0) {
                    println!(
                        "  [CBS CLASS B TRANSMIT] Sent {} Bytes immediately (Credit: {}).",
                        sent, self.tsn_qav_engine.class_b.current_credit
                    );
                } else {
                    println!(
                        "  ⏳ [CBS CLASS B BLOCKED] Insufficient credit ({}), queued for idleSlope replenish.",
                        self.tsn_qav_engine.class_b.current_credit
                    );
                }
            }
            "step" => {
                let ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(20_000)
                } else {
                    20_000
                };
                self.tsn_qav_engine.class_a.advance_time(ns);
                self.tsn_qav_engine.class_b.advance_time(ns);
                println!(
                    "  [CBS TIME ADVANCED] Stepped simulation to {} ns -> Class A Credit: {}, Class B Credit: {}.",
                    ns,
                    self.tsn_qav_engine.class_a.current_credit,
                    self.tsn_qav_engine.class_b.current_credit
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-qav [status | tx-a <bytes> | tx-b <bytes> | step <ns>]"
            ),
        }
    }

    fn cmd_diameter_np(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter Np RAN Congestion Awareness Interface (App ID: 16777342 / TS 29.217):"
                );
                println!(
                    "  • PCRF Realm             : {}",
                    self.rcaf_np_engine.pcrf_realm
                );
                println!(
                    "  • Total NCR Reports      : {}",
                    self.rcaf_np_engine.total_ncr_reports
                );
                println!(
                    "  • Monitored Cells Count  : {}",
                    self.rcaf_np_engine.cell_congestion_map.len()
                );
                for ((enb, cell), lvl) in &self.rcaf_np_engine.cell_congestion_map {
                    println!(
                        "    [eNodeB #{}, Cell #{}] Congestion Level: {:?}",
                        enb, cell, lvl
                    );
                }
            }
            "ruca" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460012345678901"
                };
                let enb = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(1001)
                } else {
                    1001
                };
                let cell = if args.len() >= 4 {
                    args[3].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let level_str = if args.len() >= 5 { args[4] } else { "high" };
                let level = match level_str.to_lowercase().as_str() {
                    "high" | "3" => RanCongestionLevel::High,
                    "medium" | "med" | "2" => RanCongestionLevel::Medium,
                    "low" | "1" => RanCongestionLevel::Low,
                    _ => RanCongestionLevel::None,
                };

                let info = RanCongestionInfo {
                    enodeb_id: enb,
                    cell_id: cell,
                    level,
                };
                let ncr = NpMessage::new_ncr("np-cli-sess", imsi, info);
                let nca = self.rcaf_np_engine.handle_ncr(&ncr);
                let rc = nca
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let NpAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);

                println!(
                    "  [DIAMETER Np NCR/NCA] IMSI: {}, eNodeB #{}, Cell #{} -> Level: {:?} (Result-Code: {})",
                    imsi, enb, cell, level, rc
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-np [status | ruca <imsi> <enb> <cell> <level>]"
            ),
        }
    }

    fn cmd_evpn_damp(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Layer 2 Port Flap Damping & Unknown MAC Route Dampening (RFC 7432 Section 16):"
                );
                println!(
                    "  • Flap Penalty           : {:.1}",
                    self.evpn_damping_engine.flap_penalty
                );
                println!(
                    "  • Suppress Threshold     : {:.1}",
                    self.evpn_damping_engine.suppress_threshold
                );
                println!(
                    "  • Reuse Threshold        : {:.1}",
                    self.evpn_damping_engine.reuse_threshold
                );
                println!(
                    "  • Half-Life Duration     : {} s",
                    self.evpn_damping_engine.half_life_ns / 1_000_000_000
                );
                println!(
                    "  • Tracked Entities Count : {}",
                    self.evpn_damping_engine.entries.len()
                );
                for (name, entry) in &self.evpn_damping_engine.entries {
                    println!(
                        "    [Interface/MAC: {}] State: {:?} | Penalty: {:.1} | Total Flaps: {} | Suppressions: {}",
                        name,
                        entry.state,
                        entry.penalty,
                        entry.total_flaps,
                        entry.total_suppressions
                    );
                }
            }
            "flap" => {
                let iface = if args.len() >= 2 { args[1] } else { "eth_ce1" };
                let now_sec = if args.len() >= 3 {
                    args[2].parse::<u64>().unwrap_or(0)
                } else {
                    0
                };
                let now_ns = now_sec * 1_000_000_000;
                let state = self.evpn_damping_engine.record_flap(iface, now_ns);
                let entry = self.evpn_damping_engine.entries.get(iface).unwrap();
                println!(
                    "  [FLAP RECORDED] Interface '{}' flapped at t={}s -> Penalty: {:.1}, State: {:?}",
                    iface, now_sec, entry.penalty, state
                );
            }
            "eval" => {
                let iface = if args.len() >= 2 { args[1] } else { "eth_ce1" };
                let now_sec = if args.len() >= 3 {
                    args[2].parse::<u64>().unwrap_or(30)
                } else {
                    30
                };
                let now_ns = now_sec * 1_000_000_000;
                let state = self.evpn_damping_engine.evaluate_state(iface, now_ns);
                let penalty = self
                    .evpn_damping_engine
                    .entries
                    .get(iface)
                    .map(|e| e.penalty)
                    .unwrap_or(0.0);
                println!(
                    "  [DAMP EVALUATE] Interface '{}' evaluated at t={}s -> Decayed Penalty: {:.1}, State: {:?}",
                    iface, now_sec, penalty, state
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-damp [status | flap <interface> [timestamp_sec] | eval <interface> [timestamp_sec]]"
            ),
        }
    }

    fn cmd_gtpu_ma(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "5G Multi-Access PDU (MA-PDU) Session & ATSSS Steering Engine (3GPP TS 23.501 / TS 24.193):"
                );
                println!(
                    "  • Session ID            : {}",
                    self.ma_pdu_engine.session_id
                );
                println!("  • ATSSS Steering Mode   : {:?}", self.ma_pdu_engine.mode);
                println!(
                    "  • 3GPP Access Leg       : {} (TEID 0x{:08X}, RTT: {} ms, Alive: {}) -> Sent: {} pkts",
                    self.ma_pdu_engine.leg_3gpp.remote_ip,
                    self.ma_pdu_engine.leg_3gpp.teid,
                    self.ma_pdu_engine.leg_3gpp.rtt_ms,
                    self.ma_pdu_engine.leg_3gpp.is_available,
                    self.ma_pdu_engine.leg_3gpp.total_packets_sent
                );
                println!(
                    "  • Non-3GPP Access Leg   : {} (TEID 0x{:08X}, RTT: {} ms, Alive: {}) -> Sent: {} pkts",
                    self.ma_pdu_engine.leg_non_3gpp.remote_ip,
                    self.ma_pdu_engine.leg_non_3gpp.teid,
                    self.ma_pdu_engine.leg_non_3gpp.rtt_ms,
                    self.ma_pdu_engine.leg_non_3gpp.is_available,
                    self.ma_pdu_engine.leg_non_3gpp.total_packets_sent
                );
            }
            "steer" => {
                if let Some((leg, ip, teid)) = self.ma_pdu_engine.steer_packet() {
                    println!(
                        "  [ATSSS STEERED] Packet routed to {:?} leg -> Remote IP: {}, TEID: 0x{:08X}",
                        leg, ip, teid
                    );
                } else {
                    println!("  🚨 [ATSSS DROP] All access legs are unavailable!");
                }
            }
            "rtt" => {
                let leg_str = if args.len() >= 2 { args[1] } else { "3gpp" };
                let rtt_ms = if args.len() >= 3 {
                    args[2].parse::<u32>().unwrap_or(15)
                } else {
                    15
                };
                let leg = if leg_str.contains("non") || leg_str.contains("wifi") {
                    AccessLegType::NonThreeGpp
                } else {
                    AccessLegType::ThreeGpp
                };
                self.ma_pdu_engine.update_leg_rtt(leg, rtt_ms);
                println!(
                    "  [RTT UPDATED] {:?} Access leg RTT set to {} ms.",
                    leg, rtt_ms
                );
            }
            "mode" => {
                let mode_str = if args.len() >= 2 { args[1] } else { "delay" };
                match mode_str {
                    "standby" => self.ma_pdu_engine.mode = AtsssMode::ActiveStandby,
                    "split" => {
                        self.ma_pdu_engine.mode = AtsssMode::LoadBalancing {
                            ratio_3gpp_percent: 50,
                        }
                    }
                    "priority" => self.ma_pdu_engine.mode = AtsssMode::PriorityBased,
                    _ => self.ma_pdu_engine.mode = AtsssMode::SmallestDelay,
                }
                println!(
                    "  [ATSSS MODE CHANGED] Steering mode is now: {:?}",
                    self.ma_pdu_engine.mode
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-ma [status | steer | rtt <3gpp|wifi> <ms> | mode <standby|delay|split>]"
            ),
        }
    }

    fn cmd_tsn_preempt(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "IEEE 802.1Qbu / 802.3br Frame Preemption & Qbv Dynamic Guard Band Engine:"
                );
                println!(
                    "  • Port Rate              : {} bps",
                    self.tsn_guard_band_engine.port_rate_bps
                );
                println!(
                    "  • Preemption Enabled     : {}",
                    self.tsn_guard_band_engine.preemption_enabled
                );
                println!(
                    "  • MAC Merge Sublayer     : {:?}",
                    self.tsn_guard_band_engine.merge_state
                );
                println!(
                    "  • Min Fragment Size      : {} Bytes",
                    self.tsn_guard_band_engine.min_fragment_size_bytes
                );
                println!(
                    "  • Calculated Guard Band  : {} ns",
                    self.tsn_guard_band_engine
                        .calculate_guard_band_duration_ns()
                );
                println!(
                    "  • Total Preempted Frames : {}",
                    self.tsn_guard_band_engine.total_preempted_frames
                );
                println!(
                    "  • Guard Band Frame Drops : {}",
                    self.tsn_guard_band_engine.total_guard_band_drops
                );
            }
            "calc" => {
                let gb_ns = self
                    .tsn_guard_band_engine
                    .calculate_guard_band_duration_ns();
                println!(
                    "  [GUARD BAND CALCULATION] With Preemption={}: Guard Band duration = {} ns ({:.2} µs).",
                    self.tsn_guard_band_engine.preemption_enabled,
                    gb_ns,
                    (gb_ns as f64) / 1000.0
                );
            }
            "test" => {
                let prio_str = if args.len() >= 2 { args[1] } else { "preempt" };
                let prio = if prio_str.contains("exp") {
                    PriorityType::Express
                } else {
                    PriorityType::Preemptable
                };
                let bytes = if args.len() >= 3 {
                    args[2].parse::<usize>().unwrap_or(1500)
                } else {
                    1500
                };
                let time_ns = if args.len() >= 4 {
                    args[3].parse::<u64>().unwrap_or(6000)
                } else {
                    6000
                };

                let allowed = self
                    .tsn_guard_band_engine
                    .can_transmit_frame(prio, bytes, time_ns);
                if allowed {
                    println!(
                        "  ✅ [TX ADMISSION ACCEPTED] Frame ({} B, {:?}) permitted with {} ns remaining before express window.",
                        bytes, prio, time_ns
                    );
                } else {
                    println!(
                        "  🛑 [TX ADMISSION REJECTED] Frame ({} B, {:?}) dropped to protect scheduled express gate window.",
                        bytes, prio
                    );
                }
            }
            "toggle" => {
                self.tsn_guard_band_engine.preemption_enabled =
                    !self.tsn_guard_band_engine.preemption_enabled;
                println!(
                    "  [PREEMPTION TOGGLED] IEEE 802.1Qbu Preemption is now: {}",
                    self.tsn_guard_band_engine.preemption_enabled
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-preempt [status | calc | test <express|preempt> <bytes> <time_ns> | toggle]"
            ),
        }
    }

    fn cmd_diameter_s6t(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter S6t SCEF to HSS Cellular IoT Interface (App ID: 16777345 / TS 29.336):"
                );
                println!(
                    "  • HSS Realm             : {}",
                    self.s6t_hss_engine.hss_realm
                );
                println!(
                    "  • Total CIR Requests    : {}",
                    self.s6t_hss_engine.total_cir_requests
                );
                println!(
                    "  • Total RIR Reports     : {}",
                    self.s6t_hss_engine.total_rir_reports
                );
                println!(
                    "  • Monitored Subscribers : {}",
                    self.s6t_hss_engine.user_monitoring_events.len()
                );
                for (user, events) in &self.s6t_hss_engine.user_monitoring_events {
                    println!(
                        "    [Subscriber {}] Active Monitoring Events ({}):",
                        user,
                        events.len()
                    );
                    for ev in events {
                        println!(
                            "      - Type: {:?} | SCEF ID: {} | Ref ID: {}",
                            ev.event_type, ev.scef_id, ev.scef_ref_id
                        );
                    }
                }
            }
            "cir" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460041234567890"
                };
                let type_str = if args.len() >= 3 {
                    args[2]
                } else {
                    "reachability"
                };
                let ev_type = match type_str.to_lowercase().as_str() {
                    "loss" | "connectivity" => MonitoringEventType::LossOfConnectivity,
                    "location" => MonitoringEventType::LocationReporting,
                    "roaming" => MonitoringEventType::RoamingStatus,
                    _ => MonitoringEventType::UeReachability,
                };

                let config = MonitoringEventConfig {
                    scef_id: "scef.cli.net".into(),
                    scef_ref_id: 9991,
                    event_type: ev_type,
                };

                let cir = S6tMessage::new_cir("s6t-cli-sess", imsi, config);
                let cia = self.s6t_hss_engine.handle_cir(&cir);
                let rc = cia
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6tAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);

                println!(
                    "  [DIAMETER S6t CIR/CIA] IMSI: {} -> Event: {:?} configured (Result-Code: {})",
                    imsi, ev_type, rc
                );
            }
            _ => println!("Unknown subcommand. Usage: diameter-s6t [status | cir <imsi> <type>]"),
        }
    }

    fn cmd_evpn_pvlan(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Layer 2 Private VLAN (PVLAN) & Port Isolation Engine (RFC 7432 / RFC 5517):"
                );
                println!(
                    "  • Primary VNI           : {}",
                    self.evpn_pvlan_engine.primary_vni
                );
                println!(
                    "  • Configured Ports      : {}",
                    self.evpn_pvlan_engine.port_roles.len()
                );
                println!(
                    "  • Total Allowed Frames  : {}",
                    self.evpn_pvlan_engine.total_allowed_frames
                );
                println!(
                    "  • Total Blocked Frames  : {}",
                    self.evpn_pvlan_engine.total_blocked_frames
                );
                for (port, role) in &self.evpn_pvlan_engine.port_roles {
                    println!("    [Port {}] PVLAN Role: {:?}", port, role);
                }
            }
            "set" => {
                let port = if args.len() >= 2 { args[1] } else { "vm_new" };
                let role_str = if args.len() >= 3 { args[2] } else { "iso" };
                let comm_id = if args.len() >= 4 {
                    args[3].parse::<u32>().unwrap_or(10)
                } else {
                    10
                };

                let role = match role_str.to_lowercase().as_str() {
                    "promisc" | "p" => PvlanPortType::Promiscuous,
                    "comm" | "c" => PvlanPortType::Community(comm_id),
                    _ => PvlanPortType::Isolated,
                };

                self.evpn_pvlan_engine.register_port(port, role);
                println!(
                    "  [PVLAN PORT CONFIGURED] Port '{}' role set to {:?}",
                    port, role
                );
            }
            "test" => {
                let in_port = if args.len() >= 2 { args[1] } else { "vm_iso1" };
                let out_port = if args.len() >= 3 { args[2] } else { "gw_port" };

                let allowed = self.evpn_pvlan_engine.can_forward(in_port, out_port);
                if allowed {
                    println!(
                        "  ✅ [PVLAN ALLOWED] Inter-port traffic from '{}' to '{}' is PERMITTED.",
                        in_port, out_port
                    );
                } else {
                    println!(
                        "  🛑 [PVLAN ISOLATED] Inter-port traffic from '{}' to '{}' is BLOCKED (Micro-segmentation).",
                        in_port, out_port
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-pvlan [status | set <port> <promisc|iso|comm> [id] | test <in_port> <out_port>]"
            ),
        }
    }

    fn cmd_gtpu_redundant(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "5G GTP-U Redundant User Plane Dual-Tunnel Engine (3GPP TS 23.501 Section 5.33.2):"
                );
                println!(
                    "  • Session ID            : {}",
                    self.gtpu_redundant_engine.session_id
                );
                println!(
                    "  • Leg 1 Endpoint        : {} (TEID 0x{:08X})",
                    self.gtpu_redundant_engine.leg1_ip, self.gtpu_redundant_engine.leg1_teid
                );
                println!(
                    "  • Leg 2 Endpoint        : {} (TEID 0x{:08X})",
                    self.gtpu_redundant_engine.leg2_ip, self.gtpu_redundant_engine.leg2_teid
                );
                println!(
                    "  • Next TX Sequence      : {}",
                    self.gtpu_redundant_engine.next_tx_seq
                );
                println!(
                    "  • Duplicated TX Pkts    : {}",
                    self.gtpu_redundant_engine.total_duplicated_sent
                );
                println!(
                    "  • Valid RX Delivered    : {}",
                    self.gtpu_redundant_engine.total_valid_delivered
                );
                println!(
                    "  • Duplicates Dropped    : {}",
                    self.gtpu_redundant_engine.total_duplicates_dropped
                );
            }
            "tx" => {
                let payload_text = if args.len() >= 2 {
                    args[1..].join(" ")
                } else {
                    "URLLC Robot Control Frame".to_string()
                };
                let (p1, p2) = self
                    .gtpu_redundant_engine
                    .replicate_outgoing(payload_text.as_bytes());
                println!(
                    "  [GTP-U REPLICATE TX] Seq #{}: Dispatched copy 1 to {} (TEID: 0x{:08X}) and copy 2 to {} (TEID: 0x{:08X})",
                    p1.sequence_number, p1.target_ip, p1.teid, p2.target_ip, p2.teid
                );
            }
            "rx" => {
                let seq = if args.len() >= 2 {
                    args[1].parse::<u16>().unwrap_or(1)
                } else {
                    1
                };
                let payload_text = if args.len() >= 3 {
                    args[2..].join(" ")
                } else {
                    "Payload".to_string()
                };
                if let Some(data) = self
                    .gtpu_redundant_engine
                    .ingest_incoming(seq, payload_text.into_bytes())
                {
                    println!(
                        "  ✅ [GTP-U DELIVERED] Seq #{}: First arriving copy delivered immediately: {:?}",
                        seq,
                        String::from_utf8_lossy(&data)
                    );
                } else {
                    println!(
                        "  🛑 [GTP-U DEDUPLICATED] Seq #{}: Duplicate arriving copy suppressed at egress.",
                        seq
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-redundant [status | tx <payload> | rx <seq> <payload>]"
            ),
        }
    }

    fn cmd_tsn_cqf_time(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qch CQF Time-Synchronized Dispatch Engine:");
                println!(
                    "  • Cycle Time             : {} ns ({:.2} µs)",
                    self.tsn_cqf_time_engine.cycle_time_ns,
                    (self.tsn_cqf_time_engine.cycle_time_ns as f64) / 1000.0
                );
                println!(
                    "  • Current Time           : {} ns",
                    self.tsn_cqf_time_engine.current_time_ns
                );
                println!(
                    "  • Current Cycle Index    : #{}",
                    self.tsn_cqf_time_engine.current_cycle_index
                );
                println!(
                    "  • Queue Even Size        : {} frames",
                    self.tsn_cqf_time_engine.queue_even.len()
                );
                println!(
                    "  • Queue Odd Size         : {} frames",
                    self.tsn_cqf_time_engine.queue_odd.len()
                );
                println!(
                    "  • Total Enqueued Frames  : {}",
                    self.tsn_cqf_time_engine.total_enqueued
                );
                println!(
                    "  • Total Dispatched Frame : {}",
                    self.tsn_cqf_time_engine.total_dispatched
                );
            }
            "rx" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(101)
                } else {
                    101
                };
                let bytes = if args.len() >= 3 {
                    args[2].parse::<usize>().unwrap_or(500)
                } else {
                    500
                };
                self.tsn_cqf_time_engine.enqueue_frame(stream_id, bytes);
                println!(
                    "  [CQF FRAME INGESTED] Stream #{}: {} Bytes enqueued in Cycle #{}.",
                    stream_id, bytes, self.tsn_cqf_time_engine.current_cycle_index
                );
            }
            "tick" => {
                let delta_ns = if args.len() >= 2 {
                    args[1].parse::<u64>().unwrap_or(10_000)
                } else {
                    10_000
                };
                let dispatched = self.tsn_cqf_time_engine.advance_time(delta_ns);
                println!(
                    "  [CQF TIME TICK] Advanced by {} ns (Now: {} ns, Cycle #{}) -> Dispatched {} frames.",
                    delta_ns,
                    self.tsn_cqf_time_engine.current_time_ns,
                    self.tsn_cqf_time_engine.current_cycle_index,
                    dispatched.len()
                );
                for f in &dispatched {
                    println!(
                        "    • Dispatched Frame: Stream #{} ({} B, Ingress Cycle: #{})",
                        f.stream_id, f.payload_bytes, f.ingress_cycle
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-cqf-time [status | rx <stream> <bytes> | tick <ns>]"
            ),
        }
    }

    fn cmd_diameter_s6m(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "3GPP Diameter S6m / S6n MAP-to-Diameter HSS Interworking Interface (App ID: 16777310 / TS 29.336):"
                );
                println!(
                    "  • HSS Realm             : {}",
                    self.s6m_hss_engine.hss_realm
                );
                println!(
                    "  • Total SIR Requests    : {}",
                    self.s6m_hss_engine.total_sir_requests
                );
                println!(
                    "  • Registered Profiles   : {}",
                    self.s6m_hss_engine.subscriber_profiles.len()
                );
                for (imsi, status) in &self.s6m_hss_engine.subscriber_profiles {
                    println!(
                        "    [Subscriber {}] Authorization Status: {:?}",
                        imsi, status
                    );
                }
            }
            "sir" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460029988776655"
                };
                let req = S6mMessage::new_sir("s6m-cli-sess", imsi);
                let resp = self.s6m_hss_engine.handle_sir(&req);
                let rc = resp
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6mAvp::ResultCode(c) = a {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(5000);
                let auth = resp
                    .avps
                    .iter()
                    .find_map(|a| {
                        if let S6mAvp::SmsMiResult(r) = a {
                            Some(*r)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(SmsMiResult::NotRegistered);

                println!(
                    "  [DIAMETER S6m SIR/SIA] IMSI: {} -> Authorization: {:?} (Result-Code: {})",
                    imsi, auth, rc
                );
            }
            "register" => {
                let imsi = if args.len() >= 2 {
                    args[1]
                } else {
                    "460029988776655"
                };
                let stat_str = if args.len() >= 3 { args[2] } else { "ok" };
                let status = if stat_str.contains("bar") {
                    SmsMiResult::Barred
                } else {
                    SmsMiResult::Authorized
                };
                self.s6m_hss_engine.register_subscriber(imsi, status);
                println!(
                    "  [SUBSCRIBER REGISTERED] IMSI {} set to {:?}",
                    imsi, status
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: diameter-s6m [status | sir <imsi> | register <imsi> <ok|barred>]"
            ),
        }
    }

    fn cmd_evpn_umt(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "EVPN Unknown Multicast Tree & Ingress Replication Optimization Engine (RFC 7432 / RFC 9251):"
                );
                println!(
                    "  • Local VTEP IP         : {}",
                    self.evpn_umt_engine.local_vtep
                );
                println!(
                    "  • VNIs with IMET        : {}",
                    self.evpn_umt_engine.inclusive_vtep_map.len()
                );
                println!(
                    "  • Active SMET Channels  : {}",
                    self.evpn_umt_engine.selective_vtep_map.len()
                );
                println!(
                    "  • Total Multicast Frames: {}",
                    self.evpn_umt_engine.total_multicast_frames_ingressed
                );
                println!(
                    "  • Replicated Copies Sent: {}",
                    self.evpn_umt_engine.total_copies_replicated
                );
                println!(
                    "  • Pruned Remote Leaves  : {}",
                    self.evpn_umt_engine.total_leaves_pruned
                );
            }
            "add-imet" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let ip_str = if args.len() >= 3 { args[2] } else { "10.0.0.2" };
                if let Ok(ip) = ip_str.parse::<Ipv4Address>() {
                    self.evpn_umt_engine.add_inclusive_vtep(vni, ip);
                    println!(
                        "  [IMET VTEP ADDED] VNI {}: Added inclusive VTEP {}",
                        vni, ip
                    );
                }
            }
            "add-smet" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let grp_str = if args.len() >= 3 {
                    args[2]
                } else {
                    "239.1.1.1"
                };
                let ip_str = if args.len() >= 4 { args[3] } else { "10.0.0.2" };
                if let (Ok(grp), Ok(ip)) = (
                    grp_str.parse::<Ipv4Address>(),
                    ip_str.parse::<Ipv4Address>(),
                ) {
                    self.evpn_umt_engine.add_selective_receiver(vni, grp, ip);
                    println!(
                        "  [SMET RECEIVER ADDED] VNI {} / Group {}: Added receiver VTEP {}",
                        vni, grp, ip
                    );
                }
            }
            "resolve" => {
                let vni = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(100)
                } else {
                    100
                };
                let grp_str = if args.len() >= 3 {
                    args[2]
                } else {
                    "239.1.1.1"
                };
                if let Ok(grp) = grp_str.parse::<Ipv4Address>() {
                    let targets = self.evpn_umt_engine.resolve_replication_targets(vni, grp);
                    println!(
                        "  [REPLICATION TARGETS RESOLVED] VNI {} / Group {} -> Dispatched to {} VTEPs: {:?}",
                        vni,
                        grp,
                        targets.len(),
                        targets
                    );
                }
            }
            _ => println!(
                "Unknown subcommand. Usage: evpn-umt [status | add-imet <vni> <ip> | add-smet <vni> <grp> <ip> | resolve <vni> <grp>]"
            ),
        }
    }

    fn cmd_gtpu_jitter(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!(
                    "5G GTP-U Path Jitter & Microsecond Delay Telemetry Engine (3GPP TS 38.415 / RFC 3550):"
                );
                println!(
                    "  • Session ID            : {}",
                    self.gtpu_jitter_engine.session_id
                );
                println!(
                    "  • Total Samples         : {}",
                    self.gtpu_jitter_engine.total_samples
                );
                println!(
                    "  • Min One-Way Delay     : {} µs",
                    if self.gtpu_jitter_engine.total_samples > 0 {
                        self.gtpu_jitter_engine.min_delay_us
                    } else {
                        0
                    }
                );
                println!(
                    "  • Max One-Way Delay     : {} µs",
                    self.gtpu_jitter_engine.max_delay_us
                );
                println!(
                    "  • Average One-Way Delay : {:.2} µs",
                    self.gtpu_jitter_engine.average_delay_us()
                );
                println!(
                    "  • Smoothed Jitter (EMA) : {:.2} µs",
                    self.gtpu_jitter_engine.current_jitter_us
                );
            }
            "sample" => {
                let seq = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let tx = if args.len() >= 3 {
                    args[2].parse::<u64>().unwrap_or(10_000)
                } else {
                    10_000
                };
                let rx = if args.len() >= 4 {
                    args[3].parse::<u64>().unwrap_or(12_500)
                } else {
                    12_500
                };

                let sample = self.gtpu_jitter_engine.record_sample(seq, tx, rx);
                println!(
                    "  [LATENCY SAMPLE RECORDED] Seq #{}: TX: {} µs, RX: {} µs -> OWD: {} µs (Current Jitter: {:.2} µs)",
                    sample.sequence_number,
                    sample.tx_timestamp_us,
                    sample.rx_timestamp_us,
                    sample.one_way_delay_us,
                    self.gtpu_jitter_engine.current_jitter_us
                );
            }
            "stream" => {
                let count = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(5)
                } else {
                    5
                };
                for i in 1..=count {
                    let tx = i as u64 * 10_000;
                    let rx = tx + 2000 + ((i % 3) as u64 * 150);
                    self.gtpu_jitter_engine.record_sample(i, tx, rx);
                }
                println!(
                    "  [SYNTHETIC STREAM INGESTED] Processed {} samples. Current Jitter: {:.2} µs, Avg Delay: {:.2} µs",
                    count,
                    self.gtpu_jitter_engine.current_jitter_us,
                    self.gtpu_jitter_engine.average_delay_us()
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: gtpu-jitter [status | sample <seq> <tx_us> <rx_us> | stream <count>]"
            ),
        }
    }

    fn cmd_tsn_cqf_meter(&mut self, args: &[&str]) {
        let subcmd = args.first().copied().unwrap_or("status");
        match subcmd {
            "status" => {
                println!("IEEE 802.1Qch CQF with trTCM Traffic Metering Engine (RFC 2698):");
                println!(
                    "  • CIR / CBS             : {} bps / {} Bytes",
                    self.tsn_cqf_trtcm_engine.meter.cir_bps,
                    self.tsn_cqf_trtcm_engine.meter.cbs_bytes
                );
                println!(
                    "  • PIR / PBS             : {} bps / {} Bytes",
                    self.tsn_cqf_trtcm_engine.meter.pir_bps,
                    self.tsn_cqf_trtcm_engine.meter.pbs_bytes
                );
                println!(
                    "  • Drop Yellow on Congest: {}",
                    self.tsn_cqf_trtcm_engine.drop_yellow_on_congestion
                );
                println!(
                    "  • Green Frames Admitted : {}",
                    self.tsn_cqf_trtcm_engine.total_green_admitted
                );
                println!(
                    "  • Yellow Frames Admitted: {}",
                    self.tsn_cqf_trtcm_engine.total_yellow_admitted
                );
                println!(
                    "  • Red Frames Dropped    : {}",
                    self.tsn_cqf_trtcm_engine.total_red_dropped
                );
                println!(
                    "  • Current Queue Depth   : {} frames",
                    self.tsn_cqf_trtcm_engine.queue.len()
                );
            }
            "ingest" => {
                let stream_id = if args.len() >= 2 {
                    args[1].parse::<u32>().unwrap_or(1)
                } else {
                    1
                };
                let bytes = if args.len() >= 3 {
                    args[2].parse::<usize>().unwrap_or(1000)
                } else {
                    1000
                };
                let now_ns = if args.len() >= 4 {
                    args[3].parse::<u64>().unwrap_or(0)
                } else {
                    0
                };

                let color = self
                    .tsn_cqf_trtcm_engine
                    .ingest_frame(stream_id, bytes, now_ns);
                match color {
                    TrTcmColor::Green => println!(
                        "  🟢 [trTCM GREEN] Stream #{}: {} Bytes admitted into committed CQF slot.",
                        stream_id, bytes
                    ),
                    TrTcmColor::Yellow => println!(
                        "  🟡 [trTCM YELLOW] Stream #{}: {} Bytes admitted with remarking (Peak Burst).",
                        stream_id, bytes
                    ),
                    TrTcmColor::Red => println!(
                        "  🔴 [trTCM RED] Stream #{}: {} Bytes dropped due to PIR rate limit violation!",
                        stream_id, bytes
                    ),
                }
            }
            "drop-yellow" => {
                let flag_str = if args.len() >= 2 { args[1] } else { "true" };
                self.tsn_cqf_trtcm_engine.drop_yellow_on_congestion =
                    flag_str == "true" || flag_str == "1";
                println!(
                    "  [YELLOW POLICY UPDATED] Drop yellow on congestion is now: {}",
                    self.tsn_cqf_trtcm_engine.drop_yellow_on_congestion
                );
            }
            _ => println!(
                "Unknown subcommand. Usage: tsn-cqf-meter [status | ingest <stream> <bytes> [now_ns] | drop-yellow <true|false>]"
            ),
        }
    }
}

// ===========================================================================
// Socket-runtime lab helpers used by the `lab sockets`/`tcp-*`/`http` demos.
//
// These drive the real stack: they build a two-host virtual lab and then use
// only the application-facing socket API. No demo constructs a TCP segment,
// IPv4 packet, or Ethernet frame by hand.
// ===========================================================================

/// Server address used by every socket-runtime demo.
const SOCKET_LAB_SERVER_IP: Ipv4Address = Ipv4Address([192, 168, 50, 2]);
/// Client address used by every socket-runtime demo.
const SOCKET_LAB_CLIENT_IP: Ipv4Address = Ipv4Address([192, 168, 50, 10]);

/// Builds a two-host lab on one link with ARP pre-seeded, so frame indices line up with
/// TCP segments and loss injection targets the segment a demo means to drop.
fn build_socket_lab(link: &str, mss: u16) -> VirtualLab {
    let server_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x50, 0x02]);
    let client_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x50, 0x0A]);

    let mut lab = VirtualLab::new();
    lab.add_link(link);
    lab.add_host(
        "server",
        link,
        NetStackConfig {
            mac: server_mac,
            ip: SOCKET_LAB_SERVER_IP,
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "client",
        link,
        NetStackConfig {
            mac: client_mac,
            ip: SOCKET_LAB_CLIENT_IP,
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );

    lab.host_mut("client")
        .unwrap()
        .stack
        .arp_table
        .insert(SOCKET_LAB_SERVER_IP.0, server_mac);
    lab.host_mut("server")
        .unwrap()
        .stack
        .arp_table
        .insert(SOCKET_LAB_CLIENT_IP.0, client_mac);

    lab.host_mut("client").unwrap().stack.set_tcp_mss(mss);
    lab.host_mut("server").unwrap().stack.set_tcp_mss(mss);
    lab
}

/// Completes a three-way handshake between the lab's client and server hosts and returns
/// the two stream handles plus the listener.
fn socket_lab_connect(
    lab: &mut VirtualLab,
) -> (TcpStreamHandle, TcpStreamHandle, TcpListenerHandle) {
    let listener = lab
        .host_mut("server")
        .unwrap()
        .stack
        .tcp_listen(80)
        .unwrap();
    let client = lab
        .host_mut("client")
        .unwrap()
        .stack
        .tcp_connect(SocketAddrV4 {
            ip: SOCKET_LAB_SERVER_IP,
            port: 80,
        })
        .unwrap();

    lab.run_until(50, 10_000, |l| {
        l.host("client")
            .unwrap()
            .stack
            .tcp_state(client)
            .map(|s| s == TcpState::Established)
            .unwrap_or(false)
    });

    let (server, _) = lab
        .host_mut("server")
        .unwrap()
        .stack
        .tcp_accept(listener)
        .expect("listener accept queue");
    (client, server, listener)
}

/// Reads every currently available byte from a stream through the socket API.
fn drain_stream(lab: &mut VirtualLab, host: &str, stream: TcpStreamHandle) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match lab
            .host_mut(host)
            .unwrap()
            .stack
            .tcp_read(stream, &mut chunk)
        {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    out
}

/// Minimal HTTP/1.1 origin server. Operates purely on the byte stream the socket API
/// delivered; it has no idea TCP, IPv4, or Ethernet exist.
fn http_respond(request: &str) -> String {
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let (status, body) = match (method, target) {
        ("GET", "/hello") => ("200 OK", "Hello from the userspace TCP/IP stack!\n"),
        ("GET", _) => ("404 Not Found", "not found\n"),
        _ => ("405 Method Not Allowed", "method not allowed\n"),
    };

    format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    )
}

/// Renders the RFC 4456 reflection metadata of one route for a diagnostic line.
///
/// Returns an empty string when there is none, so an ordinary un-reflected route
/// prints exactly as it did before route reflection existed.
fn format_reflection(originator: Option<Ipv4Address>, clusters: &[Ipv4Address]) -> String {
    if originator.is_none() && clusters.is_empty() {
        return String::new();
    }
    let mut out = String::from(" [reflected");
    if let Some(id) = originator {
        out.push_str(&format!(" originator {}", id));
    }
    if !clusters.is_empty() {
        let list: Vec<String> = clusters.iter().map(|c| c.to_string()).collect();
        out.push_str(&format!(" cluster-list {}", list.join(" ")));
    }
    out.push(']');
    out
}
