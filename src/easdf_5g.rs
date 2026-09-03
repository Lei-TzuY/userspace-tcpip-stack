//! 3GPP TS 29.544 / TS 23.548 5G Edge Application Server Discovery Function (EASDF) Engine.
//!
//! Implements 5G Multi-access Edge Computing (MEC) Edge Application Server discovery:
//! - Neasdf_DNSContext Service (TS 29.544 Section 5.2):
//!   - SMF creates, updates, and deletes per-PDU-session DNS contexts
//!   - DNS Handling Rules (`DnsRule`) with FQDN wildcard matching and precedence ordering
//!   - Event reporting to SMF upon edge DNS queries (triggering UPF UL CL / Branching Point insertion)
//!   - EDNS Client Subnet (ECS - RFC 7871) injection for localized Geo-DNS edge resolution
//!   - Local DNS (LDNS) routing steering based on target Data Network Access Identifier (DNAI)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;

// ---------------------------------------------------------------------------
// 5G EASDF Enums & Data Structures (TS 29.544 Section 6)
// ---------------------------------------------------------------------------

/// Action to apply when a DNS query matches a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Forward query to default upstream DNS resolver.
    ForwardDefault,
    /// Forward query to specific Local DNS (LDNS) associated with a local DNAI.
    ForwardToLdns,
    /// Notify SMF of query and forward to LDNS (prompts SMF to activate UPF UL CL).
    ReportAndForward,
    /// Inject EDNS0 Client Subnet (ECS) and forward to target LDNS.
    InjectEcsAndForward,
}

/// DNS Handling Rule configured by SMF (TS 29.544 Section 6.1.6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRule {
    pub rule_id: u32,
    pub precedence: u32,            // Lower value = higher priority
    pub fqdn_patterns: Vec<String>, // e.g. ["*.edge.gamestream.com", "mec-app.io"]
    pub action: DnsAction,
    pub target_ldns_ip: Option<Ipv4Address>,
    pub target_dnai: Option<String>,
    pub ecs_client_subnet: Option<(Ipv4Address, u8)>, // (Subnet, Prefix Len)
}

/// Per-PDU session DNS Context (TS 29.544 Section 6.1.6.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsContext {
    pub context_id: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub ue_ipv4: Ipv4Address,
    pub dnn: String,
    pub dns_rules: Vec<DnsRule>,
}

/// Notification sent to SMF when an edge DNS query is intercepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryEventReport {
    pub context_id: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub matched_rule_id: u32,
    pub queried_fqdn: String,
    pub target_dnai: Option<String>,
    pub timestamp_epoch_s: u64,
}

/// DNS Resolution Result returned to UE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolutionResult {
    pub fqdn: String,
    pub resolved_ip: Ipv4Address,
    pub matched_rule_id: Option<u32>,
    pub ecs_injected: bool,
    pub forwarded_ldns: Option<Ipv4Address>,
}

/// EASDF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EasdfError {
    ContextNotFound,
    RuleNotFound,
    InvalidDnsRule(&'static str),
    FqdnResolutionFailed(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level EASDF Engine
// ---------------------------------------------------------------------------

/// 5G Edge Application Server Discovery Function (EASDF) Engine.
pub struct EasdfEngine {
    pub easdf_id: String,
    pub default_dns_server: Ipv4Address,
    pub next_context_id: u64,
    /// Active contexts: context_id -> DnsContext
    pub contexts: HashMap<String, DnsContext>,
    /// Index: ue_ipv4 -> context_id
    pub ue_ip_to_context: HashMap<Ipv4Address, String>,
    /// Simulated Upstream / Local DNS Records: (LDNS IP, FQDN) -> Resolved IP
    pub dns_records: HashMap<(Ipv4Address, String), Ipv4Address>,
    /// Event log / dispatch queue for SMF notifications
    pub smf_notification_queue: Vec<DnsQueryEventReport>,
}

impl EasdfEngine {
    /// Create a new EASDF engine.
    pub fn new(easdf_id: &str, default_dns_server: Ipv4Address) -> Self {
        EasdfEngine {
            easdf_id: easdf_id.to_string(),
            default_dns_server,
            next_context_id: 1,
            contexts: HashMap::new(),
            ue_ip_to_context: HashMap::new(),
            dns_records: HashMap::new(),
            smf_notification_queue: Vec::new(),
        }
    }

    /// Add a simulated DNS record into an LDNS server.
    pub fn add_dns_record(&mut self, ldns_ip: Ipv4Address, fqdn: &str, ip: Ipv4Address) {
        self.dns_records.insert((ldns_ip, fqdn.to_lowercase()), ip);
    }

    // -----------------------------------------------------------------------
    // Neasdf_DNSContext Service Operations (TS 29.544 Section 5.2)
    // -----------------------------------------------------------------------

    /// Create a new DNS Context for a PDU session.
    pub fn create_dns_context(
        &mut self,
        supi: &str,
        pdu_session_id: u8,
        ue_ipv4: Ipv4Address,
        dnn: &str,
        mut rules: Vec<DnsRule>,
    ) -> String {
        let ctx_id = format!("easdf-ctx-{}", self.next_context_id);
        self.next_context_id += 1;

        // Sort rules by precedence (ascending: lowest precedence value first)
        rules.sort_by_key(|r| r.precedence);

        let ctx = DnsContext {
            context_id: ctx_id.clone(),
            supi: supi.to_string(),
            pdu_session_id,
            ue_ipv4,
            dnn: dnn.to_string(),
            dns_rules: rules,
        };

        self.ue_ip_to_context.insert(ue_ipv4, ctx_id.clone());
        self.contexts.insert(ctx_id.clone(), ctx);

        ctx_id
    }

    /// Update an existing DNS Context (e.g. upon UE mobility to a new DNAI).
    pub fn update_dns_context_rules(
        &mut self,
        context_id: &str,
        mut new_rules: Vec<DnsRule>,
    ) -> Result<(), EasdfError> {
        let ctx = self
            .contexts
            .get_mut(context_id)
            .ok_or(EasdfError::ContextNotFound)?;
        new_rules.sort_by_key(|r| r.precedence);
        ctx.dns_rules = new_rules;
        Ok(())
    }

    /// Delete a DNS Context upon PDU session termination.
    pub fn delete_dns_context(&mut self, context_id: &str) -> Result<(), EasdfError> {
        let ctx = self
            .contexts
            .remove(context_id)
            .ok_or(EasdfError::ContextNotFound)?;
        self.ue_ip_to_context.remove(&ctx.ue_ipv4);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // DNS Message Interception & Edge Routing Pipeline
    // -----------------------------------------------------------------------

    /// Process a DNS query issued by a UE.
    pub fn process_dns_query(
        &mut self,
        ue_ipv4: Ipv4Address,
        queried_fqdn: &str,
        timestamp_s: u64,
    ) -> Result<DnsResolutionResult, EasdfError> {
        let ctx_id = self
            .ue_ip_to_context
            .get(&ue_ipv4)
            .ok_or(EasdfError::ContextNotFound)?
            .clone();

        let ctx = self
            .contexts
            .get(&ctx_id)
            .ok_or(EasdfError::ContextNotFound)?;
        let normalized_fqdn = queried_fqdn.to_lowercase();

        // 1. Evaluate rules in order of precedence
        let matched_rule = ctx
            .dns_rules
            .iter()
            .find(|rule| {
                rule.fqdn_patterns
                    .iter()
                    .any(|pattern| match_fqdn_pattern(pattern, &normalized_fqdn))
            })
            .cloned();

        let (target_ldns, matched_id, ecs_injected) = if let Some(rule) = matched_rule {
            match rule.action {
                DnsAction::ForwardDefault => (self.default_dns_server, Some(rule.rule_id), false),
                DnsAction::ForwardToLdns => {
                    let ldns = rule.target_ldns_ip.unwrap_or(self.default_dns_server);
                    (ldns, Some(rule.rule_id), false)
                }
                DnsAction::ReportAndForward => {
                    // Queue notification to SMF for UPF UL CL activation
                    self.smf_notification_queue.push(DnsQueryEventReport {
                        context_id: ctx.context_id.clone(),
                        supi: ctx.supi.clone(),
                        pdu_session_id: ctx.pdu_session_id,
                        matched_rule_id: rule.rule_id,
                        queried_fqdn: normalized_fqdn.clone(),
                        target_dnai: rule.target_dnai.clone(),
                        timestamp_epoch_s: timestamp_s,
                    });
                    let ldns = rule.target_ldns_ip.unwrap_or(self.default_dns_server);
                    (ldns, Some(rule.rule_id), false)
                }
                DnsAction::InjectEcsAndForward => {
                    let ldns = rule.target_ldns_ip.unwrap_or(self.default_dns_server);
                    (ldns, Some(rule.rule_id), true)
                }
            }
        } else {
            // No rule matched: fallback to default DNS
            (self.default_dns_server, None, false)
        };

        // 2. Resolve IP from target LDNS records (or default)
        let resolved_ip = self
            .dns_records
            .get(&(target_ldns, normalized_fqdn.clone()))
            .or_else(|| {
                self.dns_records
                    .get(&(self.default_dns_server, normalized_fqdn.clone()))
            })
            .copied()
            .ok_or(EasdfError::FqdnResolutionFailed(
                "Domain not found in target LDNS",
            ))?;

        Ok(DnsResolutionResult {
            fqdn: normalized_fqdn,
            resolved_ip,
            matched_rule_id: matched_id,
            ecs_injected,
            forwarded_ldns: Some(target_ldns),
        })
    }
}

// ---------------------------------------------------------------------------
// Wildcard FQDN Matcher (e.g. "*.edge.cloud.io" matches "game.edge.cloud.io")
// ---------------------------------------------------------------------------

fn match_fqdn_pattern(pattern: &str, fqdn: &str) -> bool {
    let p = pattern.to_lowercase();
    let f = fqdn.to_lowercase();

    if p == f {
        return true;
    }

    if p.starts_with("*.") {
        let suffix = &p[1..]; // includes leading dot ".edge.cloud.io"
        f.ends_with(suffix) && f.len() > suffix.len()
    } else {
        false
    }
}
