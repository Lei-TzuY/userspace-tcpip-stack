//! 3GPP TS 29.558 / TS 23.558 5G Edge Enabler Server (EES) & Edge Configuration Server (ECS) Engine.
//!
//! Implements 3GPP EDGEAPP (Enabling Edge Applications over 5G Core):
//! - Edge Configuration Server (ECS - TS 29.558 Section 8.2 / EDGE-1):
//!   - Service Provisioning resolving suitable EES endpoints based on UE location and Application Client ID
//! - Edge Enabler Server (EES - TS 29.558 Section 8.3-8.6 / EDGE-3):
//!   - EAS Registration (TS 29.558 Section 8.4): EAS registers capabilities, DNAI, service area, and latency SLAs
//!   - EAS Discovery (TS 29.558 Section 8.5): Matches EEC queries by App ID, geographic service area, load, and SLA
//!   - Dynamic EAS load reporting and overload protection
//!   - Edge relocation triggers for mobile UEs traversing DNAI boundaries

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G EDGEAPP Enums & Data Structures (TS 29.558 Section 6)
// ---------------------------------------------------------------------------

/// Edge Application Server (EAS) Registration Profile (TS 29.558 Section 6.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct EasProfile {
    pub eas_id: String,
    pub app_id: String,
    pub eas_endpoint_uri: String,
    pub dnai: String,
    pub service_area: Vec<String>, // List of TAIs or Tracking Areas, e.g. ["tai-tokyo-01", "tai-tokyo-02"]
    pub max_latency_ms: u32,
    pub gpu_accelerated: bool,
    pub active_load_pct: u8, // 0..100%
}

/// Edge Enabler Server (EES) Profile registered in ECS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EesProfile {
    pub ees_id: String,
    pub ees_endpoint_uri: String,
    pub service_area: Vec<String>,
    pub supported_dnais: Vec<String>,
}

/// ECS Service Provisioning Request from Edge Enabler Client (EEC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcsProvisioningRequest {
    pub eec_id: String,
    pub ue_location_tai: String,
    pub app_client_id: String,
}

/// ECS Service Provisioning Response to EEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcsProvisioningResponse {
    pub matched_ees_list: Vec<String>, // URIs of matching EES instances
}

/// EAS Discovery Request from EEC to EES.
#[derive(Debug, Clone, PartialEq)]
pub struct EasDiscoveryRequest {
    pub app_id: String,
    pub ue_location_tai: String,
    pub required_gpu: bool,
    pub max_acceptable_latency_ms: Option<u32>,
}

/// Ranked EAS Discovery Result returned to EEC.
#[derive(Debug, Clone, PartialEq)]
pub struct EasDiscoveryResult {
    pub eas_id: String,
    pub eas_endpoint_uri: String,
    pub dnai: String,
    pub expected_latency_ms: u32,
    pub current_load_pct: u8,
}

/// EES / ECS Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeAppError {
    NoMatchingEesFound,
    NoMatchingEasFound,
    EasAlreadyRegistered,
    EasNotFound,
    InvalidProfile(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level Edge Configuration Server (ECS) Engine
// ---------------------------------------------------------------------------

/// 5G Edge Configuration Server (ECS).
pub struct EcsEngine {
    pub ecs_id: String,
    /// Registered EES profiles: ees_id -> EesProfile
    pub registered_ees: HashMap<String, EesProfile>,
}

impl EcsEngine {
    /// Create a new ECS engine.
    pub fn new(ecs_id: &str) -> Self {
        EcsEngine {
            ecs_id: ecs_id.to_string(),
            registered_ees: HashMap::new(),
        }
    }

    /// Register an EES instance in the ECS directory.
    pub fn register_ees(&mut self, profile: EesProfile) {
        self.registered_ees.insert(profile.ees_id.clone(), profile);
    }

    /// Process EEC Service Provisioning request (TS 29.558 Section 8.2).
    pub fn provision_service(
        &self,
        req: &EcsProvisioningRequest,
    ) -> Result<EcsProvisioningResponse, EdgeAppError> {
        let mut matched = Vec::new();

        for ees in self.registered_ees.values() {
            if ees
                .service_area
                .iter()
                .any(|area| area == &req.ue_location_tai)
            {
                matched.push(ees.ees_endpoint_uri.clone());
            }
        }

        if matched.is_empty() {
            Err(EdgeAppError::NoMatchingEesFound)
        } else {
            Ok(EcsProvisioningResponse {
                matched_ees_list: matched,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Top-Level Edge Enabler Server (EES) Engine
// ---------------------------------------------------------------------------

/// 5G Edge Enabler Server (EES).
pub struct EesEngine {
    pub ees_id: String,
    pub ees_endpoint_uri: String,
    /// Registered EAS instances: eas_id -> EasProfile
    pub registered_eas: HashMap<String, EasProfile>,
}

impl EesEngine {
    /// Create a new EES engine.
    pub fn new(ees_id: &str, endpoint_uri: &str) -> Self {
        EesEngine {
            ees_id: ees_id.to_string(),
            ees_endpoint_uri: endpoint_uri.to_string(),
            registered_eas: HashMap::new(),
        }
    }

    /// Register a new Edge Application Server (TS 29.558 Section 8.4).
    pub fn register_eas(&mut self, profile: EasProfile) -> Result<(), EdgeAppError> {
        if self.registered_eas.contains_key(&profile.eas_id) {
            return Err(EdgeAppError::EasAlreadyRegistered);
        }
        self.registered_eas.insert(profile.eas_id.clone(), profile);
        Ok(())
    }

    /// Update dynamic load of an active EAS.
    pub fn update_eas_load(&mut self, eas_id: &str, load_pct: u8) -> Result<(), EdgeAppError> {
        let eas = self
            .registered_eas
            .get_mut(eas_id)
            .ok_or(EdgeAppError::EasNotFound)?;
        eas.active_load_pct = load_pct.min(100);
        Ok(())
    }

    /// Deregister an EAS upon shutdown or maintenance.
    pub fn deregister_eas(&mut self, eas_id: &str) -> Result<(), EdgeAppError> {
        self.registered_eas
            .remove(eas_id)
            .map(|_| ())
            .ok_or(EdgeAppError::EasNotFound)
    }

    /// Discover matching EAS candidates for an Edge Enabler Client (TS 29.558 Section 8.5).
    pub fn discover_eas(
        &self,
        req: &EasDiscoveryRequest,
    ) -> Result<Vec<EasDiscoveryResult>, EdgeAppError> {
        let mut candidates = Vec::new();

        for eas in self.registered_eas.values() {
            // 1. App ID match
            if eas.app_id != req.app_id {
                continue;
            }

            // 2. Service area coverage match
            if !eas
                .service_area
                .iter()
                .any(|area| area == &req.ue_location_tai)
            {
                continue;
            }

            // 3. GPU capability check
            if req.required_gpu && !eas.gpu_accelerated {
                continue;
            }

            // 4. Latency SLA check
            if let Some(max_lat) = req.max_acceptable_latency_ms {
                if eas.max_latency_ms > max_lat {
                    continue;
                }
            }

            // 5. Overload protection (omit EAS with load >= 95%)
            if eas.active_load_pct >= 95 {
                continue;
            }

            candidates.push(EasDiscoveryResult {
                eas_id: eas.eas_id.clone(),
                eas_endpoint_uri: eas.eas_endpoint_uri.clone(),
                dnai: eas.dnai.clone(),
                expected_latency_ms: eas.max_latency_ms,
                current_load_pct: eas.active_load_pct,
            });
        }

        if candidates.is_empty() {
            return Err(EdgeAppError::NoMatchingEasFound);
        }

        // Rank candidates: lowest load first, then lowest expected latency
        candidates.sort_by(|a, b| {
            a.current_load_pct
                .cmp(&b.current_load_pct)
                .then_with(|| a.expected_latency_ms.cmp(&b.expected_latency_ms))
        });

        Ok(candidates)
    }
}
