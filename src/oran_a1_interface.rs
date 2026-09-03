//! O-RAN Alliance WG2 A1 Interface Engine (A1-P & A1-EI Services).
//!
//! Implements RESTful A1-P Policy Management and A1-EI Enrichment Information
//! services connecting the Non-Real-Time RAN Intelligent Controller (Non-RT RIC / SMO)
//! and the Near-Real-Time RAN Intelligent Controller (Near-RT RIC).
//!
//! Facilitates declarative policy configuration and translates A1 intent into
//! imperative O-RAN WG3 E2AP closed-loop control directives.

use std::collections::HashMap;

use crate::e2ap_oran::{RAN_FUNCTION_ID_RC, RicControlRequest, RicRequestId};

/// HTTP Methods used in A1 REST interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A1HttpMethod {
    Get,
    Put,
    Post,
    Delete,
}

/// A1 REST Response Status Codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A1StatusCode {
    Ok200 = 200,
    Created201 = 201,
    NoContent204 = 204,
    BadRequest400 = 400,
    NotFound404 = 404,
    Conflict409 = 409,
    InternalServerError500 = 500,
}

/// A1 Policy Enforcement State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A1EnforcementState {
    Enforcing,
    NotEnforced,
    EnforceFailed,
}

/// A1 Policy Type definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1PolicyType {
    pub policy_type_id: u32,
    pub name: String,
    pub description: String,
    pub schema_version: String,
}

/// Declarative Slice SLA Policy Payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceSlaPolicyPayload {
    pub target_slice_sst: u8,
    pub target_slice_sd: Option<[u8; 3]>,
    pub guaranteed_prb_quota_ppm: u32, // PRB quota in ppm (0..1_000_000)
    pub max_latency_ms: u32,
}

/// A1 Policy Instance created under a Policy Type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1PolicyInstance {
    pub policy_type_id: u32,
    pub policy_instance_id: String,
    pub payload: SliceSlaPolicyPayload,
}

/// Status of an A1 Policy Instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1PolicyStatus {
    pub enforcement_state: A1EnforcementState,
    pub enforcement_reason: Option<String>,
}

/// A1 Enrichment Information (A1-EI) Type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1EiType {
    pub ei_type_id: String,
    pub description: String,
}

/// A1 Enrichment Information Job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1EiJob {
    pub ei_job_id: String,
    pub ei_type_id: String,
    pub target_xapp: String,
    pub job_data: String,
}

/// Simulated A1 REST Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1RestRequest {
    pub method: A1HttpMethod,
    pub path: String,
    pub body: Option<String>,
}

/// Simulated A1 REST Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1RestResponse {
    pub status_code: A1StatusCode,
    pub body: Option<String>,
}

/// Role in the A1 interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A1Role {
    NonRtRic,
    NearRtRic,
}

/// O-RAN WG2 A1 Interface Engine.
#[derive(Debug, Clone)]
pub struct A1InterfaceEngine {
    pub role: A1Role,
    pub policy_types: HashMap<u32, A1PolicyType>,
    pub policy_instances: HashMap<(u32, String), (A1PolicyInstance, A1PolicyStatus)>,
    pub ei_types: HashMap<String, A1EiType>,
    pub ei_jobs: HashMap<String, A1EiJob>,
}

impl A1InterfaceEngine {
    pub fn new(role: A1Role) -> Self {
        Self {
            role,
            policy_types: HashMap::new(),
            policy_instances: HashMap::new(),
            ei_types: HashMap::new(),
            ei_jobs: HashMap::new(),
        }
    }

    /// Registers a Policy Type schema.
    pub fn register_policy_type(&mut self, policy_type: A1PolicyType) {
        self.policy_types
            .insert(policy_type.policy_type_id, policy_type);
    }

    /// Creates or updates a Policy Instance (PUT /a1-p/policytypes/{type_id}/policies/{instance_id}).
    pub fn put_policy(&mut self, instance: A1PolicyInstance) -> A1RestResponse {
        if !self.policy_types.contains_key(&instance.policy_type_id) {
            return A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("Policy type does not exist".to_string()),
            };
        }

        // Validate PRB quota range
        if instance.payload.guaranteed_prb_quota_ppm > 1_000_000 {
            return A1RestResponse {
                status_code: A1StatusCode::BadRequest400,
                body: Some("PRB quota exceeds 1,000,000 ppm".to_string()),
            };
        }

        let key = (instance.policy_type_id, instance.policy_instance_id.clone());
        let is_update = self.policy_instances.contains_key(&key);

        let status = A1PolicyStatus {
            enforcement_state: A1EnforcementState::Enforcing,
            enforcement_reason: None,
        };

        self.policy_instances.insert(key, (instance, status));

        if is_update {
            A1RestResponse {
                status_code: A1StatusCode::Ok200,
                body: Some("Policy updated successfully".to_string()),
            }
        } else {
            A1RestResponse {
                status_code: A1StatusCode::Created201,
                body: Some("Policy created successfully".to_string()),
            }
        }
    }

    /// Fetches a Policy Instance (GET /a1-p/policytypes/{type_id}/policies/{instance_id}).
    pub fn get_policy(&self, type_id: u32, instance_id: &str) -> A1RestResponse {
        let key = (type_id, instance_id.to_string());
        if let Some((instance, _)) = self.policy_instances.get(&key) {
            A1RestResponse {
                status_code: A1StatusCode::Ok200,
                body: Some(format!(
                    "PolicyInstance(id={}, type={}, sst={}, prb_ppm={})",
                    instance.policy_instance_id,
                    instance.policy_type_id,
                    instance.payload.target_slice_sst,
                    instance.payload.guaranteed_prb_quota_ppm
                )),
            }
        } else {
            A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("Policy instance not found".to_string()),
            }
        }
    }

    /// Fetches enforcement status (GET /a1-p/policytypes/{type_id}/policies/{instance_id}/status).
    pub fn get_policy_status(&self, type_id: u32, instance_id: &str) -> A1RestResponse {
        let key = (type_id, instance_id.to_string());
        if let Some((_, status)) = self.policy_instances.get(&key) {
            A1RestResponse {
                status_code: A1StatusCode::Ok200,
                body: Some(format!("{:?}", status.enforcement_state)),
            }
        } else {
            A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("Policy instance not found".to_string()),
            }
        }
    }

    /// Deletes a Policy Instance (DELETE /a1-p/policytypes/{type_id}/policies/{instance_id}).
    pub fn delete_policy(&mut self, type_id: u32, instance_id: &str) -> A1RestResponse {
        let key = (type_id, instance_id.to_string());
        if self.policy_instances.remove(&key).is_some() {
            A1RestResponse {
                status_code: A1StatusCode::NoContent204,
                body: None,
            }
        } else {
            A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("Policy instance not found".to_string()),
            }
        }
    }

    /// Translates declarative A1 policy intent into imperative E2AP RicControlRequest.
    pub fn translate_to_e2_control(
        &self,
        type_id: u32,
        instance_id: &str,
        ric_req_id: RicRequestId,
    ) -> Option<RicControlRequest> {
        let key = (type_id, instance_id.to_string());
        let (instance, _) = self.policy_instances.get(&key)?;

        Some(RicControlRequest {
            ric_request_id: ric_req_id,
            ran_function_id: RAN_FUNCTION_ID_RC,
            target_slice_sst: instance.payload.target_slice_sst,
            target_slice_sd: instance.payload.target_slice_sd,
            allocated_prb_quota_ppm: instance.payload.guaranteed_prb_quota_ppm,
            ack_request: true,
        })
    }

    /// Creates an A1 Enrichment Information Job (A1-EI).
    pub fn create_ei_job(&mut self, job: A1EiJob) -> A1RestResponse {
        if !self.ei_types.contains_key(&job.ei_type_id) {
            return A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("EI Type not found".to_string()),
            };
        }

        self.ei_jobs.insert(job.ei_job_id.clone(), job);
        A1RestResponse {
            status_code: A1StatusCode::Created201,
            body: Some("EI Job created successfully".to_string()),
        }
    }

    /// Deletes an A1 Enrichment Information Job.
    pub fn delete_ei_job(&mut self, job_id: &str) -> A1RestResponse {
        if self.ei_jobs.remove(job_id).is_some() {
            A1RestResponse {
                status_code: A1StatusCode::NoContent204,
                body: None,
            }
        } else {
            A1RestResponse {
                status_code: A1StatusCode::NotFound404,
                body: Some("EI Job not found".to_string()),
            }
        }
    }
}
