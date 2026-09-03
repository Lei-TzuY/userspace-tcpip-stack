//! 3GPP Diameter SLg Interface & Location Services (3GPP TS 29.172 / TS 23.271).
//!
//! Implements the Diameter-based SLg reference point between the Gateway Mobile Location Centre
//! (GMLC) and the MME/SGSN for Evolved Packet System (EPS) Location Services (LCS).
//! Application ID 16777255 (3GPP SLg).
//!
//! Supports:
//! - Provide-Location-Request / Answer (PLR / PLA - Command Code 8388620)
//! - Location-Report-Request / Answer (LRR / LRA - Command Code 8388621)
//! - LCS-EPS-Client-Name, Deferred-Location-Type, Positioning Method AVPs
//! - GMLC Location Session Engine with location result tracking and periodic scheduling

use crate::diameter::{DIAMETER_SUCCESS, DiameterAvp, DiameterHeader, DiameterMessage};
use std::collections::HashMap;

/// Diameter SLg Application ID (3GPP TS 29.172 Section 6.2).
pub const DIAMETER_APPLICATION_SLG: u32 = 16777255;

/// Command Codes for Diameter SLg.
pub const DIAMETER_CMD_PROVIDE_LOCATION: u32 = 8388620; // PLR / PLA
pub const DIAMETER_CMD_LOCATION_REPORT: u32 = 8388621; // LRR / LRA

/// Diameter SLg AVP Codes (3GPP TS 29.172 Section 7).
pub const AVP_SLG_LOCATION_TYPE: u32 = 2500;
pub const AVP_LCS_EPS_CLIENT_NAME: u32 = 2501;
pub const AVP_LCS_REQUESTOR_NAME: u32 = 2502;
pub const AVP_LCS_PRIORITY: u32 = 2503;
pub const AVP_LCS_QOS: u32 = 2504;
pub const AVP_HORIZONTAL_ACCURACY: u32 = 2505;
pub const AVP_VERTICAL_ACCURACY: u32 = 2506;
pub const AVP_VELOCITY_REQUESTED: u32 = 2508;
pub const AVP_LCS_REFERENCE_NUMBER: u32 = 2580;
pub const AVP_DEFERRED_LOCATION_TYPE: u32 = 2532;
pub const AVP_GERANPOSITIONING_DATA: u32 = 2510;
pub const AVP_UTRANPOSITIONING_DATA: u32 = 2511;
pub const AVP_LOCATION_ESTIMATE: u32 = 2516;
pub const AVP_ACCURACY_FULFILMENT_INDICATOR: u32 = 2513;
pub const AVP_AGE_OF_LOCATION_ESTIMATE: u32 = 2514;
pub const AVP_VELOCITY_ESTIMATE: u32 = 2515;
pub const AVP_EUTRAN_POSITIONING_DATA: u32 = 2517;
pub const AVP_ECGI: u32 = 2518;
pub const AVP_LOCATION_EVENT: u32 = 2519;
pub const AVP_PSEUDONYM_INDICATOR: u32 = 2520;
pub const AVP_LCS_SERVICE_TYPE_ID: u32 = 2521;
pub const AVP_LCS_PRIVACY_CHECK_SESSION: u32 = 2522;
pub const AVP_LCS_PRIVACY_CHECK_NON_SESSION: u32 = 2523;
pub const AVP_IMEI: u32 = 2524;
pub const AVP_PERIODIC_LDR_INFORMATION: u32 = 2540;
pub const AVP_REPORTING_AMOUNT: u32 = 2541;
pub const AVP_REPORTING_INTERVAL: u32 = 2542;

// Common Diameter AVPs
pub const AVP_SESSION_ID: u32 = 263;
pub const AVP_ORIGIN_HOST: u32 = 264;
pub const AVP_ORIGIN_REALM: u32 = 296;
pub const AVP_DESTINATION_REALM: u32 = 283;
pub const AVP_DESTINATION_HOST: u32 = 293;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_AUTH_SESSION_STATE: u32 = 277;
pub const AVP_USER_NAME: u32 = 1;

/// SLg Location Type enumeration (AVP 2500).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlgLocationType {
    CurrentLocation = 0,
    CurrentOrLastKnownLocation = 1,
    InitialLocation = 2,
    ActivateDeferredLocation = 3,
    CancelDeferredLocation = 4,
    NotificationVerificationOnly = 5,
}

impl SlgLocationType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => SlgLocationType::CurrentLocation,
            1 => SlgLocationType::CurrentOrLastKnownLocation,
            2 => SlgLocationType::InitialLocation,
            3 => SlgLocationType::ActivateDeferredLocation,
            4 => SlgLocationType::CancelDeferredLocation,
            _ => SlgLocationType::NotificationVerificationOnly,
        }
    }
}

/// Deferred Location Type flags (bitmask, AVP 2532).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeferredLocationType(pub u32);

impl DeferredLocationType {
    pub const UE_AVAILABLE: Self = DeferredLocationType(0x01);
    pub const ENTERING_INTO_AREA: Self = DeferredLocationType(0x02);
    pub const LEAVING_FROM_AREA: Self = DeferredLocationType(0x04);
    pub const BEING_INSIDE_AREA: Self = DeferredLocationType(0x08);
    pub const PERIODIC_LDR: Self = DeferredLocationType(0x10);
    pub const MOTION_EVENT: Self = DeferredLocationType(0x20);

    pub fn has_flag(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// LCS Priority (AVP 2503).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcsPriority {
    HighestPriority = 0,
    NormalPriority = 1,
}

impl LcsPriority {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => LcsPriority::HighestPriority,
            _ => LcsPriority::NormalPriority,
        }
    }
}

/// Accuracy Fulfilment Indicator (AVP 2513).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccuracyFulfilmentIndicator {
    RequestedAccuracyFulfilled = 0,
    RequestedAccuracyNotFulfilled = 1,
}

impl AccuracyFulfilmentIndicator {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => AccuracyFulfilmentIndicator::RequestedAccuracyFulfilled,
            _ => AccuracyFulfilmentIndicator::RequestedAccuracyNotFulfilled,
        }
    }
}

/// Location Event (AVP 2519, used in LRR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationEvent {
    EmergencyCallOrigination = 0,
    EmergencyCallRelease = 1,
    MoLr = 2,
    EmergencyCallHandover = 3,
    DeferredMtLrResponse = 4,
    DeferredMoLrTttpInitiation = 5,
    DelayedLocationReporting = 6,
}

impl LocationEvent {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => LocationEvent::EmergencyCallOrigination,
            1 => LocationEvent::EmergencyCallRelease,
            2 => LocationEvent::MoLr,
            3 => LocationEvent::EmergencyCallHandover,
            4 => LocationEvent::DeferredMtLrResponse,
            5 => LocationEvent::DeferredMoLrTttpInitiation,
            _ => LocationEvent::DelayedLocationReporting,
        }
    }
}

/// LCS Quality of Service parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcsQos {
    pub horizontal_accuracy: Option<u32>,
    pub vertical_accuracy: Option<u32>,
    pub velocity_requested: bool,
    pub response_time_category: LcsResponseTime,
}

/// LCS Response Time Category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcsResponseTime {
    LowDelay = 0,
    DelayTolerant = 1,
}

impl LcsResponseTime {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => LcsResponseTime::LowDelay,
            _ => LcsResponseTime::DelayTolerant,
        }
    }
}

impl Default for LcsQos {
    fn default() -> Self {
        LcsQos {
            horizontal_accuracy: Some(50),
            vertical_accuracy: None,
            velocity_requested: false,
            response_time_category: LcsResponseTime::LowDelay,
        }
    }
}

/// Location Estimate: a Universal Geographical Area Description (GAD) shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationEstimate {
    /// Ellipsoid Point (latitude, longitude in units of 1/2^23 degrees).
    EllipsoidPoint { latitude: i32, longitude: i32 },
    /// Ellipsoid Point with Uncertainty Circle.
    EllipsoidPointUncertaintyCircle {
        latitude: i32,
        longitude: i32,
        uncertainty_radius_m: u32,
    },
    /// Ellipsoid Point with Altitude and Uncertainty Ellipsoid.
    EllipsoidPointAltitudeUncertainty {
        latitude: i32,
        longitude: i32,
        altitude_m: i16,
        uncertainty_semi_major_m: u32,
        uncertainty_semi_minor_m: u32,
        orientation_major_axis_deg: u16,
        uncertainty_altitude_m: u32,
        confidence_pct: u8,
    },
    /// Raw GAD bytes for shapes we don't explicitly decode.
    Raw(Vec<u8>),
}

/// Periodic LDR (Location Deferred Request) Information (AVP 2540).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodicLdrInformation {
    pub reporting_amount: u32,
    pub reporting_interval_sec: u32,
}

// ---------------------------------------------------------------------------
// Message Structures
// ---------------------------------------------------------------------------

/// Provide-Location-Request (PLR) message — GMLC → MME/SGSN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvideLocationRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub destination_realm: String,
    pub destination_host: Option<String>,
    pub imsi: String,
    pub msisdn: Option<String>,
    pub imei: Option<String>,
    pub location_type: SlgLocationType,
    pub lcs_eps_client_name: Option<String>,
    pub lcs_requestor_name: Option<String>,
    pub lcs_priority: LcsPriority,
    pub lcs_qos: LcsQos,
    pub deferred_location_type: Option<DeferredLocationType>,
    pub lcs_reference_number: Option<u32>,
    pub periodic_ldr: Option<PeriodicLdrInformation>,
    pub lcs_service_type_id: Option<u32>,
}

impl ProvideLocationRequest {
    pub fn new(
        session_id: &str,
        imsi: &str,
        location_type: SlgLocationType,
        origin_host: &str,
        origin_realm: &str,
        destination_realm: &str,
    ) -> Self {
        ProvideLocationRequest {
            session_id: session_id.to_string(),
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
            destination_realm: destination_realm.to_string(),
            destination_host: None,
            imsi: imsi.to_string(),
            msisdn: None,
            imei: None,
            location_type,
            lcs_eps_client_name: None,
            lcs_requestor_name: None,
            lcs_priority: LcsPriority::NormalPriority,
            lcs_qos: LcsQos::default(),
            deferred_location_type: None,
            lcs_reference_number: None,
            periodic_ldr: None,
            lcs_service_type_id: None,
        }
    }

    /// Encodes the PLR into a generic Diameter message.
    pub fn to_diameter_message(&self) -> DiameterMessage {
        let header = DiameterHeader {
            version: 1,
            length: 0,   // Computed upon serialization
            flags: 0xC0, // R-bit + P-bit set (Request)
            command_code: DIAMETER_CMD_PROVIDE_LOCATION,
            application_id: DIAMETER_APPLICATION_SLG,
            hop_by_hop_id: 0,
            end_to_end_id: 0,
        };

        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_HOST, &self.origin_host));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_REALM, &self.origin_realm));
        avps.push(DiameterAvp::new_utf8(
            AVP_DESTINATION_REALM,
            &self.destination_realm,
        ));
        avps.push(DiameterAvp::new_u32(AVP_AUTH_SESSION_STATE, 1)); // NO_STATE_MAINTAINED
        avps.push(DiameterAvp::new_utf8(AVP_USER_NAME, &self.imsi));
        avps.push(DiameterAvp::new_u32(
            AVP_SLG_LOCATION_TYPE,
            self.location_type as u32,
        ));
        avps.push(DiameterAvp::new_u32(
            AVP_LCS_PRIORITY,
            self.lcs_priority as u32,
        ));

        if let Some(ref client_name) = self.lcs_eps_client_name {
            avps.push(DiameterAvp::new_utf8(AVP_LCS_EPS_CLIENT_NAME, client_name));
        }
        if let Some(ref requestor) = self.lcs_requestor_name {
            avps.push(DiameterAvp::new_utf8(AVP_LCS_REQUESTOR_NAME, requestor));
        }
        if let Some(ref dest_host) = self.destination_host {
            avps.push(DiameterAvp::new_utf8(AVP_DESTINATION_HOST, dest_host));
        }

        // QoS AVPs
        if let Some(h_acc) = self.lcs_qos.horizontal_accuracy {
            avps.push(DiameterAvp::new_u32(AVP_HORIZONTAL_ACCURACY, h_acc));
        }
        if let Some(v_acc) = self.lcs_qos.vertical_accuracy {
            avps.push(DiameterAvp::new_u32(AVP_VERTICAL_ACCURACY, v_acc));
        }

        if let Some(deferred) = &self.deferred_location_type {
            avps.push(DiameterAvp::new_u32(AVP_DEFERRED_LOCATION_TYPE, deferred.0));
        }
        if let Some(ref_num) = self.lcs_reference_number {
            avps.push(DiameterAvp::new_u32(AVP_LCS_REFERENCE_NUMBER, ref_num));
        }
        if let Some(ref periodic) = self.periodic_ldr {
            avps.push(DiameterAvp::new_u32(
                AVP_REPORTING_AMOUNT,
                periodic.reporting_amount,
            ));
            avps.push(DiameterAvp::new_u32(
                AVP_REPORTING_INTERVAL,
                periodic.reporting_interval_sec,
            ));
        }
        if let Some(svc_id) = self.lcs_service_type_id {
            avps.push(DiameterAvp::new_u32(AVP_LCS_SERVICE_TYPE_ID, svc_id));
        }

        DiameterMessage { header, avps }
    }
}

/// Provide-Location-Answer (PLA) message — MME/SGSN → GMLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvideLocationAnswer {
    pub session_id: String,
    pub result_code: u32,
    pub origin_host: String,
    pub origin_realm: String,
    pub location_estimate: Option<LocationEstimate>,
    pub accuracy_fulfilment: Option<AccuracyFulfilmentIndicator>,
    pub age_of_location_estimate_sec: Option<u32>,
    pub velocity_estimate: Option<Vec<u8>>,
    pub eutran_positioning_data: Option<Vec<u8>>,
    pub ecgi: Option<Vec<u8>>,
    pub lcs_reference_number: Option<u32>,
}

impl ProvideLocationAnswer {
    pub fn success(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        location: LocationEstimate,
    ) -> Self {
        ProvideLocationAnswer {
            session_id: session_id.to_string(),
            result_code: DIAMETER_SUCCESS,
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
            location_estimate: Some(location),
            accuracy_fulfilment: Some(AccuracyFulfilmentIndicator::RequestedAccuracyFulfilled),
            age_of_location_estimate_sec: Some(0),
            velocity_estimate: None,
            eutran_positioning_data: None,
            ecgi: None,
            lcs_reference_number: None,
        }
    }

    pub fn to_diameter_message(&self) -> DiameterMessage {
        let header = DiameterHeader {
            version: 1,
            length: 0,
            flags: 0x40, // P-bit set (Answer)
            command_code: DIAMETER_CMD_PROVIDE_LOCATION,
            application_id: DIAMETER_APPLICATION_SLG,
            hop_by_hop_id: 0,
            end_to_end_id: 0,
        };

        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_u32(AVP_RESULT_CODE, self.result_code));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_HOST, &self.origin_host));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_REALM, &self.origin_realm));

        if let Some(ref loc) = self.location_estimate {
            let raw = match loc {
                LocationEstimate::EllipsoidPoint {
                    latitude,
                    longitude,
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v
                }
                LocationEstimate::EllipsoidPointUncertaintyCircle {
                    latitude,
                    longitude,
                    uncertainty_radius_m,
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v.extend_from_slice(&uncertainty_radius_m.to_be_bytes());
                    v
                }
                LocationEstimate::EllipsoidPointAltitudeUncertainty {
                    latitude,
                    longitude,
                    altitude_m,
                    ..
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v.extend_from_slice(&altitude_m.to_be_bytes());
                    v
                }
                LocationEstimate::Raw(raw) => raw.clone(),
            };
            avps.push(DiameterAvp::new(AVP_LOCATION_ESTIMATE, &raw));
        }

        if let Some(afi) = &self.accuracy_fulfilment {
            avps.push(DiameterAvp::new_u32(
                AVP_ACCURACY_FULFILMENT_INDICATOR,
                *afi as u32,
            ));
        }
        if let Some(age) = self.age_of_location_estimate_sec {
            avps.push(DiameterAvp::new_u32(AVP_AGE_OF_LOCATION_ESTIMATE, age));
        }
        if let Some(ref vel) = self.velocity_estimate {
            avps.push(DiameterAvp::new(AVP_VELOCITY_ESTIMATE, vel));
        }
        if let Some(ref epos) = self.eutran_positioning_data {
            avps.push(DiameterAvp::new(AVP_EUTRAN_POSITIONING_DATA, epos));
        }
        if let Some(ref ecgi) = self.ecgi {
            avps.push(DiameterAvp::new(AVP_ECGI, ecgi));
        }
        if let Some(ref_num) = self.lcs_reference_number {
            avps.push(DiameterAvp::new_u32(AVP_LCS_REFERENCE_NUMBER, ref_num));
        }

        DiameterMessage { header, avps }
    }
}

/// Location-Report-Request (LRR) message — MME/SGSN → GMLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationReportRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub destination_realm: String,
    pub destination_host: String,
    pub imsi: String,
    pub location_event: LocationEvent,
    pub location_estimate: Option<LocationEstimate>,
    pub accuracy_fulfilment: Option<AccuracyFulfilmentIndicator>,
    pub age_of_location_estimate_sec: Option<u32>,
    pub lcs_reference_number: Option<u32>,
    pub ecgi: Option<Vec<u8>>,
}

impl LocationReportRequest {
    pub fn new(
        session_id: &str,
        imsi: &str,
        location_event: LocationEvent,
        origin_host: &str,
        origin_realm: &str,
        destination_realm: &str,
        destination_host: &str,
    ) -> Self {
        LocationReportRequest {
            session_id: session_id.to_string(),
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
            destination_realm: destination_realm.to_string(),
            destination_host: destination_host.to_string(),
            imsi: imsi.to_string(),
            location_event,
            location_estimate: None,
            accuracy_fulfilment: None,
            age_of_location_estimate_sec: None,
            lcs_reference_number: None,
            ecgi: None,
        }
    }

    pub fn to_diameter_message(&self) -> DiameterMessage {
        let header = DiameterHeader {
            version: 1,
            length: 0,
            flags: 0xC0, // R-bit + P-bit set
            command_code: DIAMETER_CMD_LOCATION_REPORT,
            application_id: DIAMETER_APPLICATION_SLG,
            hop_by_hop_id: 0,
            end_to_end_id: 0,
        };

        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_HOST, &self.origin_host));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_REALM, &self.origin_realm));
        avps.push(DiameterAvp::new_utf8(
            AVP_DESTINATION_REALM,
            &self.destination_realm,
        ));
        avps.push(DiameterAvp::new_utf8(
            AVP_DESTINATION_HOST,
            &self.destination_host,
        ));
        avps.push(DiameterAvp::new_u32(AVP_AUTH_SESSION_STATE, 1));
        avps.push(DiameterAvp::new_utf8(AVP_USER_NAME, &self.imsi));
        avps.push(DiameterAvp::new_u32(
            AVP_LOCATION_EVENT,
            self.location_event as u32,
        ));

        if let Some(ref loc) = self.location_estimate {
            let raw = match loc {
                LocationEstimate::EllipsoidPoint {
                    latitude,
                    longitude,
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v
                }
                LocationEstimate::EllipsoidPointUncertaintyCircle {
                    latitude,
                    longitude,
                    uncertainty_radius_m,
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v.extend_from_slice(&uncertainty_radius_m.to_be_bytes());
                    v
                }
                LocationEstimate::EllipsoidPointAltitudeUncertainty {
                    latitude,
                    longitude,
                    altitude_m,
                    ..
                } => {
                    let mut v = Vec::new();
                    v.extend_from_slice(&latitude.to_be_bytes());
                    v.extend_from_slice(&longitude.to_be_bytes());
                    v.extend_from_slice(&altitude_m.to_be_bytes());
                    v
                }
                LocationEstimate::Raw(raw) => raw.clone(),
            };
            avps.push(DiameterAvp::new(AVP_LOCATION_ESTIMATE, &raw));
        }
        if let Some(afi) = &self.accuracy_fulfilment {
            avps.push(DiameterAvp::new_u32(
                AVP_ACCURACY_FULFILMENT_INDICATOR,
                *afi as u32,
            ));
        }
        if let Some(age) = self.age_of_location_estimate_sec {
            avps.push(DiameterAvp::new_u32(AVP_AGE_OF_LOCATION_ESTIMATE, age));
        }
        if let Some(ref_num) = self.lcs_reference_number {
            avps.push(DiameterAvp::new_u32(AVP_LCS_REFERENCE_NUMBER, ref_num));
        }
        if let Some(ref ecgi) = self.ecgi {
            avps.push(DiameterAvp::new(AVP_ECGI, ecgi));
        }

        DiameterMessage { header, avps }
    }
}

/// Location-Report-Answer (LRA) message — GMLC → MME/SGSN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationReportAnswer {
    pub session_id: String,
    pub result_code: u32,
    pub origin_host: String,
    pub origin_realm: String,
}

impl LocationReportAnswer {
    pub fn success(session_id: &str, origin_host: &str, origin_realm: &str) -> Self {
        LocationReportAnswer {
            session_id: session_id.to_string(),
            result_code: DIAMETER_SUCCESS,
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
        }
    }

    pub fn to_diameter_message(&self) -> DiameterMessage {
        let header = DiameterHeader {
            version: 1,
            length: 0,
            flags: 0x40,
            command_code: DIAMETER_CMD_LOCATION_REPORT,
            application_id: DIAMETER_APPLICATION_SLG,
            hop_by_hop_id: 0,
            end_to_end_id: 0,
        };

        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_u32(AVP_RESULT_CODE, self.result_code));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_HOST, &self.origin_host));
        avps.push(DiameterAvp::new_utf8(AVP_ORIGIN_REALM, &self.origin_realm));

        DiameterMessage { header, avps }
    }
}

// ---------------------------------------------------------------------------
// Location Session Tracking
// ---------------------------------------------------------------------------

/// State of a single GMLC location session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationSessionState {
    /// PLR sent, awaiting PLA from MME.
    PendingLocationResponse,
    /// PLA received with a valid location estimate.
    LocationReceived,
    /// Deferred/periodic session active, awaiting LRR events.
    DeferredActive { reports_remaining: Option<u32> },
    /// Session completed or cancelled.
    Completed,
}

/// A tracked GMLC location session.
#[derive(Debug, Clone)]
pub struct GmlcLocationSession {
    pub session_id: String,
    pub imsi: String,
    pub state: LocationSessionState,
    pub location_type: SlgLocationType,
    pub last_location: Option<LocationEstimate>,
    pub location_reports: Vec<LocationReportRequest>,
    pub total_reports_received: usize,
}

/// GMLC (Gateway Mobile Location Centre) SLg Engine.
///
/// Manages location sessions towards MME/SGSN: generates PLR requests,
/// processes PLA answers, and handles asynchronous LRR events for deferred/periodic
/// location services.
#[derive(Debug, Clone)]
pub struct GmlcSlgEngine {
    pub gmlc_host: String,
    pub gmlc_realm: String,
    pub sessions: HashMap<String, GmlcLocationSession>,
    pub next_session_counter: u64,
    pub total_plr_sent: usize,
    pub total_pla_received: usize,
    pub total_lrr_received: usize,
    pub total_lra_sent: usize,
}

impl GmlcSlgEngine {
    pub fn new(gmlc_host: &str, gmlc_realm: &str) -> Self {
        GmlcSlgEngine {
            gmlc_host: gmlc_host.to_string(),
            gmlc_realm: gmlc_realm.to_string(),
            sessions: HashMap::new(),
            next_session_counter: 1,
            total_plr_sent: 0,
            total_pla_received: 0,
            total_lrr_received: 0,
            total_lra_sent: 0,
        }
    }

    /// Initiates a new immediate location request (PLR).
    pub fn request_immediate_location(
        &mut self,
        imsi: &str,
        destination_realm: &str,
        qos: LcsQos,
    ) -> ProvideLocationRequest {
        let session_id = format!("{};{}", self.gmlc_host, self.next_session_counter);
        self.next_session_counter += 1;

        let mut plr = ProvideLocationRequest::new(
            &session_id,
            imsi,
            SlgLocationType::CurrentLocation,
            &self.gmlc_host,
            &self.gmlc_realm,
            destination_realm,
        );
        plr.lcs_qos = qos;

        self.sessions.insert(
            session_id.clone(),
            GmlcLocationSession {
                session_id: session_id.clone(),
                imsi: imsi.to_string(),
                state: LocationSessionState::PendingLocationResponse,
                location_type: SlgLocationType::CurrentLocation,
                last_location: None,
                location_reports: Vec::new(),
                total_reports_received: 0,
            },
        );

        self.total_plr_sent += 1;
        plr
    }

    /// Initiates a periodic deferred location request (PLR with Deferred + Periodic LDR).
    pub fn request_periodic_location(
        &mut self,
        imsi: &str,
        destination_realm: &str,
        reporting_amount: u32,
        reporting_interval_sec: u32,
    ) -> ProvideLocationRequest {
        let session_id = format!("{};{}", self.gmlc_host, self.next_session_counter);
        self.next_session_counter += 1;

        let mut plr = ProvideLocationRequest::new(
            &session_id,
            imsi,
            SlgLocationType::ActivateDeferredLocation,
            &self.gmlc_host,
            &self.gmlc_realm,
            destination_realm,
        );
        plr.deferred_location_type = Some(DeferredLocationType::PERIODIC_LDR);
        plr.periodic_ldr = Some(PeriodicLdrInformation {
            reporting_amount,
            reporting_interval_sec,
        });
        plr.lcs_reference_number = Some(self.next_session_counter as u32);

        self.sessions.insert(
            session_id.clone(),
            GmlcLocationSession {
                session_id: session_id.clone(),
                imsi: imsi.to_string(),
                state: LocationSessionState::DeferredActive {
                    reports_remaining: Some(reporting_amount),
                },
                location_type: SlgLocationType::ActivateDeferredLocation,
                last_location: None,
                location_reports: Vec::new(),
                total_reports_received: 0,
            },
        );

        self.total_plr_sent += 1;
        plr
    }

    /// Processes a Provide-Location-Answer (PLA) received from MME/SGSN.
    pub fn process_pla(&mut self, pla: &ProvideLocationAnswer) -> bool {
        self.total_pla_received += 1;

        if let Some(session) = self.sessions.get_mut(&pla.session_id) {
            if pla.result_code == DIAMETER_SUCCESS {
                session.last_location = pla.location_estimate.clone();

                // For immediate location, transition to Completed
                if session.location_type == SlgLocationType::CurrentLocation
                    || session.location_type == SlgLocationType::CurrentOrLastKnownLocation
                {
                    session.state = LocationSessionState::LocationReceived;
                }
                // For deferred, the session remains active, awaiting LRR events
            } else {
                session.state = LocationSessionState::Completed;
            }
            true
        } else {
            false
        }
    }

    /// Processes a Location-Report-Request (LRR) received from MME/SGSN.
    /// Returns a Location-Report-Answer (LRA) to send back.
    pub fn process_lrr(&mut self, lrr: &LocationReportRequest) -> LocationReportAnswer {
        self.total_lrr_received += 1;

        if let Some(session) = self.sessions.get_mut(&lrr.session_id) {
            session.last_location = lrr.location_estimate.clone();
            session.total_reports_received += 1;
            session.location_reports.push(lrr.clone());

            // Decrement periodic reporting counter
            if let LocationSessionState::DeferredActive { reports_remaining } = &mut session.state {
                if let Some(rem) = reports_remaining {
                    if *rem > 0 {
                        *rem -= 1;
                    }
                    if *rem == 0 {
                        session.state = LocationSessionState::Completed;
                    }
                }
            }
        }

        self.total_lra_sent += 1;
        LocationReportAnswer::success(&lrr.session_id, &self.gmlc_host, &self.gmlc_realm)
    }

    /// Returns the most recently received location for a given session.
    pub fn get_last_location(&self, session_id: &str) -> Option<&LocationEstimate> {
        self.sessions
            .get(session_id)
            .and_then(|s| s.last_location.as_ref())
    }

    /// Returns the complete list of location reports received for a session.
    pub fn get_location_history(&self, session_id: &str) -> Option<&[LocationReportRequest]> {
        self.sessions
            .get(session_id)
            .map(|s| s.location_reports.as_slice())
    }

    /// Returns the current state of a location session.
    pub fn get_session_state(&self, session_id: &str) -> Option<&LocationSessionState> {
        self.sessions.get(session_id).map(|s| &s.state)
    }

    /// Returns the count of active deferred tracking sessions.
    pub fn active_deferred_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state, LocationSessionState::DeferredActive { .. }))
            .count()
    }

    /// Initiates an emergency location retrieval request (3GPP TS 29.172 Section 5.2.1).
    pub fn request_emergency_location(
        &mut self,
        imsi: &str,
        destination_realm: &str,
    ) -> ProvideLocationRequest {
        let session_id = format!("{};{}", self.gmlc_host, self.next_session_counter);
        self.next_session_counter += 1;

        let mut plr = ProvideLocationRequest::new(
            &session_id,
            imsi,
            SlgLocationType::CurrentOrLastKnownLocation,
            &self.gmlc_host,
            &self.gmlc_realm,
            destination_realm,
        );
        plr.lcs_priority = LcsPriority::HighestPriority;
        plr.lcs_qos = LcsQos {
            horizontal_accuracy: Some(50),
            vertical_accuracy: None,
            velocity_requested: false,
            response_time_category: LcsResponseTime::LowDelay,
        };

        self.sessions.insert(
            session_id.clone(),
            GmlcLocationSession {
                session_id: session_id.clone(),
                imsi: imsi.to_string(),
                state: LocationSessionState::PendingLocationResponse,
                location_type: SlgLocationType::CurrentOrLastKnownLocation,
                last_location: None,
                location_reports: Vec::new(),
                total_reports_received: 0,
            },
        );

        self.total_plr_sent += 1;
        plr
    }

    /// Cancels an active deferred location tracking session (3GPP TS 29.172 Section 5.2.1).
    pub fn cancel_deferred_location(
        &mut self,
        session_id: &str,
        destination_realm: &str,
    ) -> Option<ProvideLocationRequest> {
        let session = self.sessions.get_mut(session_id)?;
        if !matches!(session.state, LocationSessionState::DeferredActive { .. }) {
            return None;
        }

        let imsi = session.imsi.clone();
        session.state = LocationSessionState::Completed;

        let plr = ProvideLocationRequest::new(
            session_id,
            &imsi,
            SlgLocationType::CancelDeferredLocation,
            &self.gmlc_host,
            &self.gmlc_realm,
            destination_realm,
        );

        self.total_plr_sent += 1;
        Some(plr)
    }
}
