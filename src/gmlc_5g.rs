//! 3GPP TS 29.515 / TS 23.273 5G Gateway Mobile Location Centre (GMLC) Engine.
//!
//! Implements 5G Location Services (LCS) gateway and privacy authorization:
//! - Ngmlc_Location Service (TS 29.515 Section 5.2):
//!   - `ProvideLocation` operation for external Commercial, Emergency (E911), and Lawful LCS clients
//!   - Subscriber Privacy Profile verification (PPR - Privacy Profile Register)
//!   - Serving AMF routing resolution and delegated positioning request forwarding
//!   - Geo-fencing and deferred event-triggered location reporting (EnteringArea / LeavingArea)
//!   - Emergency call location priority routing with privacy check bypass

use std::collections::HashMap;

use crate::lmf_5g::{GeographicCoordinates, LocationQos};

// ---------------------------------------------------------------------------
// 5G GMLC Enums & Data Structures (TS 29.515 Section 6)
// ---------------------------------------------------------------------------

/// LCS Client Class (TS 29.515 Section 6.1.6.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcsClientClass {
    EmergencyServices,
    LawfulIntercept,
    CommercialWithNotification,
    ValueAddedWhitelisted,
}

/// Subscriber Privacy Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyConsent {
    Allowed,
    AllowedWithNotification,
    Disallowed,
}

/// Geo-Fence Definition for event-triggered location reporting.
#[derive(Debug, Clone, PartialEq)]
pub struct CircularGeoFence {
    pub center_lat: f64,
    pub center_lon: f64,
    pub radius_m: f64,
}

/// Geo-Fence Event Trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoFenceEvent {
    EnteringArea,
    LeavingArea,
    InsideArea,
}

/// Deferred Location Subscription.
#[derive(Debug, Clone, PartialEq)]
pub struct DeferredLocationSub {
    pub sub_id: String,
    pub gpsi: String,
    pub geo_fence: CircularGeoFence,
    pub event_trigger: GeoFenceEvent,
    pub client_id: String,
    pub last_inside: bool,
}

/// External LCS Client Location Request (POST /provide-location).
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideLocationRequest {
    pub client_id: String,
    pub client_class: LcsClientClass,
    pub target_gpsi: String, // External ID (MSISDN or GPSI)
    pub target_supi: Option<String>,
    pub requested_qos: Option<LocationQos>,
    pub timestamp_epoch_s: u64,
}

/// Location Response returned to external LCS Client.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideLocationResponse {
    pub target_gpsi: String,
    pub coordinates: GeographicCoordinates,
    pub serving_amf_id: String,
    pub privacy_notified: bool,
}

/// GMLC Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmlcError {
    UnauthorizedClient,
    PrivacyCheckFailed(&'static str),
    ServingAmfNotFound,
    PositioningFailed(&'static str),
    SubscriptionNotFound,
}

// ---------------------------------------------------------------------------
// Top-Level GMLC Engine
// ---------------------------------------------------------------------------

/// 5G Gateway Mobile Location Centre (GMLC) Engine.
pub struct GmlcEngine {
    pub gmlc_id: String,
    pub next_sub_id: u64,
    /// Authorized external clients: client_id -> client_class
    pub authorized_clients: HashMap<String, LcsClientClass>,
    /// Subscriber Privacy Profiles: gpsi -> PrivacyConsent
    pub privacy_profiles: HashMap<String, PrivacyConsent>,
    /// UDM Routing Cache: gpsi -> serving_amf_id
    pub amf_routing_cache: HashMap<String, String>,
    /// Active Deferred Subscriptions: sub_id -> DeferredLocationSub
    pub deferred_subscriptions: HashMap<String, DeferredLocationSub>,
}

impl GmlcEngine {
    /// Create a new GMLC engine instance.
    pub fn new(gmlc_id: &str) -> Self {
        GmlcEngine {
            gmlc_id: gmlc_id.to_string(),
            next_sub_id: 1,
            authorized_clients: HashMap::new(),
            privacy_profiles: HashMap::new(),
            amf_routing_cache: HashMap::new(),
            deferred_subscriptions: HashMap::new(),
        }
    }

    /// Register an authorized external LCS client.
    pub fn register_client(&mut self, client_id: &str, class: LcsClientClass) {
        self.authorized_clients.insert(client_id.to_string(), class);
    }

    /// Configure subscriber privacy settings.
    pub fn set_privacy_policy(&mut self, gpsi: &str, consent: PrivacyConsent) {
        self.privacy_profiles.insert(gpsi.to_string(), consent);
    }

    /// Update UDM serving AMF address for a subscriber.
    pub fn update_serving_amf(&mut self, gpsi: &str, amf_id: &str) {
        self.amf_routing_cache
            .insert(gpsi.to_string(), amf_id.to_string());
    }

    /// Ngmlc_Location_ProvideLocation operation (TS 29.515 Section 5.2.2.2).
    pub fn provide_location(
        &self,
        req: &ProvideLocationRequest,
        mock_amf_position: GeographicCoordinates,
    ) -> Result<ProvideLocationResponse, GmlcError> {
        // 1. Verify Client Authorization
        let client_class = self
            .authorized_clients
            .get(&req.client_id)
            .ok_or(GmlcError::UnauthorizedClient)?;

        // 2. Privacy Profile Verification (PPR)
        let mut privacy_notified = false;
        if *client_class != LcsClientClass::EmergencyServices
            && *client_class != LcsClientClass::LawfulIntercept
        {
            let consent = self
                .privacy_profiles
                .get(&req.target_gpsi)
                .copied()
                .unwrap_or(PrivacyConsent::Allowed);

            match consent {
                PrivacyConsent::Allowed => {}
                PrivacyConsent::AllowedWithNotification => {
                    privacy_notified = true;
                }
                PrivacyConsent::Disallowed => {
                    return Err(GmlcError::PrivacyCheckFailed("Subscriber opted out of LCS"));
                }
            }
        }

        // 3. Resolve Serving AMF from UDM cache
        let serving_amf = self
            .amf_routing_cache
            .get(&req.target_gpsi)
            .ok_or(GmlcError::ServingAmfNotFound)?;

        // 4. Return coordinates received from AMF/LMF
        Ok(ProvideLocationResponse {
            target_gpsi: req.target_gpsi.clone(),
            coordinates: mock_amf_position,
            serving_amf_id: serving_amf.clone(),
            privacy_notified,
        })
    }

    // -----------------------------------------------------------------------
    // Deferred Geo-Fencing & Event Location (Section 5.2.2.4)
    // -----------------------------------------------------------------------

    /// Create a deferred event-based location reporting subscription.
    pub fn create_deferred_subscription(
        &mut self,
        client_id: &str,
        gpsi: &str,
        geo_fence: CircularGeoFence,
        event_trigger: GeoFenceEvent,
    ) -> Result<String, GmlcError> {
        if !self.authorized_clients.contains_key(client_id) {
            return Err(GmlcError::UnauthorizedClient);
        }

        let sub_id = format!("gmlc-sub-{}", self.next_sub_id);
        self.next_sub_id += 1;

        let sub = DeferredLocationSub {
            sub_id: sub_id.clone(),
            gpsi: gpsi.to_string(),
            geo_fence,
            event_trigger,
            client_id: client_id.to_string(),
            last_inside: false,
        };

        self.deferred_subscriptions.insert(sub_id.clone(), sub);
        Ok(sub_id)
    }

    /// Evaluate current position against deferred geo-fencing subscriptions.
    /// Returns triggered subscription IDs.
    pub fn evaluate_geo_fence_events(
        &mut self,
        gpsi: &str,
        current_lat: f64,
        current_lon: f64,
    ) -> Vec<String> {
        let mut triggered = Vec::new();

        for sub in self.deferred_subscriptions.values_mut() {
            if sub.gpsi == gpsi {
                let dist_m = haversine_distance_m(
                    sub.geo_fence.center_lat,
                    sub.geo_fence.center_lon,
                    current_lat,
                    current_lon,
                );
                let is_inside = dist_m <= sub.geo_fence.radius_m;

                let event_fired = match sub.event_trigger {
                    GeoFenceEvent::EnteringArea => !sub.last_inside && is_inside,
                    GeoFenceEvent::LeavingArea => sub.last_inside && !is_inside,
                    GeoFenceEvent::InsideArea => is_inside,
                };

                sub.last_inside = is_inside;

                if event_fired {
                    triggered.push(sub.sub_id.clone());
                }
            }
        }

        triggered
    }

    /// Cancel a deferred location subscription.
    pub fn cancel_deferred_subscription(&mut self, sub_id: &str) -> Result<(), GmlcError> {
        self.deferred_subscriptions
            .remove(sub_id)
            .map(|_| ())
            .ok_or(GmlcError::SubscriptionNotFound)
    }
}

// ---------------------------------------------------------------------------
// Geodesic Distance Helper (Haversine Formula)
// ---------------------------------------------------------------------------

const EARTH_RADIUS_M: f64 = 6_371_000.0;

fn haversine_distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_M * c
}
