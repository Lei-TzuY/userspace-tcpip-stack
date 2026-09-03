// src/diameter_s13_geo_fence.rs
//
// 3GPP TS 29.272 Diameter S13 / S13' Geofencing & Cell-ID Anomaly Detection Engine.
//
// Standard Reference:
//   - 3GPP TS 29.272 (Evolved Packet System; MME and SGSN Related Interfaces Based on Diameter Protocol)
//   - 3GPP TS 29.272 Section 5.2.1 (ME-Identity-Check Request / Answer, Command Code 324)
//   - 3GPP TS 29.061 / TS 29.274 (User-Location-Info: ECGI, TAI, TAC)
//   - 3GPP TS 23.003 (Numbering, Addressing and Identification)
//
// Concepts:
//   1. E-UTRAN Cell Global Identity (ECGI) & Tracking Area Code (TAC) Ingestion.
//   2. Geofence Boundary Validation: Allowed and Restricted Tracking Areas.
//   3. Velocity & Impossible Travel Anomaly Detection: Calculates travel speed
//      between consecutive checks; flags physically impossible speeds (> 1000 km/h).
//   4. Diameter Result-Code Signaling (2001 DIAMETER_SUCCESS vs 5004 DIAMETER_AUTHORIZATION_REJECTED).
//
// Pure safe Rust, zero external crates.

pub const DIAMETER_APPLICATION_S13: u32 = 16777252;
pub const DIAMETER_COMMAND_ECR: u32 = 324;

pub const DIAMETER_SUCCESS: u32 = 2001;
pub const DIAMETER_AUTHORIZATION_REJECTED: u32 = 5004;

/// Result verdict for geographical validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoVerdict {
    /// Device location conforms to all geofence policies and travel constraints.
    LegitimateLocation {
        tac: u32,
        plmn_id: String,
        result_code: u32,
    },
    /// Device is located inside a prohibited or restricted tracking area.
    RestrictedZoneViolation {
        tac: u32,
        plmn_id: String,
        reason: String,
        result_code: u32,
    },
    /// Impossible travel speed detected between consecutive location reports.
    ImpossibleTravelFraud {
        imei: String,
        previous_tac: u32,
        current_tac: u32,
        elapsed_secs: u64,
        calculated_speed_kmh: u64,
        max_allowed_speed_kmh: u64,
        result_code: u32,
    },
    /// Device is operating in an unauthorized foreign PLMN network.
    UnauthorizedPlmn { plmn_id: String, result_code: u32 },
}

/// Geographical coordinate point (latitude/longitude in microdegrees for integer arithmetic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoCoord {
    /// Latitude in microdegrees (-90_000_000 to +90_000_000).
    pub lat_microdeg: i32,
    /// Longitude in microdegrees (-180_000_000 to +180_000_000).
    pub lon_microdeg: i32,
}

impl GeoCoord {
    pub const fn new(lat_microdeg: i32, lon_microdeg: i32) -> Self {
        Self {
            lat_microdeg,
            lon_microdeg,
        }
    }

    /// Approximate flat-Earth distance in kilometers using integer arithmetic.
    pub fn distance_km(&self, other: &GeoCoord) -> u64 {
        let d_lat = (self.lat_microdeg - other.lat_microdeg).abs() as i64;
        let d_lon = (self.lon_microdeg - other.lon_microdeg).abs() as i64;

        // Approx: 1 degree latitude ~= 111 km -> 1 microdegree ~= 0.000111 km
        let lat_km = (d_lat * 111) / 1_000_000;
        let lon_km = (d_lon * 111) / 1_000_000;

        // Euclidean approximation: sqrt(dx^2 + dy^2) using integer sqrt
        let dist_sq = (lat_km * lat_km) + (lon_km * lon_km);
        integer_sqrt(dist_sq as u64)
    }
}

fn integer_sqrt(val: u64) -> u64 {
    if val == 0 {
        return 0;
    }
    let mut x0 = val / 2;
    if x0 == 0 {
        return 1;
    }
    let mut x1 = (x0 + val / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + val / x0) / 2;
    }
    x0
}

/// Tracking Area definition with coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackingAreaProfile {
    pub tac: u32,
    pub plmn_id: String,
    pub center_coord: GeoCoord,
    pub is_restricted: bool,
}

/// Last known location of an IMEI device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLocationHistory {
    pub imei: String,
    pub last_tac: u32,
    pub last_coord: GeoCoord,
    pub last_timestamp_secs: u64,
}

/// 3GPP Diameter S13 Geofencing & Cell-ID Anomaly Detection Engine.
#[derive(Debug, Clone)]
pub struct S13GeoFenceEngine {
    /// Allowed PLMN network IDs (MCC+MNC, e.g. "20801", "310410").
    pub allowed_plmns: Vec<String>,
    /// Configured tracking areas.
    pub tracking_areas: Vec<TrackingAreaProfile>,
    /// Per-device last reported location history.
    pub location_history: Vec<DeviceLocationHistory>,
    /// Maximum plausible travel speed in km/h (default 1000 km/h).
    pub max_travel_speed_kmh: u64,
    /// Statistics: total evaluated location checks.
    pub total_inspections: u64,
    /// Statistics: total legitimate admissions.
    pub total_legitimate: u64,
    /// Statistics: total geofence/zone violations.
    pub total_zone_violations: u64,
    /// Statistics: total impossible travel fraud detections.
    pub total_travel_anomalies: u64,
}

impl S13GeoFenceEngine {
    /// Creates a new Geofencing Engine.
    pub fn new(max_travel_speed_kmh: u64) -> Self {
        Self {
            allowed_plmns: Vec::new(),
            tracking_areas: Vec::new(),
            location_history: Vec::new(),
            max_travel_speed_kmh,
            total_inspections: 0,
            total_legitimate: 0,
            total_zone_violations: 0,
            total_travel_anomalies: 0,
        }
    }

    /// Adds an authorized PLMN.
    pub fn add_allowed_plmn(&mut self, plmn_id: &str) {
        if !self.allowed_plmns.iter().any(|p| p == plmn_id) {
            self.allowed_plmns.push(plmn_id.to_string());
        }
    }

    /// Registers a Tracking Area Code (TAC) with location coordinates and restriction flag.
    pub fn register_tracking_area(
        &mut self,
        tac: u32,
        plmn_id: &str,
        lat_microdeg: i32,
        lon_microdeg: i32,
        is_restricted: bool,
    ) {
        if let Some(pos) = self
            .tracking_areas
            .iter()
            .position(|t| t.tac == tac && t.plmn_id == plmn_id)
        {
            self.tracking_areas[pos].center_coord = GeoCoord::new(lat_microdeg, lon_microdeg);
            self.tracking_areas[pos].is_restricted = is_restricted;
        } else {
            self.tracking_areas.push(TrackingAreaProfile {
                tac,
                plmn_id: plmn_id.to_string(),
                center_coord: GeoCoord::new(lat_microdeg, lon_microdeg),
                is_restricted,
            });
        }
    }

    /// Validates an incoming Diameter S13 Equipment-Check Request (ECR) location.
    pub fn inspect_equipment_location(
        &mut self,
        imei: &str,
        tac: u32,
        plmn_id: &str,
        timestamp_secs: u64,
    ) -> GeoVerdict {
        self.total_inspections += 1;

        // 1. Check PLMN authorization
        if !self.allowed_plmns.is_empty() && !self.allowed_plmns.iter().any(|p| p == plmn_id) {
            self.total_zone_violations += 1;
            return GeoVerdict::UnauthorizedPlmn {
                plmn_id: plmn_id.to_string(),
                result_code: DIAMETER_AUTHORIZATION_REJECTED,
            };
        }

        // 2. Lookup TAC profile
        let tac_profile = self
            .tracking_areas
            .iter()
            .find(|t| t.tac == tac && t.plmn_id == plmn_id)
            .cloned();

        let (coord, is_restricted) = match tac_profile {
            Some(ref prof) => (prof.center_coord, prof.is_restricted),
            None => (GeoCoord::new(0, 0), false),
        };

        // 3. Check zone restriction
        if is_restricted {
            self.total_zone_violations += 1;
            return GeoVerdict::RestrictedZoneViolation {
                tac,
                plmn_id: plmn_id.to_string(),
                reason: "TAC marked as restricted/prohibited security zone".to_string(),
                result_code: DIAMETER_AUTHORIZATION_REJECTED,
            };
        }

        // 4. Check Impossible Travel / Velocity Anomaly
        if let Some(pos) = self.location_history.iter().position(|h| h.imei == imei) {
            let prev = &self.location_history[pos];
            if timestamp_secs > prev.last_timestamp_secs {
                let elapsed_secs = timestamp_secs - prev.last_timestamp_secs;
                let distance_km = prev.last_coord.distance_km(&coord);

                // Speed = (distance_km * 3600) / elapsed_secs
                let speed_kmh = (distance_km * 3600) / elapsed_secs;

                if speed_kmh > self.max_travel_speed_kmh {
                    self.total_travel_anomalies += 1;
                    return GeoVerdict::ImpossibleTravelFraud {
                        imei: imei.to_string(),
                        previous_tac: prev.last_tac,
                        current_tac: tac,
                        elapsed_secs,
                        calculated_speed_kmh: speed_kmh,
                        max_allowed_speed_kmh: self.max_travel_speed_kmh,
                        result_code: DIAMETER_AUTHORIZATION_REJECTED,
                    };
                }
            }

            // Update history
            self.location_history[pos].last_tac = tac;
            self.location_history[pos].last_coord = coord;
            self.location_history[pos].last_timestamp_secs = timestamp_secs;
        } else {
            // First time seeing this device
            self.location_history.push(DeviceLocationHistory {
                imei: imei.to_string(),
                last_tac: tac,
                last_coord: coord,
                last_timestamp_secs: timestamp_secs,
            });
        }

        self.total_legitimate += 1;
        GeoVerdict::LegitimateLocation {
            tac,
            plmn_id: plmn_id.to_string(),
            result_code: DIAMETER_SUCCESS,
        }
    }

    /// Clears all location histories.
    pub fn purge_history(&mut self) {
        self.location_history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_fence_lifecycle() {
        let mut engine = S13GeoFenceEngine::new(1000); // 1000 km/h max
        engine.add_allowed_plmn("20801");

        // TAC 10: Paris (approx 48.85 deg N, 2.35 deg E)
        engine.register_tracking_area(10, "20801", 48_850_000, 2_350_000, false);
        // TAC 20: London (approx 51.50 deg N, -0.12 deg E -> ~340 km away)
        engine.register_tracking_area(20, "20801", 51_500_000, -120_000, false);
        // TAC 99: Military border restricted zone
        engine.register_tracking_area(99, "20801", 45_000_000, 5_000_000, true);

        // 1. Initial location in Paris at t = 1000s
        let v1 = engine.inspect_equipment_location("860011112222333", 10, "20801", 1000);
        assert_eq!(
            v1,
            GeoVerdict::LegitimateLocation {
                tac: 10,
                plmn_id: "20801".to_string(),
                result_code: DIAMETER_SUCCESS,
            }
        );

        // 2. Restricted zone test
        let v_rest = engine.inspect_equipment_location("860099998888777", 99, "20801", 1000);
        match v_rest {
            GeoVerdict::RestrictedZoneViolation { result_code, .. } => {
                assert_eq!(result_code, DIAMETER_AUTHORIZATION_REJECTED);
            }
            _ => panic!("Expected RestrictedZoneViolation"),
        }

        // 3. Impossible travel: Appears in London after only 60 seconds (requires ~20,000 km/h)
        let v_fraud = engine.inspect_equipment_location("860011112222333", 20, "20801", 1060);
        match v_fraud {
            GeoVerdict::ImpossibleTravelFraud {
                calculated_speed_kmh,
                result_code,
                ..
            } => {
                assert!(calculated_speed_kmh > 1000);
                assert_eq!(result_code, DIAMETER_AUTHORIZATION_REJECTED);
            }
            _ => panic!("Expected ImpossibleTravelFraud"),
        }

        // 4. Legitimate travel after 2 hours (7200s -> ~170 km/h)
        let v_ok = engine.inspect_equipment_location("860011112222333", 20, "20801", 8200);
        assert_eq!(
            v_ok,
            GeoVerdict::LegitimateLocation {
                tac: 20,
                plmn_id: "20801".to_string(),
                result_code: DIAMETER_SUCCESS,
            }
        );
    }
}
