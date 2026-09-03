//! 3GPP TS 38.300 Section 16.14 / TS 38.211 / TS 38.331 Release 17 5G Non-Terrestrial Networks (NTN) Engine.
//!
//! Implements 5G NR Satellite Communications & Physical Layer Compensation:
//! - LEO / MEO / GEO Satellite Orbit Ephemeris Modeling (ECEF Position & Velocity vectors)
//! - Slant Range, Propagation Delay (RTT), and Timing Advance (T_TA) Calculation
//! - Doppler Frequency Shift and Radial Velocity Compensation for High-Speed LEO (~7.5 km/s)
//! - NTN K_offset Scheduling Slot Offset computation (TS 38.214)
//! - Satellite Beam Handover Prediction based on Ground Elevation Angle

use std::collections::HashMap;

pub const SPEED_OF_LIGHT_MPS: f64 = 299_792_458.0;
pub const EARTH_RADIUS_M: f64 = 6_371_000.0;

// ---------------------------------------------------------------------------
// 5G NTN Enums & Data Structures (TS 38.300 Section 16.14 / TS 38.331)
// ---------------------------------------------------------------------------

/// Satellite Orbit Classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrbitType {
    /// Low Earth Orbit (500 - 1200 km, ~7.5 km/s velocity)
    Leo,
    /// Medium Earth Orbit (2000 - 20000 km)
    Meo,
    /// Geostationary Earth Orbit (35786 km, stationary relative to surface)
    Geo,
}

/// Satellite Ephemeris Vector in ECEF Frame (TS 38.331 Section 6.3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct SatelliteEphemeris {
    pub sat_id: String,
    pub orbit_type: OrbitType,
    pub position_ecef_m: [f64; 3],   // X, Y, Z coordinates in meters
    pub velocity_ecef_mps: [f64; 3], // Vx, Vy, Vz in meters per second
    pub epoch_timestamp_s: u64,
}

/// Ground UE Position in ECEF Frame.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundUePosition {
    pub ue_id: String,
    pub position_ecef_m: [f64; 3], // X, Y, Z in meters
}

/// Calculated NTN Link Compensation Parameters (TS 38.211 / TS 38.214).
#[derive(Debug, Clone, PartialEq)]
pub struct NtnLinkMetrics {
    pub slant_range_km: f64,
    pub one_way_delay_ms: f64,
    pub round_trip_time_ms: f64,
    pub timing_advance_us: f64,
    pub k_offset_slots: u32,
    pub doppler_shift_hz: f64,
    pub radial_velocity_mps: f64,
    pub elevation_angle_deg: f64,
}

/// Satellite Handover Evaluation Result.
#[derive(Debug, Clone, PartialEq)]
pub enum NtnHandoverStatus {
    InService {
        elevation_deg: f64,
    },
    HandoverRequired {
        elevation_deg: f64,
        min_threshold_deg: f64,
    },
}

/// NTN Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtnError {
    SatelliteNotFound,
    InvalidCarrierFrequency,
    InvalidSubcarrierSpacing,
}

// ---------------------------------------------------------------------------
// Top-Level 5G NTN Engine
// ---------------------------------------------------------------------------

/// 5G Non-Terrestrial Networks (NTN) Satellite Engine.
pub struct NtnEngine {
    pub engine_id: String,
    pub satellites: HashMap<String, SatelliteEphemeris>,
}

impl NtnEngine {
    /// Create a new 5G NTN engine instance.
    pub fn new(engine_id: &str) -> Self {
        NtnEngine {
            engine_id: engine_id.to_string(),
            satellites: HashMap::new(),
        }
    }

    /// Register or update a satellite orbital ephemeris.
    pub fn register_satellite(&mut self, ephemeris: SatelliteEphemeris) {
        self.satellites.insert(ephemeris.sat_id.clone(), ephemeris);
    }

    /// Compute Slant Range, RTT, Timing Advance, K_offset, and Doppler Frequency Shift.
    pub fn compute_link_metrics(
        &self,
        sat_id: &str,
        ue_pos: &GroundUePosition,
        carrier_freq_hz: f64,
        subcarrier_spacing_khz: u32,
    ) -> Result<NtnLinkMetrics, NtnError> {
        if carrier_freq_hz <= 0.0 {
            return Err(NtnError::InvalidCarrierFrequency);
        }
        if subcarrier_spacing_khz == 0 {
            return Err(NtnError::InvalidSubcarrierSpacing);
        }

        let sat = self
            .satellites
            .get(sat_id)
            .ok_or(NtnError::SatelliteNotFound)?;

        // 1. Calculate Slant Range Vector R = P_sat - P_ue
        let rx = sat.position_ecef_m[0] - ue_pos.position_ecef_m[0];
        let ry = sat.position_ecef_m[1] - ue_pos.position_ecef_m[1];
        let rz = sat.position_ecef_m[2] - ue_pos.position_ecef_m[2];

        let slant_range_m = (rx * rx + ry * ry + rz * rz).sqrt();
        let slant_range_km = slant_range_m / 1000.0;

        // 2. Propagation Delay & Timing Advance
        let one_way_delay_s = slant_range_m / SPEED_OF_LIGHT_MPS;
        let one_way_delay_ms = one_way_delay_s * 1000.0;
        let rtt_ms = one_way_delay_ms * 2.0;
        let timing_advance_us = one_way_delay_s * 2.0 * 1_000_000.0;

        // 3. Slot Duration and K_offset Calculation (TS 38.214)
        // Slot duration in ms = 1.0 / (2^mu), where mu = log2(scs_khz / 15)
        let slot_duration_ms = match subcarrier_spacing_khz {
            15 => 1.0,
            30 => 0.5,
            60 => 0.25,
            120 => 0.125,
            _ => 1.0,
        };
        let k_offset_slots = (rtt_ms / slot_duration_ms).ceil() as u32;

        // 4. Radial Velocity & Doppler Shift Calculation
        // v_rad = (V_sat . R) / |R|
        let dot_product = sat.velocity_ecef_mps[0] * rx
            + sat.velocity_ecef_mps[1] * ry
            + sat.velocity_ecef_mps[2] * rz;

        let radial_velocity_mps = dot_product / slant_range_m;

        // Doppler Shift: delta_f = -f0 * (v_rad / c)
        let doppler_shift_hz = -carrier_freq_hz * (radial_velocity_mps / SPEED_OF_LIGHT_MPS);

        // 5. Elevation Angle Calculation
        // Dot product of UE position vector and slant vector R:
        // cos(90 - elevation) = (P_ue . R) / (|P_ue| * |R|)
        let ue_mag = (ue_pos.position_ecef_m[0] * ue_pos.position_ecef_m[0]
            + ue_pos.position_ecef_m[1] * ue_pos.position_ecef_m[1]
            + ue_pos.position_ecef_m[2] * ue_pos.position_ecef_m[2])
            .sqrt();

        let ue_dot_r = ue_pos.position_ecef_m[0] * rx
            + ue_pos.position_ecef_m[1] * ry
            + ue_pos.position_ecef_m[2] * rz;

        let cos_zenith = ue_dot_r / (ue_mag * slant_range_m);
        // clamp to -1.0 .. 1.0
        let cos_zenith_clamped = cos_zenith.max(-1.0).min(1.0);
        let zenith_rad = cos_zenith_clamped.acos();
        let elevation_deg = 90.0 - zenith_rad.to_degrees();

        Ok(NtnLinkMetrics {
            slant_range_km,
            one_way_delay_ms,
            round_trip_time_ms: rtt_ms,
            timing_advance_us,
            k_offset_slots,
            doppler_shift_hz,
            radial_velocity_mps,
            elevation_angle_deg: elevation_deg,
        })
    }

    /// Evaluate if satellite beam handover is required based on ground elevation threshold.
    pub fn evaluate_handover(
        &self,
        sat_id: &str,
        ue_pos: &GroundUePosition,
        min_elevation_deg: f64,
    ) -> Result<NtnHandoverStatus, NtnError> {
        let metrics = self.compute_link_metrics(sat_id, ue_pos, 2.0e9, 30)?;
        if metrics.elevation_angle_deg >= min_elevation_deg {
            Ok(NtnHandoverStatus::InService {
                elevation_deg: metrics.elevation_angle_deg,
            })
        } else {
            Ok(NtnHandoverStatus::HandoverRequired {
                elevation_deg: metrics.elevation_angle_deg,
                min_threshold_deg: min_elevation_deg,
            })
        }
    }
}
