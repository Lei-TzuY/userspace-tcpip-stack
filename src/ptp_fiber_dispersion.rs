//! PTP Optical Fiber Delay Dispersion & Thermal Drift Compensation (IEEE 1588-2019 / ITU-T G.8275.1).
//!
//! Models and calculates temperature-dependent propagation delay drift (TCD) and chromatic dispersion
//! asymmetry in optical carrier transport fibers (ITU-T G.652 / G.655) with picosecond precision.

use crate::ptp_high_accuracy::HighPrecisionTimestamp;

/// Speed of light in vacuum (meters / second).
pub const SPEED_OF_LIGHT_VACUUM: f64 = 299_792_458.0;

/// Standard ITU-T Optical Fiber Profile.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FiberType {
    /// ITU-T G.652 Standard Single-Mode Fiber (SSMF)
    G652,
    /// ITU-T G.655 Non-Zero Dispersion-Shifted Fiber (NZDSF)
    G655,
    /// Custom fiber specification
    Custom {
        refractive_index: f64,
        tcd_ps_per_km_c: f64,  // Thermal coefficient of delay (ps / (km * °C))
        dispersion_slope: f64, // ps / (nm^2 * km)
        zero_dispersion_wavelength_nm: f64,
    },
}

impl FiberType {
    /// Nominal group refractive index around 1310/1550 nm.
    pub fn refractive_index(&self) -> f64 {
        match self {
            FiberType::G652 => 1.4682,
            FiberType::G655 => 1.4695,
            FiberType::Custom {
                refractive_index, ..
            } => *refractive_index,
        }
    }

    /// Thermal Coefficient of Delay in picoseconds per kilometer per degree Celsius (ps / (km * °C)).
    pub fn tcd_ps_per_km_c(&self) -> f64 {
        match self {
            FiberType::G652 => 37.0, // ~37 ps/(km*°C)
            FiberType::G655 => 35.0,
            FiberType::Custom {
                tcd_ps_per_km_c, ..
            } => *tcd_ps_per_km_c,
        }
    }

    /// Zero-dispersion wavelength (lambda_0 in nm).
    pub fn zero_dispersion_wavelength_nm(&self) -> f64 {
        match self {
            FiberType::G652 => 1312.0,
            FiberType::G655 => 1450.0,
            FiberType::Custom {
                zero_dispersion_wavelength_nm,
                ..
            } => *zero_dispersion_wavelength_nm,
        }
    }

    /// Dispersion slope S_0 in ps / (nm^2 * km).
    pub fn dispersion_slope(&self) -> f64 {
        match self {
            FiberType::G652 => 0.092,
            FiberType::G655 => 0.075,
            FiberType::Custom {
                dispersion_slope, ..
            } => *dispersion_slope,
        }
    }

    /// Calculates chromatic dispersion parameter D(lambda) in ps / (nm * km) per Sellmeier relation.
    pub fn chromatic_dispersion(&self, wavelength_nm: f64) -> f64 {
        let s0 = self.dispersion_slope();
        let lambda0 = self.zero_dispersion_wavelength_nm();
        (s0 / 4.0) * (wavelength_nm - (lambda0.powi(4) / wavelength_nm.powi(3)))
    }
}

/// Optical Link Wavelength Configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WavelengthConfig {
    /// Dual-strand fiber operating at identical forward and reverse wavelength (e.g., 1310 nm)
    DualStrandSameWavelength { wavelength_nm: f64 },
    /// Single-strand BiDi (Bidirectional) optical transceiver with differing TX and RX wavelengths
    SingleStrandBiDi {
        forward_wavelength_nm: f64, // Master-to-Slave (e.g. 1310 nm)
        reverse_wavelength_nm: f64, // Slave-to-Master (e.g. 1490 nm or 1550 nm)
    },
}

/// Optical Fiber Physical Link Parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct OpticalFiberLink {
    pub link_id: String,
    pub fiber_type: FiberType,
    pub length_km: f64,
    pub reference_temp_c: f64, // Calibration baseline temperature (e.g. 20.0 °C)
    pub wavelength_cfg: WavelengthConfig,
}

/// Calculated Fiber Propagation Delay & Asymmetry Results (in picoseconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiberDelayCompensation {
    /// Nominal one-way propagation delay at baseline temperature (ps)
    pub nominal_delay_ps: i64,
    /// Thermal drift delay offset at current temperature (ps)
    pub thermal_drift_ps: i64,
    /// Chromatic dispersion asymmetry offset (ps) (positive means forward path is slower)
    pub chromatic_dispersion_asym_ps: i64,
    /// Total net delay asymmetry (ps) to feed into PTP Delay Asymmetry TLV / calibration
    pub total_delay_asymmetry_ps: i64,
}

/// PTP Optical Fiber Delay Dispersion & Thermal Drift Compensation Engine.
#[derive(Debug, Clone)]
pub struct FiberThermalDispersionModel {
    pub link: OpticalFiberLink,
}

impl FiberThermalDispersionModel {
    pub fn new(link: OpticalFiberLink) -> Self {
        Self { link }
    }

    /// Computes full optical delay compensation metrics for a given operational temperature.
    pub fn calculate_compensation(&self, current_temp_c: f64) -> FiberDelayCompensation {
        let n = self.link.fiber_type.refractive_index();
        let length_m = self.link.length_km * 1000.0;

        // Nominal one-way delay: T_nom = L * n / c (seconds -> picoseconds)
        let nominal_delay_sec = (length_m * n) / SPEED_OF_LIGHT_VACUUM;
        let nominal_delay_ps = (nominal_delay_sec
            * (HighPrecisionTimestamp::PICOSECONDS_PER_SECOND as f64))
            .round() as i64;

        // Thermal drift: Delta_T_temp = L_km * TCD * (T_curr - T_ref)
        let temp_delta = current_temp_c - self.link.reference_temp_c;
        let tcd = self.link.fiber_type.tcd_ps_per_km_c();
        let thermal_drift_ps = (self.link.length_km * tcd * temp_delta).round() as i64;

        // Chromatic dispersion asymmetry:
        // Delta_T_disp = D(lambda_fwd) * L * (lambda_fwd - lambda_0) - D(lambda_rev) * L * (lambda_rev - lambda_0)
        let chromatic_dispersion_asym_ps = match self.link.wavelength_cfg {
            WavelengthConfig::DualStrandSameWavelength { .. } => 0i64,
            WavelengthConfig::SingleStrandBiDi {
                forward_wavelength_nm,
                reverse_wavelength_nm,
            } => {
                let d_fwd = self
                    .link
                    .fiber_type
                    .chromatic_dispersion(forward_wavelength_nm);
                let d_rev = self
                    .link
                    .fiber_type
                    .chromatic_dispersion(reverse_wavelength_nm);
                let delta_lambda = forward_wavelength_nm - reverse_wavelength_nm;
                let avg_d = (d_fwd + d_rev) / 2.0;
                let asym_ps = avg_d * delta_lambda * self.link.length_km;
                asym_ps.round() as i64
            }
        };

        let total_delay_asymmetry_ps = chromatic_dispersion_asym_ps;

        FiberDelayCompensation {
            nominal_delay_ps,
            thermal_drift_ps,
            chromatic_dispersion_asym_ps,
            total_delay_asymmetry_ps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fiber_thermal_and_dispersion_compensation() {
        let link = OpticalFiberLink {
            link_id: "Fronthaul-Link-1".to_string(),
            fiber_type: FiberType::G652,
            length_km: 10.0, // 10 km optical link
            reference_temp_c: 20.0,
            wavelength_cfg: WavelengthConfig::SingleStrandBiDi {
                forward_wavelength_nm: 1310.0,
                reverse_wavelength_nm: 1490.0,
            },
        };

        let model = FiberThermalDispersionModel::new(link);

        // At baseline temperature 20°C
        let comp_20c = model.calculate_compensation(20.0);
        assert_eq!(comp_20c.thermal_drift_ps, 0);
        // Nominal delay for 10km SSMF is ~48.97 microseconds = ~48_973_900 ps
        assert!(comp_20c.nominal_delay_ps > 48_000_000 && comp_20c.nominal_delay_ps < 50_000_000);
        // Dispersion asymmetry between 1310nm and 1490nm
        assert!(comp_20c.chromatic_dispersion_asym_ps != 0);

        // At elevated temperature 40°C (+20°C delta)
        let comp_40c = model.calculate_compensation(40.0);
        // Delta = 10km * 37 ps/(km*°C) * 20°C = +7400 ps
        assert_eq!(comp_40c.thermal_drift_ps, 7400);
    }
}
