//! 3GPP Release 18 / Release 19 (5G-Advanced / Pre-6G) Frequency Range 3 (FR3) Giga-MIMO & Near-Field ELAA Engine.
//!
//! Standards Reference:
//! - 3GPP TR 38.868 Rel-18/Rel-19: "Study on NR support for 7–24 GHz frequency range (FR3 / Upper Mid-Band)"
//! - 3GPP TR 38.901 Rel-18: "Study on channel model for frequencies from 0.5 to 100 GHz (FR3 spatial non-stationarity enhancements)"
//! - 3GPP TS 38.101-1 / TS 38.101-2 Rel-18: "User Equipment radio transmission and reception - Frequency Range 3"
//! - 3GPP TS 38.211 / TS 38.214 Rel-18/Rel-19: "Physical channels and modulation - Giga-MIMO with 256/512/1024 antenna elements, near-field beam focusing, spherical wave propagation, and hybrid digital-analog beamforming"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::f64::consts::PI;
use std::fmt;

// ============================================================================
// 1. Constants
// ============================================================================

/// Speed of light in vacuum (meters per second).
pub const FR3_SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Default FR3 carrier frequency (10.0 GHz, Upper Mid-Band, wavelength $\lambda = 3.0\text{ cm}$).
pub const DEFAULT_FR3_CARRIER_FREQ_HZ: f64 = 10.0e9;

/// Maximum number of physical antenna elements in Giga-MIMO array (e.g. 32x32 = 1024).
pub const MAX_GIGA_MIMO_ELEMENTS: usize = 1024;

// ============================================================================
// 2. Error Types
// ============================================================================

/// Errors encountered during FR3 Giga-MIMO operations.
#[derive(Debug, Clone, PartialEq)]
pub enum Fr3MimoError {
    /// Array dimension exceeds supported maximum (1024 elements).
    ArrayDimensionExceeded { requested: usize, max: usize },
    /// Invalid carrier frequency (outside FR3 range: 7.125 GHz to 24.25 GHz).
    InvalidCarrierFrequency(f64),
    /// Subarray partitioning configuration mismatch.
    SubarrayConfigError(String),
    /// Precoding inversion error (e.g. singular matrix in Zero-Forcing).
    PrecodingError(String),
}

impl fmt::Display for Fr3MimoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fr3MimoError::ArrayDimensionExceeded { requested, max } => {
                write!(f, "Requested {requested} elements exceeds maximum {max}")
            }
            Fr3MimoError::InvalidCarrierFrequency(freq) => {
                write!(
                    f,
                    "Carrier frequency {freq:.2} Hz is outside FR3 range (7.125 - 24.25 GHz)"
                )
            }
            Fr3MimoError::SubarrayConfigError(msg) => {
                write!(f, "Subarray configuration error: {msg}")
            }
            Fr3MimoError::PrecodingError(msg) => write!(f, "Precoding error: {msg}"),
        }
    }
}

// ============================================================================
// 3. Complex Number Arithmetic
// ============================================================================

/// Complex number for baseband signal processing and beamforming weight synthesis.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    pub fn one() -> Self {
        Self { re: 1.0, im: 0.0 }
    }

    pub fn from_polar(r: f64, theta_rad: f64) -> Self {
        Self {
            re: r * theta_rad.cos(),
            im: r * theta_rad.sin(),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }

    pub fn scale(&self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }

    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    pub fn norm_sq(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn norm(&self) -> f64 {
        self.norm_sq().sqrt()
    }

    pub fn arg(&self) -> f64 {
        self.im.atan2(self.re)
    }
}

// ============================================================================
// 4. FR3 Array Geometry & Propagation Regime
// ============================================================================

/// Propagation regime based on Rayleigh boundary distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationRegime {
    /// Distance $d \ge d_R$: Planar wavefront approximation is valid.
    FarFieldPlaneWave,
    /// Distance $d < d_R$: Spherical wavefront with depth-of-focus power concentration.
    NearFieldSphericalWave,
}

/// Uniform Planar Array (UPA) geometry for Giga-MIMO.
#[derive(Debug, Clone, PartialEq)]
pub struct Fr3ArrayGeometry {
    pub num_rows: usize,
    pub num_cols: usize,
    pub spacing_x_m: f64,
    pub spacing_y_m: f64,
    pub carrier_freq_hz: f64,
}

impl Fr3ArrayGeometry {
    pub fn new(
        num_rows: usize,
        num_cols: usize,
        carrier_freq_hz: f64,
    ) -> Result<Self, Fr3MimoError> {
        let total = num_rows * num_cols;
        if total == 0 || total > MAX_GIGA_MIMO_ELEMENTS {
            return Err(Fr3MimoError::ArrayDimensionExceeded {
                requested: total,
                max: MAX_GIGA_MIMO_ELEMENTS,
            });
        }
        if !(7.0e9..=25.0e9).contains(&carrier_freq_hz) {
            return Err(Fr3MimoError::InvalidCarrierFrequency(carrier_freq_hz));
        }

        let lambda = FR3_SPEED_OF_LIGHT_M_S / carrier_freq_hz;
        let spacing = lambda / 2.0;

        Ok(Self {
            num_rows,
            num_cols,
            spacing_x_m: spacing,
            spacing_y_m: spacing,
            carrier_freq_hz,
        })
    }

    pub fn total_elements(&self) -> usize {
        self.num_rows * self.num_cols
    }

    pub fn wavelength_m(&self) -> f64 {
        FR3_SPEED_OF_LIGHT_M_S / self.carrier_freq_hz
    }

    /// Physical aperture diagonal dimension $D = \sqrt{L_x^2 + L_y^2}$.
    pub fn aperture_diagonal_m(&self) -> f64 {
        let lx = ((self.num_cols.saturating_sub(1)) as f64) * self.spacing_x_m;
        let ly = ((self.num_rows.saturating_sub(1)) as f64) * self.spacing_y_m;
        (lx * lx + ly * ly).sqrt()
    }

    /// Rayleigh Fraunhofer distance $d_R = \frac{2 D^2}{\lambda}$.
    pub fn rayleigh_distance_m(&self) -> f64 {
        let d = self.aperture_diagonal_m();
        (2.0 * d * d) / self.wavelength_m()
    }

    /// Evaluate propagation regime at distance $d$ meters.
    pub fn classify_regime(&self, distance_m: f64) -> PropagationRegime {
        if distance_m >= self.rayleigh_distance_m() {
            PropagationRegime::FarFieldPlaneWave
        } else {
            PropagationRegime::NearFieldSphericalWave
        }
    }

    /// Physical coordinates $(x_{m,n}, y_{m,n}, z_{m,n})$ of element $(m, n)$ centered at origin.
    pub fn element_position(&self, row: usize, col: usize) -> (f64, f64, f64) {
        let center_x = ((self.num_cols - 1) as f64) * self.spacing_x_m / 2.0;
        let center_y = ((self.num_rows - 1) as f64) * self.spacing_y_m / 2.0;

        let x = (col as f64) * self.spacing_x_m - center_x;
        let y = (row as f64) * self.spacing_y_m - center_y;
        let z = 0.0; // Array lies in the xy-plane

        (x, y, z)
    }
}

// ============================================================================
// 5. Near-Field Spherical Wavefront Beam Focusing
// ============================================================================

/// 3D Near-Field Focal Target point $(x, y, z)$ in meters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NearFieldFocusTarget {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl NearFieldFocusTarget {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn distance_from_origin(&self) -> f64 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }

    pub fn azimuth_rad(&self) -> f64 {
        self.y.atan2(self.x)
    }

    pub fn elevation_rad(&self) -> f64 {
        let r_xy = (self.x * self.x + self.y * self.y).sqrt();
        self.z.atan2(r_xy)
    }
}

/// Synthesizes near-field spherical beam focusing weights and computes array factor.
#[derive(Debug)]
pub struct NearFieldBeamformingSynthesizer;

impl NearFieldBeamformingSynthesizer {
    /// Compute near-field conjugate spherical beamforming weights.
    ///
    /// $$w_{m,n} = \frac{1}{\sqrt{N_{\text{ant}}}} \exp\left(-j \frac{2\pi}{\lambda} (d_{m,n} - d_0)\right)$$
    pub fn compute_near_field_weights(
        geometry: &Fr3ArrayGeometry,
        target: &NearFieldFocusTarget,
    ) -> Vec<Complex64> {
        let total = geometry.total_elements();
        let lambda = geometry.wavelength_m();
        let k = 2.0 * PI / lambda;
        let d0 = target.distance_from_origin();
        let norm_factor = 1.0 / (total as f64).sqrt();

        let mut weights = Vec::with_capacity(total);

        for r in 0..geometry.num_rows {
            for c in 0..geometry.num_cols {
                let (elem_x, elem_y, elem_z) = geometry.element_position(r, c);
                let dx = target.x - elem_x;
                let dy = target.y - elem_y;
                let dz = target.z - elem_z;
                let d_mn = (dx * dx + dy * dy + dz * dz).sqrt();

                // Phase delay relative to array center
                let phase = -k * (d_mn - d0);
                weights.push(Complex64::from_polar(norm_factor, phase));
            }
        }

        weights
    }

    /// Compute standard far-field steering vector (for comparison).
    ///
    /// $$a_{m,n}(\theta, \phi) = \frac{1}{\sqrt{N_{\text{ant}}}} \exp\left(j \frac{2\pi}{\lambda} (x_{m,n}\cos\theta\cos\phi + y_{m,n}\cos\theta\sin\phi)\right)$$
    pub fn compute_far_field_weights(
        geometry: &Fr3ArrayGeometry,
        azimuth_rad: f64,
        elevation_rad: f64,
    ) -> Vec<Complex64> {
        let total = geometry.total_elements();
        let lambda = geometry.wavelength_m();
        let k = 2.0 * PI / lambda;
        let norm_factor = 1.0 / (total as f64).sqrt();

        let cos_el = elevation_rad.cos();
        let u_x = cos_el * azimuth_rad.cos();
        let u_y = cos_el * azimuth_rad.sin();

        let mut weights = Vec::with_capacity(total);

        for r in 0..geometry.num_rows {
            for c in 0..geometry.num_cols {
                let (elem_x, elem_y, _) = geometry.element_position(r, c);
                let phase = k * (elem_x * u_x + elem_y * u_y);
                weights.push(Complex64::from_polar(norm_factor, phase));
            }
        }

        weights
    }

    /// Compute received field strength (array factor amplitude) at an arbitrary observation point.
    pub fn evaluate_field_at_point(
        geometry: &Fr3ArrayGeometry,
        weights: &[Complex64],
        obs_x: f64,
        obs_y: f64,
        obs_z: f64,
    ) -> f64 {
        let lambda = geometry.wavelength_m();
        let k = 2.0 * PI / lambda;
        let mut total_field = Complex64::zero();

        for (idx, w) in weights.iter().enumerate() {
            let r = idx / geometry.num_cols;
            let c = idx % geometry.num_cols;
            let (elem_x, elem_y, elem_z) = geometry.element_position(r, c);

            let dx = obs_x - elem_x;
            let dy = obs_y - elem_y;
            let dz = obs_z - elem_z;
            let d_mn = (dx * dx + dy * dy + dz * dz).sqrt().max(1e-6);

            // Green's function free-space spherical wave response
            let prop_phase = -k * d_mn;
            let h = Complex64::from_polar(1.0 / d_mn, prop_phase);

            total_field = total_field.add(&w.mul(&h));
        }

        total_field.norm()
    }

    /// Compute coherent normalized array factor amplitude at an observation point.
    ///
    /// $$AF(x, y, z) = \left|\sum_{m,n} w_{m,n} \exp\left(j \frac{2\pi}{\lambda} d_{m,n}\right)\right|$$
    ///
    /// Isolates beam focusing phase coherence from free-space path loss spreading.
    pub fn evaluate_array_factor_at_point(
        geometry: &Fr3ArrayGeometry,
        weights: &[Complex64],
        obs_x: f64,
        obs_y: f64,
        obs_z: f64,
    ) -> f64 {
        let lambda = geometry.wavelength_m();
        let k = 2.0 * PI / lambda;
        let mut total = Complex64::zero();

        for (idx, w) in weights.iter().enumerate() {
            let r = idx / geometry.num_cols;
            let c = idx % geometry.num_cols;
            let (elem_x, elem_y, elem_z) = geometry.element_position(r, c);

            let dx = obs_x - elem_x;
            let dy = obs_y - elem_y;
            let dz = obs_z - elem_z;
            let d_mn = (dx * dx + dy * dy + dz * dz).sqrt();

            let phase = k * d_mn;
            let phasor = Complex64::from_polar(1.0, phase);
            total = total.add(&w.mul(&phasor));
        }

        total.norm()
    }
}

// ============================================================================
// 6. Hybrid Digital-Analog Subarray Architecture
// ============================================================================

/// Modular subarray configuration grouping physical elements to RF chains.
#[derive(Debug, Clone, PartialEq)]
pub struct SubarrayConfig {
    pub num_subarrays: usize,
    pub elements_per_subarray: usize,
}

/// Hybrid precoder combining analog phase-shifting per subarray and digital baseband precoding.
#[derive(Debug)]
pub struct HybridSubarrayPrecoder {
    pub subarray_config: SubarrayConfig,
}

impl HybridSubarrayPrecoder {
    pub fn new(num_subarrays: usize, elements_per_subarray: usize) -> Self {
        Self {
            subarray_config: SubarrayConfig {
                num_subarrays,
                elements_per_subarray,
            },
        }
    }

    /// Generate analog phase weights for each subarray and digital weights across RF chains.
    pub fn compute_hybrid_precoding(
        &self,
        full_weights: &[Complex64],
    ) -> (Vec<Complex64>, Vec<Complex64>) {
        let k_sub = self.subarray_config.num_subarrays;
        let n_sub = self.subarray_config.elements_per_subarray;

        let mut digital_weights = Vec::with_capacity(k_sub);
        let mut analog_weights = Vec::with_capacity(k_sub * n_sub);

        for s in 0..k_sub {
            let start = s * n_sub;
            let end = (start + n_sub).min(full_weights.len());
            let sub_slice = &full_weights[start..end];

            // Representative phase of subarray (coherent average)
            let mut sum = Complex64::zero();
            for &w in sub_slice {
                sum = sum.add(&w);
            }
            let d_w = Complex64::from_polar(1.0, sum.arg());
            digital_weights.push(d_w);

            // Analog weights normalized relative to digital representative
            for &w in sub_slice {
                let rel_phase = w.arg() - d_w.arg();
                analog_weights.push(Complex64::from_polar(1.0, rel_phase));
            }
        }

        (digital_weights, analog_weights)
    }
}

// ============================================================================
// 7. Spatial Non-Stationarity & Visibility Region (VR) Modeling
// ============================================================================

/// Visibility state of ELAA subarrays due to physical blockage or extreme scale.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibilityRegion {
    pub is_visible: Vec<bool>,
}

impl VisibilityRegion {
    pub fn all_visible(num_subarrays: usize) -> Self {
        Self {
            is_visible: vec![true; num_subarrays],
        }
    }

    pub fn with_blockage(num_subarrays: usize, blocked_indices: &[usize]) -> Self {
        let mut vis = vec![true; num_subarrays];
        for &idx in blocked_indices {
            if idx < num_subarrays {
                vis[idx] = false;
            }
        }
        Self { is_visible: vis }
    }

    pub fn active_count(&self) -> usize {
        self.is_visible.iter().filter(|&&v| v).count()
    }
}

/// Dynamically re-distributes transmit power across unobstructed subarrays.
#[derive(Debug)]
pub struct SpatialNonStationarityManager;

impl SpatialNonStationarityManager {
    /// Apply visibility region mask and scale power to preserve total transmit power.
    pub fn apply_visibility_mask(
        weights: &mut [Complex64],
        elements_per_subarray: usize,
        vr: &VisibilityRegion,
    ) {
        let active_count = vr.active_count();
        if active_count == 0 {
            for w in weights.iter_mut() {
                *w = Complex64::zero();
            }
            return;
        }

        let power_scaling = (vr.is_visible.len() as f64 / active_count as f64).sqrt();

        for (s_idx, &vis) in vr.is_visible.iter().enumerate() {
            let start = s_idx * elements_per_subarray;
            let end = (start + elements_per_subarray).min(weights.len());

            for elem_idx in start..end {
                if vis {
                    weights[elem_idx] = weights[elem_idx].scale(power_scaling);
                } else {
                    weights[elem_idx] = Complex64::zero();
                }
            }
        }
    }
}

// ============================================================================
// 8. FR3 Phase Noise & PTRS Scaling (TS 38.214)
// ============================================================================

/// Phase Tracking Reference Signal (PTRS) density settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrsTimeDensity {
    /// Every OFDM symbol ($L_{\text{PT-RS}} = 1$)
    Density1 = 1,
    /// Every 2nd OFDM symbol ($L_{\text{PT-RS}} = 2$)
    Density2 = 2,
    /// Every 4th OFDM symbol ($L_{\text{PT-RS}} = 4$)
    Density4 = 4,
}

/// Phase noise compensation and PTRS density selector for FR3 Upper Mid-Band.
#[derive(Debug)]
pub struct Fr3PhaseNoiseCompensator {
    pub carrier_freq_hz: f64,
}

impl Fr3PhaseNoiseCompensator {
    pub fn new(carrier_freq_hz: f64) -> Self {
        Self { carrier_freq_hz }
    }

    /// Select PTRS time density based on carrier frequency and scheduled MCS.
    pub fn select_ptrs_density(&self, mcs: u8) -> PtrsTimeDensity {
        if self.carrier_freq_hz >= 16.0e9 || mcs >= 22 {
            PtrsTimeDensity::Density1
        } else if mcs >= 14 {
            PtrsTimeDensity::Density2
        } else {
            PtrsTimeDensity::Density4
        }
    }

    /// Estimate Common Phase Error (CPE) standard deviation in radians.
    pub fn estimate_cpe_std_rad(&self, oscillator_quality_factor: f64) -> f64 {
        // Phase noise scales proportionally with carrier frequency
        let base_cpe = (self.carrier_freq_hz / 10.0e9) * 0.05;
        base_cpe / oscillator_quality_factor.max(0.1)
    }
}

// ============================================================================
// 9. End-to-End FR3 Giga-MIMO Engine Coordinator & Telemetry
// ============================================================================

/// Telemetry metrics for the FR3 Giga-MIMO subsystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fr3GigaMimoMetrics {
    pub total_beams_synthesized: u64,
    pub near_field_focus_events: u64,
    pub far_field_steering_events: u64,
    pub non_stationarity_blockage_events: u64,
    pub avg_array_gain_db: f64,
}

/// Central Coordinator for 3GPP Rel-18/19 FR3 Giga-MIMO and Near-Field ELAA.
#[derive(Debug)]
pub struct Fr3GigaMimoEngine {
    pub geometry: Fr3ArrayGeometry,
    pub subarray_precoder: HybridSubarrayPrecoder,
    pub phase_noise: Fr3PhaseNoiseCompensator,
    pub metrics: Fr3GigaMimoMetrics,
}

impl Fr3GigaMimoEngine {
    pub fn new(
        num_rows: usize,
        num_cols: usize,
        carrier_freq_hz: f64,
        num_subarrays: usize,
    ) -> Result<Self, Fr3MimoError> {
        let geometry = Fr3ArrayGeometry::new(num_rows, num_cols, carrier_freq_hz)?;
        let total_elem = geometry.total_elements();
        if total_elem % num_subarrays != 0 {
            return Err(Fr3MimoError::SubarrayConfigError(format!(
                "Total elements {total_elem} not divisible by num_subarrays {num_subarrays}"
            )));
        }

        let elem_per_sub = total_elem / num_subarrays;
        let subarray_precoder = HybridSubarrayPrecoder::new(num_subarrays, elem_per_sub);
        let phase_noise = Fr3PhaseNoiseCompensator::new(carrier_freq_hz);

        Ok(Self {
            geometry,
            subarray_precoder,
            phase_noise,
            metrics: Fr3GigaMimoMetrics::default(),
        })
    }

    /// Synthesizes optimal beamforming weights for a target UE.
    ///
    /// Automatically classifies whether target is in Near-Field or Far-Field
    /// and synthesizes spherical focus or planar beamforming weights.
    pub fn synthesize_beam_for_ue(
        &mut self,
        target: &NearFieldFocusTarget,
        visibility: Option<&VisibilityRegion>,
    ) -> (Vec<Complex64>, PropagationRegime) {
        self.metrics.total_beams_synthesized += 1;
        let dist = target.distance_from_origin();
        let regime = self.geometry.classify_regime(dist);

        let mut weights = match regime {
            PropagationRegime::NearFieldSphericalWave => {
                self.metrics.near_field_focus_events += 1;
                NearFieldBeamformingSynthesizer::compute_near_field_weights(&self.geometry, target)
            }
            PropagationRegime::FarFieldPlaneWave => {
                self.metrics.far_field_steering_events += 1;
                NearFieldBeamformingSynthesizer::compute_far_field_weights(
                    &self.geometry,
                    target.azimuth_rad(),
                    target.elevation_rad(),
                )
            }
        };

        if let Some(vr) = visibility {
            if vr.active_count() < vr.is_visible.len() {
                self.metrics.non_stationarity_blockage_events += 1;
            }
            SpatialNonStationarityManager::apply_visibility_mask(
                &mut weights,
                self.subarray_precoder.subarray_config.elements_per_subarray,
                vr,
            );
        }

        // Theoretical array gain in dB: 10 * log10(N)
        self.metrics.avg_array_gain_db = 10.0 * (self.geometry.total_elements() as f64).log10();

        (weights, regime)
    }
}
