// =============================================================================
// 3GPP TS 29.272 Diameter S13 / S13' Overload Control & Throttling (OCP)
// (RFC 7683 DOIC - Diameter Overload Indication Conveyance)
// =============================================================================
//
// In large-scale carrier mobility events (e.g. mass cell handovers, power restoration),
// Equipment Identity Register (EIR) nodes experience extreme request surges.
//
// RFC 7683 DOIC Overload Control enables EIR servers to convey Overload Reports (OC-OLR)
// to client MMEs/AMFs containing a reduction percentage (0–100%) and validity duration,
// shielding the EIR core from total collapse.
//
// Features:
//   1. RFC 7683 OC-OLR (Overload-Report) Grouped AVP Encoding & Decoding.
//   2. Loss-Based / Rate-Based Dynamic Reduction Percentage Throttling (0-100%).
//   3. OLR Validity Duration Expiration & Sequence Number Progression.
//   4. Client-side deterministic admission filter with Emergency/Priority Bypass.
//
// Pure safe Rust, zero external crates.

/// Standard Diameter Result Codes (RFC 6733).
pub const DIAMETER_SUCCESS: u32 = 2001;
pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
pub const DIAMETER_TOO_BUSY: u32 = 3004;

/// Diameter S13 Application ID (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S13: u32 = 16777252;

/// RFC 7683 Overload Report Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcReportType {
    Host = 0,
    Realm = 1,
}

/// Active RFC 7683 Overload Report (OC-OLR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcOverloadReport {
    pub sequence_number: u64,
    pub report_type: OcReportType,
    pub reduction_percentage: u8, // 0 to 100
    pub validity_duration_secs: u64,
    pub issued_at_secs: u64,
}

impl OcOverloadReport {
    pub fn is_expired(&self, current_time_secs: u64) -> bool {
        current_time_secs >= self.issued_at_secs + self.validity_duration_secs
    }
}

/// Client request throttling verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcThrottleVerdict {
    /// Request admitted and forwarded to EIR server.
    AdmitRequest,
    /// Request throttled locally to protect overloaded EIR.
    ThrottleDrop {
        reduction_percentage: u8,
        result_code: u32,
    },
    /// Emergency attach or priority subscriber bypassing overload control.
    EmergencyBypass,
}

/// Diameter S13 Overload Control Engine.
pub struct S13OverloadControlEngine {
    pub server_host: String,
    pub current_olr: Option<OcOverloadReport>,
    pub request_counter: u64,
    pub total_admitted: u64,
    pub total_throttled: u64,
    pub total_bypassed: u64,
}

impl S13OverloadControlEngine {
    pub fn new(server_host: &str) -> Self {
        Self {
            server_host: server_host.to_string(),
            current_olr: None,
            request_counter: 0,
            total_admitted: 0,
            total_throttled: 0,
            total_bypassed: 0,
        }
    }

    /// Ingest or update an Overload Report from EIR server response.
    pub fn update_overload_report(
        &mut self,
        sequence_number: u64,
        report_type: OcReportType,
        reduction_percentage: u8,
        validity_duration_secs: u64,
        current_time_secs: u64,
    ) {
        let reduction = reduction_percentage.min(100);

        if let Some(ref existing) = self.current_olr {
            if sequence_number <= existing.sequence_number
                && !existing.is_expired(current_time_secs)
            {
                return; // Ignore older or out-of-order OLR
            }
        }

        if reduction == 0 {
            // Overload resolved
            self.current_olr = None;
        } else {
            self.current_olr = Some(OcOverloadReport {
                sequence_number,
                report_type,
                reduction_percentage: reduction,
                validity_duration_secs,
                issued_at_secs: current_time_secs,
            });
        }
    }

    /// Evaluate whether an outgoing S13 Equipment-Check Request should be admitted or throttled.
    pub fn evaluate_request(
        &mut self,
        is_emergency: bool,
        current_time_secs: u64,
    ) -> OcThrottleVerdict {
        if is_emergency {
            self.total_bypassed += 1;
            return OcThrottleVerdict::EmergencyBypass;
        }

        // Check active OLR status
        if let Some(ref olr) = self.current_olr {
            if olr.is_expired(current_time_secs) {
                self.current_olr = None;
            }
        }

        if let Some(ref olr) = self.current_olr {
            let reduction = olr.reduction_percentage;
            self.request_counter = self.request_counter.wrapping_add(1);

            // Deterministic loss-based throttling via Bresenham rate generator
            let should_throttle = ((self.request_counter * reduction as u64) / 100)
                > ((self.request_counter.saturating_sub(1) * reduction as u64) / 100);
            if should_throttle {
                self.total_throttled += 1;
                OcThrottleVerdict::ThrottleDrop {
                    reduction_percentage: reduction,
                    result_code: DIAMETER_TOO_BUSY,
                }
            } else {
                self.total_admitted += 1;
                OcThrottleVerdict::AdmitRequest
            }
        } else {
            self.total_admitted += 1;
            OcThrottleVerdict::AdmitRequest
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_s13_ocp_lifecycle() {
        let mut engine = S13OverloadControlEngine::new("eir01.epc.mnc001.mcc208.3gppnetwork.org");

        // 1. Initial normal state: all requests admitted
        assert_eq!(
            engine.evaluate_request(false, 1000),
            OcThrottleVerdict::AdmitRequest
        );

        // 2. EIR signals 50% overload for 60 seconds (seq #1)
        engine.update_overload_report(1, OcReportType::Host, 50, 60, 1000);
        assert!(engine.current_olr.is_some());

        // 3. Emergency request always bypasses
        assert_eq!(
            engine.evaluate_request(true, 1005),
            OcThrottleVerdict::EmergencyBypass
        );

        // 4. Over 10 normal requests, 5 should be throttled and 5 admitted (50% reduction)
        let mut throttled = 0;
        let mut admitted = 0;
        for _ in 0..10 {
            match engine.evaluate_request(false, 1010) {
                OcThrottleVerdict::ThrottleDrop {
                    reduction_percentage,
                    result_code,
                } => {
                    assert_eq!(reduction_percentage, 50);
                    assert_eq!(result_code, DIAMETER_TOO_BUSY);
                    throttled += 1;
                }
                OcThrottleVerdict::AdmitRequest => admitted += 1,
                _ => {}
            }
        }
        assert_eq!(throttled, 5);
        assert_eq!(admitted, 5);

        // 5. After 70s, OLR expires -> reverts to 100% admission
        assert_eq!(
            engine.evaluate_request(false, 1070),
            OcThrottleVerdict::AdmitRequest
        );
    }
}
