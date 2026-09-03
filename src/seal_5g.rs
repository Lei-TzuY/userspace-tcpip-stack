//! 3GPP TS 29.538 / TS 23.434 Release 17 5G Service Enabler Architecture Layer (SEAL) Engine.
//!
//! Implements 5G SEAL Server for Horizontal Vertical Application Enablement:
//! - Nseal_GM Service (Group Management - TS 29.538 Section 5.2):
//!   - Cross-vertical group management (V2X platooning, UAS drone swarms, industrial AGVs)
//! - Nseal_LM Service (Location Management - TS 29.538 Section 5.3):
//!   - Real-time geofence tracking, entry/exit detection, and proximity alerting
//! - Nseal_NRM Service (Network Resource Management - TS 29.538 Section 5.4):
//!   - Dynamic QoS reservation and bandwidth provisioning for vertical application groups

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G SEAL Enums & Data Structures (TS 29.538 / TS 23.434)
// ---------------------------------------------------------------------------

/// Vertical Application Layer (VAL) Domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValDomain {
    V2xAutomotive,
    UasDroneSwarm,
    IndustrialFleet,
    SmartCity,
}

/// Geographic Coordinate (Microdegrees, 1e-6 degrees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoPoint {
    pub latitude_e6: i32,  // e.g. 35_681_236 = 35.681236 deg N
    pub longitude_e6: i32, // e.g. 139_767_125 = 139.767125 deg E
}

impl GeoPoint {
    /// Approximate Euclidean distance in meters for local proximity checks.
    /// 1 microdegree latitude ~= 0.111 meters.
    /// 1 microdegree longitude ~= 0.091 meters (at ~35 deg latitude).
    pub fn approximate_distance_meters(&self, other: &GeoPoint) -> u32 {
        let d_lat = (self.latitude_e6 as i64 - other.latitude_e6 as i64).abs();
        let d_lon = (self.longitude_e6 as i64 - other.longitude_e6 as i64).abs();

        let dy_meters = (d_lat * 111) / 1000;
        let dx_meters = (d_lon * 91) / 1000;

        let dist_sq = (dx_meters * dx_meters + dy_meters * dy_meters) as f64;
        dist_sq.sqrt() as u32
    }
}

/// Geofence Zone Definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeofenceZone {
    pub zone_id: String,
    pub center: GeoPoint,
    pub radius_meters: u32,
}

/// VAL Group Configuration (TS 29.538 Section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValGroup {
    pub group_id: String,
    pub domain: ValDomain,
    pub members: Vec<String>,
    pub max_members: u32,
}

/// SEAL Alert Events emitted by Location Management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealAlertEvent {
    GeofenceEntry {
        val_user_id: String,
        zone_id: String,
    },
    GeofenceExit {
        val_user_id: String,
        zone_id: String,
    },
    ProximityDetected {
        val_user_id_a: String,
        val_user_id_b: String,
        distance_meters: u32,
    },
}

/// Network Resource Reservation (TS 29.538 Section 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosReservation {
    pub reservation_id: String,
    pub val_group_id: String,
    pub required_bandwidth_mbps: u32,
    pub max_latency_ms: u32,
    pub active: bool,
}

/// SEAL Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    GroupNotFound,
    GroupCapacityExceeded,
    MemberAlreadyInGroup,
    MemberNotFound,
    GeofenceNotFound,
    DeviceLocationNotFound,
    ReservationNotFound,
}

// ---------------------------------------------------------------------------
// Top-Level 5G SEAL Server Engine
// ---------------------------------------------------------------------------

/// 5G Service Enabler Architecture Layer Server (SEAL).
pub struct SealServerEngine {
    pub seal_id: String,
    pub groups: HashMap<String, ValGroup>,
    pub geofences: HashMap<String, GeofenceZone>,
    pub device_locations: HashMap<String, GeoPoint>,
    pub device_geofence_status: HashMap<(String, String), bool>, // (user_id, zone_id) -> inside
    pub qos_reservations: HashMap<String, QosReservation>,
    pub next_res_counter: u64,
}

impl SealServerEngine {
    /// Create a new 5G SEAL Server instance.
    pub fn new(seal_id: &str) -> Self {
        SealServerEngine {
            seal_id: seal_id.to_string(),
            groups: HashMap::new(),
            geofences: HashMap::new(),
            device_locations: HashMap::new(),
            device_geofence_status: HashMap::new(),
            qos_reservations: HashMap::new(),
            next_res_counter: 1000,
        }
    }

    // -----------------------------------------------------------------------
    // Nseal_GM: Group Management Service (TS 29.538 Section 5.2)
    // -----------------------------------------------------------------------

    /// Create a new VAL Group (e.g. V2X platoon, Drone swarm).
    pub fn create_val_group(
        &mut self,
        group_id: &str,
        domain: ValDomain,
        max_members: u32,
    ) -> Result<(), SealError> {
        let group = ValGroup {
            group_id: group_id.to_string(),
            domain,
            members: Vec::new(),
            max_members,
        };
        self.groups.insert(group_id.to_string(), group);
        Ok(())
    }

    /// Add a member to a VAL Group.
    pub fn add_group_member(&mut self, group_id: &str, val_user_id: &str) -> Result<(), SealError> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(SealError::GroupNotFound)?;
        if group.members.len() >= group.max_members as usize {
            return Err(SealError::GroupCapacityExceeded);
        }
        if group.members.iter().any(|m| m == val_user_id) {
            return Err(SealError::MemberAlreadyInGroup);
        }
        group.members.push(val_user_id.to_string());
        Ok(())
    }

    /// Remove a member from a VAL Group.
    pub fn remove_group_member(
        &mut self,
        group_id: &str,
        val_user_id: &str,
    ) -> Result<(), SealError> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(SealError::GroupNotFound)?;
        let pos = group
            .members
            .iter()
            .position(|m| m == val_user_id)
            .ok_or(SealError::MemberNotFound)?;
        group.members.remove(pos);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Nseal_LM: Location Management Service (TS 29.538 Section 5.3)
    // -----------------------------------------------------------------------

    /// Register a Geofence Zone.
    pub fn register_geofence(&mut self, zone_id: &str, center: GeoPoint, radius_meters: u32) {
        let zone = GeofenceZone {
            zone_id: zone_id.to_string(),
            center,
            radius_meters,
        };
        self.geofences.insert(zone_id.to_string(), zone);
    }

    /// Update device location and evaluate geofence transitions.
    pub fn update_device_location(
        &mut self,
        val_user_id: &str,
        new_position: GeoPoint,
    ) -> Vec<SealAlertEvent> {
        self.device_locations
            .insert(val_user_id.to_string(), new_position);
        let mut alerts = Vec::new();

        for (zone_id, zone) in &self.geofences {
            let dist = new_position.approximate_distance_meters(&zone.center);
            let currently_inside = dist <= zone.radius_meters;
            let status_key = (val_user_id.to_string(), zone_id.clone());
            let previously_inside = self
                .device_geofence_status
                .get(&status_key)
                .copied()
                .unwrap_or(false);

            if currently_inside && !previously_inside {
                self.device_geofence_status.insert(status_key, true);
                alerts.push(SealAlertEvent::GeofenceEntry {
                    val_user_id: val_user_id.to_string(),
                    zone_id: zone_id.clone(),
                });
            } else if !currently_inside && previously_inside {
                self.device_geofence_status.insert(status_key, false);
                alerts.push(SealAlertEvent::GeofenceExit {
                    val_user_id: val_user_id.to_string(),
                    zone_id: zone_id.clone(),
                });
            }
        }

        alerts
    }

    /// Check proximity between two VAL devices.
    pub fn check_proximity(
        &self,
        val_user_id_a: &str,
        val_user_id_b: &str,
        threshold_meters: u32,
    ) -> Result<Option<SealAlertEvent>, SealError> {
        let pos_a = self
            .device_locations
            .get(val_user_id_a)
            .ok_or(SealError::DeviceLocationNotFound)?;
        let pos_b = self
            .device_locations
            .get(val_user_id_b)
            .ok_or(SealError::DeviceLocationNotFound)?;

        let dist = pos_a.approximate_distance_meters(pos_b);
        if dist <= threshold_meters {
            Ok(Some(SealAlertEvent::ProximityDetected {
                val_user_id_a: val_user_id_a.to_string(),
                val_user_id_b: val_user_id_b.to_string(),
                distance_meters: dist,
            }))
        } else {
            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // Nseal_NRM: Network Resource Management Service (TS 29.538 Section 5.4)
    // -----------------------------------------------------------------------

    /// Reserve network resources (QoS / Bandwidth) for a VAL Group.
    pub fn reserve_network_resources(
        &mut self,
        val_group_id: &str,
        required_bandwidth_mbps: u32,
        max_latency_ms: u32,
    ) -> Result<String, SealError> {
        if !self.groups.contains_key(val_group_id) {
            return Err(SealError::GroupNotFound);
        }

        let res_id = format!("seal-res-{}", self.next_res_counter);
        self.next_res_counter += 1;

        let res = QosReservation {
            reservation_id: res_id.clone(),
            val_group_id: val_group_id.to_string(),
            required_bandwidth_mbps,
            max_latency_ms,
            active: true,
        };

        self.qos_reservations.insert(res_id.clone(), res);
        Ok(res_id)
    }

    /// Release network resources.
    pub fn release_network_resources(&mut self, reservation_id: &str) -> Result<(), SealError> {
        let res = self
            .qos_reservations
            .get_mut(reservation_id)
            .ok_or(SealError::ReservationNotFound)?;
        res.active = false;
        Ok(())
    }
}
