//! O-RAN Alliance WG6 O2 Interface Engine (O2-IMS & O2-DMS Services).
//!
//! Implements cloudification and orchestration services between the Service
//! Management and Orchestration (SMO) framework and the O-Cloud:
//! - O2-IMS: Infrastructure inventory management, compute node topology,
//!   and specialized telco hardware accelerator discovery (FPGA/GPU for vDU High-PHY).
//! - O2-DMS: Cloud-native Network Function (NF) deployment lifecycle management,
//!   strict real-time CPU isolation/pinning, hugepage allocation, and fault alarms.

use std::collections::HashMap;

/// Types of hardware accelerators available in O-Cloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceleratorType {
    FpgaLdpc,      // 5G NR High-PHY LDPC encoder/decoder offload
    GpuHighPhy,    // GPU-accelerated baseband compute
    SmartNicSriov, // High-throughput DPDK/SR-IOV packet offload
}

/// Accelerator resource on an O-Cloud compute node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratorResource {
    pub accelerator_id: String,
    pub acc_type: AcceleratorType,
    pub pci_address: String,
    pub numa_node: u8,
    pub is_allocated: bool,
}

/// O-Cloud Compute Node Resource Inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeNodeResource {
    pub node_id: String,
    pub hostname: String,
    pub total_cpu_cores: u32,
    pub isolated_cores: Vec<u32>,
    pub allocated_isolated_cores: Vec<u32>,
    pub total_memory_mb: u64,
    pub hugepages_1gb: u32,
    pub allocated_hugepages: u32,
    pub accelerators: Vec<AcceleratorResource>,
}

impl ComputeNodeResource {
    pub fn new(
        node_id: impl Into<String>,
        hostname: impl Into<String>,
        total_cpu_cores: u32,
        isolated_cores: Vec<u32>,
        total_memory_mb: u64,
        hugepages_1gb: u32,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            hostname: hostname.into(),
            total_cpu_cores,
            isolated_cores,
            allocated_isolated_cores: Vec::new(),
            total_memory_mb,
            hugepages_1gb,
            allocated_hugepages: 0,
            accelerators: Vec::new(),
        }
    }

    pub fn add_accelerator(&mut self, acc: AcceleratorResource) {
        self.accelerators.push(acc);
    }
}

/// O-Cloud Resource Pool grouping compute nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePool {
    pub pool_id: String,
    pub name: String,
    pub location: String,
    pub nodes: HashMap<String, ComputeNodeResource>,
}

impl ResourcePool {
    pub fn new(
        pool_id: impl Into<String>,
        name: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            pool_id: pool_id.into(),
            name: name.into(),
            location: location.into(),
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: ComputeNodeResource) {
        self.nodes.insert(node.node_id.clone(), node);
    }
}

/// Types of virtualized Network Functions in O-RAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OranNfType {
    Vdu,       // Virtualized Distributed Unit (requires realtime cores + FPGA)
    VcuCp,     // Virtualized Centralized Unit Control Plane
    VcuUp,     // Virtualized Centralized Unit User Plane (requires hugepages)
    NearRtRic, // Near-Real-Time RIC Pod
}

/// O2-DMS NF Deployment Descriptor specifying resource constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfDeploymentDescriptor {
    pub descriptor_id: String,
    pub nf_type: OranNfType,
    pub required_cores: u32,
    pub requires_isolated_cores: bool,
    pub required_hugepages_1gb: u32,
    pub required_accelerator: Option<AcceleratorType>,
    pub numa_aligned: bool,
}

/// Lifecycle state of an NF Deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfDeploymentState {
    Pending,
    Deploying,
    Running,
    Failed,
    Terminated,
}

/// Instantiated NF Deployment Instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfDeploymentInstance {
    pub instance_id: String,
    pub descriptor: NfDeploymentDescriptor,
    pub assigned_node_id: String,
    pub assigned_cores: Vec<u32>,
    pub assigned_accelerator_id: Option<String>,
    pub state: NfDeploymentState,
}

/// Severity of an O2-IMS Infrastructure Alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum O2imsAlarmSeverity {
    Critical,
    Major,
    Minor,
    Warning,
}

/// O2-IMS Infrastructure Alarm Event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct O2imsAlarmEvent {
    pub alarm_id: String,
    pub node_id: String,
    pub resource_id: String,
    pub severity: O2imsAlarmSeverity,
    pub description: String,
    pub timestamp_ms: u64,
}

/// O-RAN WG6 O2 Interface Engine.
#[derive(Debug, Default)]
pub struct O2InterfaceEngine {
    pub resource_pools: HashMap<String, ResourcePool>,
    pub deployment_instances: HashMap<String, NfDeploymentInstance>,
    pub active_alarms: Vec<O2imsAlarmEvent>,
}

impl O2InterfaceEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_resource_pool(&mut self, pool: ResourcePool) {
        self.resource_pools.insert(pool.pool_id.clone(), pool);
    }

    /// O2-DMS: Instantiates a cloud-native NF with strict telco scheduling constraints.
    pub fn instantiate_nf(
        &mut self,
        pool_id: &str,
        instance_id: &str,
        descriptor: NfDeploymentDescriptor,
    ) -> Result<NfDeploymentInstance, &'static str> {
        let pool = self
            .resource_pools
            .get_mut(pool_id)
            .ok_or("Resource pool not found")?;

        // Find eligible compute node satisfying all constraints
        let mut candidate_node_id = None;
        let mut allocated_cores = Vec::new();
        let mut allocated_acc_id = None;

        for node in pool.nodes.values_mut() {
            // 1. Check Accelerator requirement
            let mut acc_match = None;
            if let Some(target_acc_type) = descriptor.required_accelerator {
                for acc in &mut node.accelerators {
                    if !acc.is_allocated && acc.acc_type == target_acc_type {
                        acc_match = Some(acc.accelerator_id.clone());
                        break;
                    }
                }
                if acc_match.is_none() {
                    continue; // Missing required accelerator
                }
            }

            // 2. Check Hugepage requirement
            if (node.hugepages_1gb - node.allocated_hugepages) < descriptor.required_hugepages_1gb {
                continue;
            }

            // 3. Check Isolated Cores requirement
            if descriptor.requires_isolated_cores {
                let available_isolated: Vec<u32> = node
                    .isolated_cores
                    .iter()
                    .filter(|c| !node.allocated_isolated_cores.contains(c))
                    .copied()
                    .collect();

                if available_isolated.len() < (descriptor.required_cores as usize) {
                    continue; // Insufficient isolated real-time cores
                }

                allocated_cores = available_isolated[..descriptor.required_cores as usize].to_vec();
            } else {
                allocated_cores = (0..descriptor.required_cores).collect();
            }

            // Node qualifies! Apply allocation
            if let Some(ref acc_id) = acc_match {
                for acc in &mut node.accelerators {
                    if acc.accelerator_id == *acc_id {
                        acc.is_allocated = true;
                        break;
                    }
                }
            }

            node.allocated_isolated_cores
                .extend_from_slice(&allocated_cores);
            node.allocated_hugepages += descriptor.required_hugepages_1gb;

            candidate_node_id = Some(node.node_id.clone());
            allocated_acc_id = acc_match;
            break;
        }

        let node_id =
            candidate_node_id.ok_or("No eligible compute node meeting deployment constraints")?;

        let instance = NfDeploymentInstance {
            instance_id: instance_id.to_string(),
            descriptor,
            assigned_node_id: node_id,
            assigned_cores: allocated_cores,
            assigned_accelerator_id: allocated_acc_id,
            state: NfDeploymentState::Running,
        };

        self.deployment_instances
            .insert(instance_id.to_string(), instance.clone());
        Ok(instance)
    }

    /// O2-DMS: Terminates an NF deployment and reclaims hardware resources.
    pub fn terminate_nf(&mut self, instance_id: &str) -> Result<(), &'static str> {
        let instance = self
            .deployment_instances
            .get_mut(instance_id)
            .ok_or("NF deployment instance not found")?;

        instance.state = NfDeploymentState::Terminated;
        let node_id = instance.assigned_node_id.clone();
        let cores_to_free = instance.assigned_cores.clone();
        let hugepages_to_free = instance.descriptor.required_hugepages_1gb;
        let acc_to_free = instance.assigned_accelerator_id.clone();

        // Reclaim in resource pool
        for pool in self.resource_pools.values_mut() {
            if let Some(node) = pool.nodes.get_mut(&node_id) {
                node.allocated_isolated_cores
                    .retain(|c| !cores_to_free.contains(c));
                node.allocated_hugepages =
                    node.allocated_hugepages.saturating_sub(hugepages_to_free);

                if let Some(ref target_acc) = acc_to_free {
                    for acc in &mut node.accelerators {
                        if acc.accelerator_id == *target_acc {
                            acc.is_allocated = false;
                        }
                    }
                }
                break;
            }
        }

        Ok(())
    }

    /// O2-IMS: Raises an infrastructure alarm event.
    pub fn raise_alarm(&mut self, alarm: O2imsAlarmEvent) {
        self.active_alarms.push(alarm);
    }

    /// O2-IMS: Fetches active infrastructure alarms.
    pub fn get_active_alarms(&self) -> &[O2imsAlarmEvent] {
        &self.active_alarms
    }
}
