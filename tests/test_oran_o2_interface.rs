//! Integration tests for O-RAN WG6 O2 Interface Engine.

use toy_tcpip::oran_o2_interface::{
    AcceleratorResource, AcceleratorType, ComputeNodeResource, NfDeploymentDescriptor,
    NfDeploymentState, O2InterfaceEngine, O2imsAlarmEvent, O2imsAlarmSeverity, OranNfType,
    ResourcePool,
};

fn setup_test_pool() -> ResourcePool {
    let mut pool = ResourcePool::new("edge-pool-01", "Regional Edge DC", "Taipei");

    let isolated_cores: Vec<u32> = (8..24).collect(); // 16 isolated cores
    let mut node1 = ComputeNodeResource::new(
        "node-edge-01",
        "worker-01.edge.o-cloud",
        64,
        isolated_cores,
        256_000,
        32, // 32 x 1GB hugepages
    );

    node1.add_accelerator(AcceleratorResource {
        accelerator_id: "fpga-acc-01".to_string(),
        acc_type: AcceleratorType::FpgaLdpc,
        pci_address: "0000:3b:00.0".to_string(),
        numa_node: 0,
        is_allocated: false,
    });

    let mut node2 = ComputeNodeResource::new(
        "node-edge-02",
        "worker-02.edge.o-cloud",
        64,
        vec![4, 5, 6, 7],
        128_000,
        16,
    );

    node2.add_accelerator(AcceleratorResource {
        accelerator_id: "gpu-acc-01".to_string(),
        acc_type: AcceleratorType::GpuHighPhy,
        pci_address: "0000:86:00.0".to_string(),
        numa_node: 1,
        is_allocated: false,
    });

    pool.add_node(node1);
    pool.add_node(node2);
    pool
}

#[test]
fn test_o2_ims_resource_pool_and_accelerator_inventory() {
    let mut o2 = O2InterfaceEngine::new();
    let pool = setup_test_pool();
    o2.add_resource_pool(pool);

    let retrieved_pool = o2.resource_pools.get("edge-pool-01").unwrap();
    assert_eq!(retrieved_pool.name, "Regional Edge DC");
    assert_eq!(retrieved_pool.nodes.len(), 2);

    let node1 = retrieved_pool.nodes.get("node-edge-01").unwrap();
    assert_eq!(node1.accelerators.len(), 1);
    assert_eq!(node1.accelerators[0].acc_type, AcceleratorType::FpgaLdpc);
    assert!(!node1.accelerators[0].is_allocated);
}

#[test]
fn test_o2_dms_vdu_instantiation_happy_path() {
    let mut o2 = O2InterfaceEngine::new();
    let pool = setup_test_pool();
    o2.add_resource_pool(pool);

    // vDU requires 8 isolated cores, 8x1GB hugepages, and FPGA LDPC accelerator
    let vdu_desc = NfDeploymentDescriptor {
        descriptor_id: "desc-vdu-01".to_string(),
        nf_type: OranNfType::Vdu,
        required_cores: 8,
        requires_isolated_cores: true,
        required_hugepages_1gb: 8,
        required_accelerator: Some(AcceleratorType::FpgaLdpc),
        numa_aligned: true,
    };

    // 1. Instantiate vDU
    let instance = o2
        .instantiate_nf("edge-pool-01", "vdu-inst-01", vdu_desc)
        .unwrap();
    assert_eq!(instance.state, NfDeploymentState::Running);
    assert_eq!(instance.assigned_node_id, "node-edge-01");
    assert_eq!(instance.assigned_cores.len(), 8);
    assert_eq!(
        instance.assigned_accelerator_id,
        Some("fpga-acc-01".to_string())
    );

    // Verify node resource consumption
    let node1 = o2
        .resource_pools
        .get("edge-pool-01")
        .unwrap()
        .nodes
        .get("node-edge-01")
        .unwrap();
    assert_eq!(node1.allocated_isolated_cores.len(), 8);
    assert_eq!(node1.allocated_hugepages, 8);
    assert!(node1.accelerators[0].is_allocated);

    // 2. Terminate vDU
    assert!(o2.terminate_nf("vdu-inst-01").is_ok());
    let terminated_instance = o2.deployment_instances.get("vdu-inst-01").unwrap();
    assert_eq!(terminated_instance.state, NfDeploymentState::Terminated);

    // Verify node resource reclamation
    let node1_reclaimed = o2
        .resource_pools
        .get("edge-pool-01")
        .unwrap()
        .nodes
        .get("node-edge-01")
        .unwrap();
    assert!(node1_reclaimed.allocated_isolated_cores.is_empty());
    assert_eq!(node1_reclaimed.allocated_hugepages, 0);
    assert!(!node1_reclaimed.accelerators[0].is_allocated);
}

#[test]
fn test_o2_dms_deployment_rejection_insufficient_accelerator() {
    let mut o2 = O2InterfaceEngine::new();
    let mut pool = ResourcePool::new("plain-pool-01", "No Accelerator DC", "Tainan");

    let node = ComputeNodeResource::new(
        "node-plain-01",
        "worker-plain.o-cloud",
        32,
        vec![2, 3, 4, 5],
        64_000,
        16,
    );
    pool.add_node(node);
    o2.add_resource_pool(pool);

    // vDU requires FPGA which does not exist in plain-pool-01
    let vdu_desc = NfDeploymentDescriptor {
        descriptor_id: "desc-vdu-02".to_string(),
        nf_type: OranNfType::Vdu,
        required_cores: 4,
        requires_isolated_cores: true,
        required_hugepages_1gb: 4,
        required_accelerator: Some(AcceleratorType::FpgaLdpc),
        numa_aligned: true,
    };

    let err = o2
        .instantiate_nf("plain-pool-01", "vdu-fail-01", vdu_desc)
        .unwrap_err();
    assert_eq!(
        err,
        "No eligible compute node meeting deployment constraints"
    );
}

#[test]
fn test_o2_ims_hardware_alarm_notification() {
    let mut o2 = O2InterfaceEngine::new();

    let alarm = O2imsAlarmEvent {
        alarm_id: "alarm-acc-pci-01".to_string(),
        node_id: "node-edge-01".to_string(),
        resource_id: "fpga-acc-01".to_string(),
        severity: O2imsAlarmSeverity::Critical,
        description: "PCIe correctable ECC threshold exceeded on FPGA".to_string(),
        timestamp_ms: 1725360000000,
    };

    o2.raise_alarm(alarm.clone());

    let alarms = o2.get_active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].alarm_id, "alarm-acc-pci-01");
    assert_eq!(alarms[0].severity, O2imsAlarmSeverity::Critical);
}
