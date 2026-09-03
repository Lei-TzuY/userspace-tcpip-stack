//! Integration tests for 3GPP TS 29.549 / TS 23.280 / TS 23.379 5G MCX CMS & Floor Control.

use toy_tcpip::mcx_cms_5g::*;

// ---------------------------------------------------------------------------
// 1. Floor Request and Release Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_mcx_floor_request_and_release_happy_path() {
    let mut mcx = McxServerEngine::new("mcx-cms-01");

    let officer1 = "sip:officer.smith@police.gov";
    let profile = McxUserProfile {
        mcx_id: officer1.to_string(),
        priority_level: 8,
        allowed_services: vec![McxServiceType::Mcptt, McxServiceType::McVideo],
        emergency_call_capable: true,
        ambient_listening_allowed: false,
    };

    mcx.provision_user_profile(profile).unwrap();

    let group = "sip:patrol-team-alpha@police.gov";
    mcx.create_group(group, 8, 65, vec![officer1]).unwrap();

    // Officer 1 requests floor -> Granted
    let res = mcx.request_floor(group, officer1, false).unwrap();
    assert_eq!(res, FloorRequestResult::Granted);

    // Release floor
    mcx.release_floor(group, officer1).expect("Release failed");

    // Group returns to Idle
    assert_eq!(mcx.groups.get(group).unwrap().floor_state, FloorState::Idle);
}

// ---------------------------------------------------------------------------
// 2. Emergency Call Preemption
// ---------------------------------------------------------------------------

#[test]
fn test_mcx_emergency_preemption() {
    let mut mcx = McxServerEngine::new("mcx-cms-02");

    let officer = "sip:officer.jones@police.gov";
    let chief = "sip:chief.connor@police.gov";

    mcx.provision_user_profile(McxUserProfile {
        mcx_id: officer.to_string(),
        priority_level: 10,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: false,
        ambient_listening_allowed: false,
    })
    .unwrap();

    mcx.provision_user_profile(McxUserProfile {
        mcx_id: chief.to_string(),
        priority_level: 2,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: true,
        ambient_listening_allowed: true,
    })
    .unwrap();

    let group = "sip:tactical-response@police.gov";
    mcx.create_group(group, 5, 65, vec![officer, chief])
        .unwrap();

    // Officer talks in routine mode
    let res1 = mcx.request_floor(group, officer, false).unwrap();
    assert_eq!(res1, FloorRequestResult::Granted);

    // Chief initiates emergency call -> Preempts Officer immediately!
    let res2 = mcx.request_floor(group, chief, true).unwrap();
    assert_eq!(
        res2,
        FloorRequestResult::PreemptedCurrentHolder {
            previous_holder: officer.to_string(),
        }
    );

    // Active floor is now held by Chief
    match &mcx.groups.get(group).unwrap().floor_state {
        FloorState::Granted {
            holder_mcx_id,
            is_emergency,
            ..
        } => {
            assert_eq!(holder_mcx_id, chief);
            assert_eq!(*is_emergency, true);
        }
        _ => panic!("Expected Granted state"),
    }
}

// ---------------------------------------------------------------------------
// 3. Floor Denied Busy when Holder has Higher or Equal Priority
// ---------------------------------------------------------------------------

#[test]
fn test_mcx_floor_denied_busy_when_lower_priority() {
    let mut mcx = McxServerEngine::new("mcx-cms-03");

    let chief = "sip:chief@police.gov";
    let officer = "sip:officer@police.gov";

    mcx.provision_user_profile(McxUserProfile {
        mcx_id: chief.to_string(),
        priority_level: 2,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: true,
        ambient_listening_allowed: true,
    })
    .unwrap();

    mcx.provision_user_profile(McxUserProfile {
        mcx_id: officer.to_string(),
        priority_level: 9,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: true,
        ambient_listening_allowed: false,
    })
    .unwrap();

    let group = "sip:ops@police.gov";
    mcx.create_group(group, 5, 65, vec![chief, officer])
        .unwrap();

    // Chief holds the floor
    mcx.request_floor(group, chief, false).unwrap();

    // Officer requests routine floor -> Denied because Chief has higher priority
    let res = mcx.request_floor(group, officer, false).unwrap();
    assert_eq!(
        res,
        FloorRequestResult::DeniedBusy {
            current_holder: chief.to_string(),
        }
    );
}

// ---------------------------------------------------------------------------
// 4. Unauthorized Emergency Call Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_mcx_unauthorized_emergency_call_rejection() {
    let mut mcx = McxServerEngine::new("mcx-cms-04");

    let cadet = "sip:cadet@police.gov";
    mcx.provision_user_profile(McxUserProfile {
        mcx_id: cadet.to_string(),
        priority_level: 14,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: false, // Not permitted for emergency
        ambient_listening_allowed: false,
    })
    .unwrap();

    let group = "sip:training@police.gov";
    mcx.create_group(group, 10, 65, vec![cadet]).unwrap();

    let err = mcx.request_floor(group, cadet, true);
    assert_eq!(err, Err(McxError::UnauthorizedEmergencyCall));
}

// ---------------------------------------------------------------------------
// 5. Non-Member and Invalid Priority Handling
// ---------------------------------------------------------------------------

#[test]
fn test_mcx_non_member_and_invalid_priority_handling() {
    let mut mcx = McxServerEngine::new("mcx-cms-05");

    let outsider = "sip:outsider@external.org";
    mcx.provision_user_profile(McxUserProfile {
        mcx_id: outsider.to_string(),
        priority_level: 5,
        allowed_services: vec![McxServiceType::Mcptt],
        emergency_call_capable: true,
        ambient_listening_allowed: false,
    })
    .unwrap();

    let group = "sip:restricted@police.gov";
    mcx.create_group(group, 5, 65, vec!["sip:allowed@police.gov"])
        .unwrap();

    // Outsider is not a member of restricted group
    let err1 = mcx.request_floor(group, outsider, false);
    assert_eq!(err1, Err(McxError::NotGroupMember));

    // Priority 0 or 16 is out of range 1..15
    let err2 = mcx.create_group("sip:bad-group", 0, 65, vec![]);
    assert_eq!(err2, Err(McxError::InvalidPriorityLevel));

    let err3 = mcx.create_group("sip:bad-group", 16, 65, vec![]);
    assert_eq!(err3, Err(McxError::InvalidPriorityLevel));
}
