use sign_protocol::sp::{
    interface::{
        sp::{ISPSafeDispatcher, ISPSafeDispatcherTrait, SPErrors, SPEvents},
        sphook::{ISPHookDispatcher, ISPHookDispatcherTrait}, versionable::IVersionable,
    },
    model::{attestation::{Attestation, OffchainAttestation}, schema::Schema}, core::sp::{SP},
    mock::{
        mockhook::{
            MockHookContract, MockHookContract::AttestationCounterEvent,
            MockHookContract::RevocationCounterEvent, MockHookContract::Event
        },
        mocksigner::MockSigner::{
            MockSigner, IMockSignerSafeDispatcherTrait, IMockSignerSafeDispatcher
        }
    }
};

use snforge_std::{
    declare, ContractClass, ContractClassTrait, test_address, start_cheat_caller_address,
    stop_cheat_caller_address, start_cheat_block_timestamp, stop_cheat_block_timestamp,
    cheat_block_timestamp_global, stop_cheat_block_timestamp_global
};

use snforge_std::{spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait};

use starknet::{ContractAddress, event::EventEmitter, get_block_timestamp, get_caller_address};

use openzeppelin::{
    access::ownable::{OwnableComponent, interface::{IOwnableDispatcher, IOwnableDispatcherTrait,}},
    token::erc20::{ERC20Component, interface::{IERC20Dispatcher, IERC20DispatcherTrait}},
    security::pausable::PausableComponent,
};

use core::{
    result::ResultTrait, traits::Into, array::SpanTrait, zeroable::Zeroable,
    poseidon::PoseidonTrait, hash::{HashStateTrait, HashStateExTrait}
};

// Set Up Functions
fn test_address_felt252() -> felt252 {
    test_address().into()
}

#[feature("safe_dispatcher")]
fn deploy_sp() -> ContractAddress {
    let sp_class = declare("SP").unwrap();
    let (contract_address, _) = sp_class.deploy(@array![test_address_felt252()]).unwrap();
    contract_address
}

#[feature("safe_dispatcher")]
fn deploy_sp_dispatcher() -> ISPSafeDispatcher {
    ISPSafeDispatcher { contract_address: deploy_sp() }
}

fn create_schema(
    registrant: ContractAddress,
    revocable: bool,
    data_location: u8,
    max_valid_for: u64,
    timestamp: u64,
    hook: ContractAddress,
    data: Span<felt252>
) -> Schema {
    Schema { registrant, revocable, data_location, max_valid_for, timestamp, hook, data }
}

fn create_attestation(
    schema_id: u64,
    linked_attestation_id: u64,
    attest_timestamp: u64,
    revoke_timestamp: u64,
    attester: ContractAddress,
    valid_until: u64,
    data_location: u8,
    revoked: bool,
    recipients: Span<felt252>,
    data: Span<felt252>,
) -> Attestation {
    Attestation {
        schema_id,
        linked_attestation_id,
        attest_timestamp,
        revoke_timestamp,
        attester,
        valid_until,
        data_location,
        revoked,
        recipients,
        data
    }
}

#[test]
#[feature("safe_dispatcher")]
fn inital_contract_details() {
    let spInstance = deploy_sp_dispatcher();
    let schema_counter = spInstance.schema_counter().unwrap();
    assert_eq!(schema_counter, 1);
}

// A - Register Test Cases
#[test]
#[feature("safe_dispatcher")]
fn register() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher(); // Dispatcher Instance

    // Initalizing the Spy
    let mut spy = spy_events();

    // Schema Input
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    // Registering Schema
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let schemaId = spInstance.register(schema_input, delegate_signature_input);
    assert_eq!(schemaId.unwrap(), 1);

    // Asserting Schema Was Registered Correctly
    let schema_output = spInstance.get_schema(1).unwrap(); // Get Schema 1
    assert_eq!(schema_output.registrant, registrant1);
    assert_eq!(schema_output.revocable, false);
    assert_eq!(schema_output.data_location, 1);
    assert_eq!(schema_output.max_valid_for, 15);
    assert_eq!(schema_output.timestamp, get_block_timestamp());
    assert_eq!(schema_output.hook, hook_address);
    assert_eq!(schema_output.data, data_input_span);

    // Asserting Event 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::SchemaRegistered(SPEvents::SchemaRegistered { schema_id: 1 })
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn register_failure_wrongRegistrant() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Schema Input
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    // Ensuring the Registering Fails
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance.register(schema_input, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'SCHEMA_WRONG_REGISTRANT', *panic_data.at(0));
        }
    };

    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::SchemaRegistered(SPEvents::SchemaRegistered { schema_id: 1 })
                )
            ]
        );
}

// B - Attest Test Cases 
#[test]
#[feature("safe_dispatcher")]
fn attest() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Schema Input
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 0, 15, 0, hook_address, data_input_span);

    // Creating Schema 
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    assert_eq!(schemaId, 1);

    // Attestation Input
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Creating Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_INVALID_DURATION', *panic_data.at(0));
        ///                         ^ it's better to use `SPErrors::xxxx`
        }
    };

    // Assert Event
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Ensure the Attestation was Registered Correctly
    let attestation_output = spInstance.get_attestation(1).unwrap(); // Get Attestation 1

    assert_eq!(attestation_output.schema_id, schemaId);
    assert_eq!(attestation_output.linked_attestation_id, 0);
    assert_eq!(attestation_output.attest_timestamp, 0);
    assert_eq!(attestation_output.revoke_timestamp, 0);
    assert_eq!(attestation_output.attester, user1);
    assert_eq!(attestation_output.valid_until, 10);
    assert_eq!(attestation_output.data_location, 0);
    assert_eq!(attestation_output.revoked, false);
    assert_eq!(attestation_output.recipients, recipients_input_span);
    assert_eq!(attestation_output.data, data_input_span);
}

#[test]
#[feature("safe_dispatcher")]
fn attest_wrong_attester() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Schema Input
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    // Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    assert_eq!(schemaId, 1);

    // Attestation Input 
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering Attestation (with wrong Account)
    let different: ContractAddress = 'different'.try_into().unwrap();
    start_cheat_caller_address(spInstance.contract_address, different);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };
}

#[test]
#[feature("safe_dispatcher")]
fn attest_attestationAlreadyRevoked() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);
    let delegate_signature_input = array![];

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_ALREADY_REVOKED', *panic_data.at(0));
        }
    };

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Retrieving Attestation
    let attestation_output = spInstance.get_attestation(1).unwrap(); // Get Attestation 1

    // Ensuring the Attestation was Registered Correctly
    assert_eq!(attestation_output.schema_id, schemaId);
    assert_eq!(attestation_output.linked_attestation_id, 0);
    assert_eq!(attestation_output.attest_timestamp, 0);
    assert_eq!(attestation_output.revoke_timestamp, 0);
    assert_eq!(attestation_output.attester, user1);
    assert_eq!(attestation_output.valid_until, 10);
    assert_eq!(attestation_output.data_location, 0);
    assert_eq!(attestation_output.revoked, false);
    assert_eq!(attestation_output.recipients, recipients_input_span);
    assert_eq!(attestation_output.data, data_input_span);

    // Creating Attestation To Fail
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, true, recipients_input_span, data_input_span
    );

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];

    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_ALREADY_REVOKED', *panic_data.at(0));
        }
    };
}

#[test]
#[feature("safe_dispatcher")]
fn attest_linkedAttestationNonExistent() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let delegate_signature_input = array![];
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 10, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation (Ensure there is an Error)
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_NONEXISTENT', *panic_data.at(0));
        }
    };

    // Ensure nothing is emitted
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn attest_schemaNonExistent() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);
    let delegate_signature_input = array![];

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let _schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation (with Different Schema)
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        15, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation (Ensure it fails)
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'SCHEMA_NONEXISTENT', *panic_data.at(0));
        }
    };

    // Ensure nothing is emitted
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn attest_attestationInvalidDuration() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, false, 1, 5, 0, hook_address, data_input_span
    ); // max_valid_for: 5 -- SCHEMA
    let delegate_signature_input = array![];

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId,
        0,
        0,
        0,
        user1,
        10,
        0,
        false,
        recipients_input_span,
        data_input_span // valid_until: 10 -- ATTESTATION
    );

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_INVALID_DURATION', *panic_data.at(0));
        }
    };

    // Ensure nothing is emitted
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn attest_attestationLinkedAttestationWrongAttestor() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);
    let delegate_signature_input = array![];

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    let attestationID = spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span)
        .unwrap();

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Retrieving Attestation
    let attestation_output = spInstance
        .get_attestation(attestationID)
        .unwrap(); // Get Attestation 1

    // Ensuring the Attestation was Registered Correctly
    assert_eq!(attestation_output.schema_id, schemaId);
    assert_eq!(attestation_output.linked_attestation_id, 0);
    assert_eq!(attestation_output.attest_timestamp, 0);
    assert_eq!(attestation_output.revoke_timestamp, 0);
    assert_eq!(attestation_output.attester, user1);
    assert_eq!(attestation_output.valid_until, 10);
    assert_eq!(attestation_output.data_location, 0);
    assert_eq!(attestation_output.revoked, false);
    assert_eq!(attestation_output.recipients, recipients_input_span);
    assert_eq!(attestation_output.data, data_input_span);

    // Creating Attestation (Linked Attestation)
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, attestationID, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];

    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Creating Attestation (Linked Attestation)
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, attestationID, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    // Registering the Attestation (FAIL)
    let different: ContractAddress = 'different'.try_into().unwrap();
    start_cheat_caller_address(spInstance.contract_address, different);
    let delegate_signature_input = array![];

    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };
}

// C - Revoke Test Cases
#[test]
#[feature("safe_dispatcher")] // And Testing Already Revoked Error 
fn revoke() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, true, 1, 15, 0, hook_address, data_input_span
    ); // registrant, revocable, data_location, max_valid_for, timestamp, hook, data

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    let attestationID = spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span)
        .unwrap();

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Revoking the Attestation
    let delegate_signature_input = array![];
    let data_input_span = array![].span();
    start_cheat_caller_address(spInstance.contract_address, user1);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_ALREADY_REVOKED', *panic_data.at(0));
        }
    };

    // Asserting the Revoke 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationRevoked(
                        SPEvents::AttestationRevoked { attestation_id: attestationID, reason: 0 }
                    )
                )
            ]
        );

    // Revoking the Attestation Again 
    let delegate_signature_input = array![];
    let data_input_span = array![].span();
    start_cheat_caller_address(spInstance.contract_address, user1);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_ALREADY_REVOKED', *panic_data.at(0));
        }
    };
}

#[test]
#[feature("safe_dispatcher")]
fn revoke_schemaNonRevocable() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, false, 1, 15, 0, hook_address, data_input_span
    ); // registrant, revocable, data_location, max_valid_for, timestamp, hook, data

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    let attestationID = spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span)
        .unwrap();

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Revoking the Attestation (Eventhough Schema is not Revocable)
    let delegate_signature_input = array![];
    let data_input_span = array![].span();
    start_cheat_caller_address(spInstance.contract_address, user1);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_IRREVOCABLE', *panic_data.at(0));
        }
    };

    // Asserting the Revoke Not Emitted
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationRevoked(
                        SPEvents::AttestationRevoked { attestation_id: attestationID, reason: 0 }
                    )
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn revoke_wrongAttester() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, true, 1, 15, 0, hook_address, data_input_span
    ); // registrant, revocable, data_location, max_valid_for, timestamp, hook, data

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    let attestationID = spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span)
        .unwrap();

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id: 1, indexing_key: 1 }
                    )
                )
            ]
        );

    // Revoking the Attestation (with wrong Address) 
    let delegate_signature_input = array![];
    let data_input_span = array![].span();

    let different: ContractAddress = 'different'.try_into().unwrap();

    start_cheat_caller_address(spInstance.contract_address, different);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Asserting the Revoke (was not Emitted)
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::AttestationRevoked(
                        SPEvents::AttestationRevoked { attestation_id: attestationID, reason: 0 }
                    )
                )
            ]
        );
}

// D - Attest Offchain
#[test]
#[feature("safe_dispatcher")] // And Testing OC Attestation Already Exist Error
fn attest_offchain() {
    // Set Blocktimestamp to 100
    cheat_block_timestamp_global(100);

    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Attestation
    let delgate_attester_input: ContractAddress = 'delgate_attester_input'.try_into().unwrap();
    let null_address: ContractAddress = ''.try_into().unwrap();
    let delegate_signature_input = array![];
    let offchain_attestation_id_input = 0;

    // Registering the Attestation 
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);

    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationMade(
                        SPEvents::OffchainAttestationMade {
                            offchain_attestation_id: offchain_attestation_id_input
                        }
                    )
                )
            ]
        );

    // Try Attesting Again 

    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);

    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'OC_ATTESTATION_EXIST', *panic_data.at(0));
        }
    };
}

// E - Revoke Offchain
#[test]
#[feature("safe_dispatcher")] // And Testing Can Not Be Revoked Twice
fn revoke_offchain() {
    // Set Blocktimestamp to 100
    cheat_block_timestamp_global(100);

    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Attestation
    let delgate_attester_input: ContractAddress = 'delgate_attester_input'.try_into().unwrap();
    let null_address: ContractAddress = ''.try_into().unwrap();
    let delegate_signature_input = array![];
    let offchain_attestation_id_input = 0;

    // Registering the Attestation 
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);

    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationMade(
                        SPEvents::OffchainAttestationMade {
                            offchain_attestation_id: offchain_attestation_id_input
                        }
                    )
                )
            ]
        );

    // Revoking Offchain
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);

    let delegate_signature_input = array![];

    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'OC_ATTESTATION_EXIST', *panic_data.at(0));
        }
    };

    // Asserting the Revocation 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationRevoked(
                        SPEvents::OffchainAttestationRevoked {
                            offchain_attestation_id: offchain_attestation_id_input, reason: 0
                        }
                    )
                )
            ]
        );

    // Revoking Offchain (Second Time -- Should Revert)
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);

    let delegate_signature_input = array![];

    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'OC_ATTESTATION_ALREADY_REVOKED', *panic_data.at(0));
        }
    };
}

#[test]
#[feature("safe_dispatcher")]
fn revoke_offchain_wrongAttester() {
    // Set Blocktimestamp to 100
    cheat_block_timestamp_global(100);

    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Attestation
    let offchain_attestation_id_input = 0;
    let null_address: ContractAddress = ''.try_into().unwrap();
    let delegate_signature_input = array![];

    // Registering the Attestation 
    let delgate_attester_input: ContractAddress = 'delgate_attester_input'.try_into().unwrap();
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Asserting the Attestion 
    spy
        .assert_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationMade(
                        SPEvents::OffchainAttestationMade {
                            offchain_attestation_id: offchain_attestation_id_input
                        }
                    )
                )
            ]
        );

    // Revoking Offchain
    start_cheat_caller_address(spInstance.contract_address, null_address);
    let delegate_signature_input = array![];
    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_WRONG_ATTESTER', *panic_data.at(0));
        }
    };

    // Asserting the Revocation (Failed)
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationRevoked(
                        SPEvents::OffchainAttestationRevoked {
                            offchain_attestation_id: offchain_attestation_id_input, reason: 0
                        }
                    )
                )
            ]
        );
}

#[test]
#[feature("safe_dispatcher")]
fn revoke_offchain_offchainAttestationNonexistent() {
    // Set Blocktimestamp to 100
    cheat_block_timestamp_global(100);

    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Initalizing the Spy
    let mut spy = spy_events();

    // Creating Attestation
    let offchain_attestation_id_input = 0;
    let delgate_attester_input: ContractAddress = 'delgate_attester_input'.try_into().unwrap();
    let delegate_signature_input = array![];

    // Revoking Offchain
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'OC_ATTESTATION_NONEXISTENT', *panic_data.at(0));
        }
    };

    // Asserting the Revocation (Failed)
    spy
        .assert_not_emitted(
            @array![
                (
                    spInstance.contract_address,
                    SP::Event::OffchainAttestationRevoked(
                        SPEvents::OffchainAttestationRevoked {
                            offchain_attestation_id: offchain_attestation_id_input, reason: 0
                        }
                    )
                )
            ]
        );
}

// F - Attest Test Cases (with Hook)
#[test]
#[feature("safe_dispatcher")]
fn attest_and_revoke_withHook() {
    // Deploy -- Sign Protocol
    let spInstance = deploy_sp_dispatcher();

    // Deploy -- Spy Events
    let mut spy = spy_events();

    // -- Hook Address --
    let hook_class = declare("MockHookContract").unwrap(); // Declare the Class 
    let (hook_address, _) = hook_class.deploy(@array![]).unwrap(); // Deploy the Contract
    let hookClassDispatcher = ISPHookDispatcher { contract_address: hook_address };

    // Schema (Input)
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap(); // Schema Registrant
    let data_input_span = array![].span(); // Data Input
    let schema_input = create_schema(
        registrant1, true, 0, 15, 0, hook_address, data_input_span
    ); // Schema Input (Registrant, Revocable, Data_Location, Max_Valid_For, Timestamp, Hook, Data)

    // Cheat and Register Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![]; // Delegate Signature Input
    let schemaId = spInstance
        .register(schema_input, delegate_signature_input)
        .unwrap(); // Register the Schema

    // Attestation (Input)
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Cheat User1 (Address) and Register Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_INVALID_DURATION', *panic_data.at(0));
        }
    };

    // Expect Hook Event (Attestation)
    spy
        .assert_emitted(
            @array![
                (
                    hookClassDispatcher.contract_address,
                    MockHookContract::Event::AttestationCounter(
                        AttestationCounterEvent { attestation_counter: 1, balance: 0 }
                    )
                )
            ]
        );

    let delegate_signature_input = array![];

    match spInstance.revoke(1, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_INVALID_DURATION', *panic_data.at(0));
        }
    };

    // Expect Hook Event (Revocation)
    spy
        .assert_emitted(
            @array![
                (
                    hookClassDispatcher.contract_address,
                    MockHookContract::Event::RevocationCounter(
                        RevocationCounterEvent { revocation_counter: 1, balance: 0 }
                    )
                )
            ]
        );
}

// G - Paused
#[test]
#[feature("safe_dispatcher")]
fn register_paused() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher(); // Dispatcher Instance

    // Creating the Registrant
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();

    // Ensure Only Owner Can Pause Contract
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    match spInstance.pause(true) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Caller is not the owner', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Pause the Contract
    spInstance.pause(true);

    // Schema Input
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    // Registering (while Paused)
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    match spInstance.register(schema_input, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };

    // Unpause the Contract
    spInstance.pause(false);

    // Registering (while not Paused)
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    match spInstance.register(schema_input, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
}

#[test]
#[feature("safe_dispatcher")]
fn attest_paused() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, true, 1, 15, 0, hook_address, data_input_span
    ); // registrant, revocable, data_location, max_valid_for, timestamp, hook, data

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    stop_cheat_caller_address(spInstance.contract_address);

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Pause the Contract
    spInstance.pause(true);

    // Registering the Attestation (while Paused)
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Unpause the Contract
    spInstance.pause(false);

    // Registering the Attestation (while not Paused)
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);
}

#[test]
#[feature("safe_dispatcher")]
fn revoke_paused() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Creating Schema
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = ''.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(
        registrant1, true, 1, 15, 0, hook_address, data_input_span
    ); // registrant, revocable, data_location, max_valid_for, timestamp, hook, data

    //  Registering Schema
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    stop_cheat_caller_address(spInstance.contract_address);

    // Creating Attestation
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    ); // schema_id, linked_attestation_id, attest_timestamp, revoke_timestamp, attester, valid_until, data_location, revoked, recipients, data

    // Registering the Attestation
    start_cheat_caller_address(spInstance.contract_address, user1);
    let delegate_signature_input = array![];
    let attestationID = spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span)
        .unwrap();
    stop_cheat_caller_address(spInstance.contract_address);

    // Pause the Contract
    spInstance.pause(true);

    // Revoking the Attestation (while Paused)
    let delegate_signature_input = array![];
    let data_input_span = array![].span();
    start_cheat_caller_address(spInstance.contract_address, user1);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Unpause the Contract
    spInstance.pause(false);

    // Revoking the Attestation (while not Paused)
    let delegate_signature_input = array![];
    let data_input_span = array![].span();
    start_cheat_caller_address(spInstance.contract_address, user1);
    match spInstance
        .revoke(attestationID, 0, hook_address, 0, delegate_signature_input, data_input_span) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);
}

#[test]
#[feature("safe_dispatcher")]
fn attest_and_revoke_offchain_paused() {
    // Set Blocktimestamp to 100
    cheat_block_timestamp_global(100);

    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher();

    // Creating Attestation
    let delgate_attester_input: ContractAddress = 'delgate_attester_input'.try_into().unwrap();
    let null_address: ContractAddress = ''.try_into().unwrap();
    let delegate_signature_input = array![];
    let offchain_attestation_id_input = 0;

    // Pause the Contract
    spInstance.pause(true);

    // Attesting OC (while Paused - Should Fail)
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Unpause the Contract
    spInstance.pause(false);

    // Registering the Attestation (Offchain) 
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance
        .attest_offchain(offchain_attestation_id_input, null_address, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Pause the Contract
    spInstance.pause(true);

    // Revoking OC (while Paused - Should Fail)
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
    stop_cheat_caller_address(spInstance.contract_address);

    // Unpause the Contract
    spInstance.pause(false);

    // Revoking Offchain
    let delegate_signature_input = array![];
    start_cheat_caller_address(spInstance.contract_address, delgate_attester_input);
    match spInstance.revoke_offchain(offchain_attestation_id_input, 0, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'Pausable: paused', *panic_data.at(0));
        }
    };
}

// H - Signature (Delegate)
#[test]
#[feature("safe_dispatcher")]
fn test_signature() {
    // Deploying the Contract
    let spInstance = deploy_sp_dispatcher(); // Dispatcher Instance

    // Attestor
    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();

    // Signer Contract
    let signer_class = declare("MockSigner").unwrap(); // Declare the Class 
    let (mocksigner_address, _) = signer_class.deploy(@array![]).unwrap(); // Deploy the Contract
    let mocksignerDispatcher = IMockSignerSafeDispatcher { contract_address: mocksigner_address };

    // Schema Input
    let hook_address: ContractAddress = ''.try_into().unwrap(); // Hook Address
    let data_input_span = array![].span(); // Data
    let schema_input = create_schema(
        mocksigner_address, false, 1, 15, 0, hook_address, data_input_span
    );

    // Attempt Delegate Call (without Signing should fail)
    let delegate_signature_input = array!['test'];
    start_cheat_caller_address(spInstance.contract_address, registrant1);
    match spInstance.register(schema_input, delegate_signature_input) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'INVALID_DELEGATE_SIGNATURE', *panic_data.at(0));
        }
    };

    // Creating Hash and Signing 
    let message_hash: felt252 = PoseidonTrait::new()
        .update_with(schema_input)
        .update_with('REGISTER')
        .finalize();

    mocksignerDispatcher.sign(message_hash);

    let delegate_signature_input = array!['test'];

    start_cheat_caller_address(spInstance.contract_address, registrant1);
    match spInstance.register(schema_input, delegate_signature_input) {
        Result::Ok(_) => {},
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'INVALID_DELEGATE_SIGNATURE', *panic_data.at(0));
        }
    };
}

