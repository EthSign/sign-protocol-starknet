use sign_protocol::sp::{
    interface::{
        sp::{ISPSafeDispatcher, ISPSafeDispatcherTrait, SPErrors, SPEvents},
        sphook::{ISPHookDispatcher, ISPHookDispatcherTrait}, versionable::IVersionable
    },
    model::{attestation::{Attestation, OffchainAttestation}, schema::Schema}, core::sp::{SP}
};

use snforge_std::{
    declare, ContractClass, ContractClassTrait, test_address, start_cheat_caller_address,
    cheat_caller_address_global, stop_cheat_caller_address, stop_cheat_caller_address_global,
    start_cheat_block_timestamp, stop_cheat_block_timestamp, cheat_block_timestamp_global,
    stop_cheat_block_timestamp_global
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

#[test]
#[feature("safe_dispatcher")]
fn register() {
    let spInstance = deploy_sp_dispatcher(); // Dispatcher Instance

    let mut spy = spy_events();

    let registrant1: ContractAddress = 'registrant1'
        .try_into()
        .unwrap(); // New Address -- registrant1

    let hook_address: ContractAddress = 'hook_address'
        .try_into()
        .unwrap(); // New Address -- Hook Address

    let data_input_span = array![].span(); // Span<felt252> [Empty] -- Data

    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    let delegate_signature_input = array![];

    start_cheat_caller_address(spInstance.contract_address, registrant1);

    let schemaId = spInstance.register(schema_input, delegate_signature_input);

    assert_eq!(schemaId.unwrap(), 1);

    let schema_output = spInstance.get_schema(1).unwrap(); // Get Schema 1

    assert_eq!(schema_output.registrant, registrant1);
    assert_eq!(schema_output.revocable, false);
    assert_eq!(schema_output.data_location, 1);
    assert_eq!(schema_output.max_valid_for, 15);
    assert_eq!(schema_output.timestamp, get_block_timestamp());
    assert_eq!(schema_output.hook, hook_address);
    assert_eq!(schema_output.data, data_input_span);

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
    let spInstance = deploy_sp_dispatcher();

    let mut spy = spy_events();

    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = 'hook_address'.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

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

#[test]
#[feature("safe_dispatcher")]
fn attest() {
    let spInstance = deploy_sp_dispatcher();

    let mut spy = spy_events();

    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = 'hook_address'.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 0, 15, 0, hook_address, data_input_span);

    start_cheat_caller_address(spInstance.contract_address, registrant1);

    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    assert_eq!(schemaId, 1);

    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

    start_cheat_caller_address(spInstance.contract_address, user1);

    let delegate_signature_input = array![];

    // let _attestation_id = spInstance
    //     .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span);

    match spInstance
        .attest(attestation_input, hook_address, 0, 1, delegate_signature_input, data_input_span) {
        Result::Ok(_) => panic_with_felt252('shouldve panicked'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'ATTESTATION_INVALID_DURATION', *panic_data.at(0));
        }
    };
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
    let spInstance = deploy_sp_dispatcher();

    let registrant1: ContractAddress = 'registrant1'.try_into().unwrap();
    let hook_address: ContractAddress = 'hook_address'.try_into().unwrap();
    let data_input_span = array![].span();
    let schema_input = create_schema(registrant1, false, 1, 15, 0, hook_address, data_input_span);

    start_cheat_caller_address(spInstance.contract_address, registrant1);

    let delegate_signature_input = array![];
    let schemaId = spInstance.register(schema_input, delegate_signature_input).unwrap();
    assert_eq!(schemaId, 1);

    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let recipients_input_span = array![].span();
    let data_input_span = array![].span();
    let attestation_input = create_attestation(
        schemaId, 0, 0, 0, user1, 10, 0, false, recipients_input_span, data_input_span
    );

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

