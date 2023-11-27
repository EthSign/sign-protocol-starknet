use core::option::OptionTrait;
use core::traits::TryInto;
use core::result::ResultTrait;
use core::array::SpanTrait;
use core::array::ArrayTrait;
use starknet::{
    ContractAddress, 
    get_block_timestamp,
    secp256_trait::Signature
};
use zeroable::Zeroable;

use snforge_std::{
    declare, 
    ContractClassTrait,
    test_address
};
use debug::PrintTrait;

use starknet_attestation_service::SAS::{
    interfaces::sas::{
        ISASSafeDispatcher, 
        ISASSafeDispatcherTrait,
        SASErrors
    },
    structs::{
        schema::Schema,
        attestation::AttestationMetadata
    }
};

fn zero_signature() -> Signature {
    Signature {
        r: 0,
        s: 0,
        y_parity: false
    }
}

fn deploy_sas() -> ISASSafeDispatcher {
    let contract = declare('SAS');
    let contract_address = contract.deploy(@ArrayTrait::new()).unwrap();
    ISASSafeDispatcher { contract_address }
}

fn register_basic_schema(dispatcher: ISASSafeDispatcher) -> (felt252, Schema) {
    let schema_id = 'testSId';
    let schema = Schema {
        schema: 'test schema data',
        data_length: 3,
        hook: Zeroable::zero(),
        revocable: false,
        max_valid_for: 1000
    };
    dispatcher.register(
        schema_id,
        schema.schema, 
        schema.data_length, 
        schema.hook, 
        schema.revocable, 
        schema.max_valid_for
    );
    (schema_id, schema)
}

fn compare_attestations_with_data(
    metadata0: AttestationMetadata, 
    data0: Span::<felt252>, 
    metadata1: AttestationMetadata, 
    data1: Span::<felt252>
) -> bool {
    metadata0 == metadata1 && data0 == data1
}

#[test]
fn register_test() {
    let dispatcher = deploy_sas();
    let schema_id = 'testId';
    let schema = Schema {
        schema: 'test schema data',
        data_length: 1,
        hook: Zeroable::zero(),
        revocable: false,
        max_valid_for: 0
    };
    match dispatcher.register(
        schema_id,
        schema.schema, 
        schema.data_length, 
        schema.hook, 
        schema.revocable, 
        schema.max_valid_for
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check if schema is properly stored
    assert(
        schema == dispatcher.get_schema(schema_id).unwrap(), 
        'Schema mismatch'
    );
    // Duplicate schema_id, should panic
    match dispatcher.register(
        schema_id,
        schema.schema, 
        schema.data_length, 
        schema.hook, 
        schema.revocable, 
        schema.max_valid_for
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic - 0'
        ),
        Result::Err(data) => {
            assert(*data.at(0) == SASErrors::SCHEMA_ID_EXISTS, '');
        }
    }
}

#[test]
fn self_attest_test() {
    let dispatcher = deploy_sas();
    let (schema_id, schema) = register_basic_schema(dispatcher);
    let attestation_id = 'testAId';
    let recipient: ContractAddress = Zeroable::zero();
    let valid_until = get_block_timestamp();
    let data = (array!['0', '1', '22']).span();
    // Check if function call is successful
    match dispatcher.self_attest(
        attestation_id,
        schema_id,
        recipient,
        valid_until,
        data
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check if data is properly stored
    let (metadata_, data_) = dispatcher.get_onchain_attestation(
        attestation_id
    ).unwrap();
    let metadata = AttestationMetadata {
        attester_sig: zero_signature(),
        attester_revoke_sig: zero_signature(),
        schema_id: schema_id,
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: recipient,
        valid_until: valid_until,
        revoked: false
    };
    assert(
        compare_attestations_with_data(
            metadata, data, metadata_, data_
        ), 
        'Attestations should match'
    );
    // Duplicate attestation_id, should panic
    match dispatcher.self_attest(
        attestation_id,
        schema_id,
        recipient,
        valid_until,
        data
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic - 0'
        ),
        Result::Err(data) => {
            assert(*data.at(0) == SASErrors::ATTESTATION_ID_EXISTS, '');
        }
    }
    // Invalid duration, should panic
    let attestation_id1 = 'testAId1';
    let invalidValidUntil = get_block_timestamp() + schema.max_valid_for;
    match dispatcher.self_attest(
        attestation_id1,
        schema_id,
        recipient,
        invalidValidUntil,
        data
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic - 1'
        ),
        Result::Err(data) => {
            assert(*data.at(0) == SASErrors::ATTESTATION_INVALID_DURATION, '');
        }
    }
    // Invalid schema_id, should panic
    // Reusing attestation_id1 since it panicked
    let invalidSchemaId = 'aijsdncfoiawun';
    match dispatcher.self_attest(
        attestation_id1,
        invalidSchemaId,
        recipient,
        valid_until,
        data
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic - 2'
        ),
        Result::Err(data) => {
            assert(*data.at(0) == SASErrors::SCHEMA_ID_DOES_NOT_EXIST, '');
        }
    }
}

#[test]
fn self_attest_batch_test() {
    let dispatcher = deploy_sas();
    let (_schema_id, schema) = register_basic_schema(dispatcher);
    let attestation_id = (array!['id0', 'id1', 'id2']).span();
    let schema_id = (array![_schema_id, _schema_id, _schema_id]).span();
    let _recipient: ContractAddress = Zeroable::zero();
    let recipient = (array![_recipient, _recipient, _recipient]).span();
    let _valid_until = get_block_timestamp() + schema.max_valid_for - 1;
    let valid_until = (array![_valid_until, _valid_until, _valid_until]).span();
    let _data = (array!['0', '1', '2']).span();
    let data = (array![_data, _data, _data]).span();
    // Check if function call is successful
    match dispatcher.self_attest_batch(
        attestation_id,
        schema_id,
        recipient,
        valid_until,
        data
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check storage
    let metadata0 = AttestationMetadata {
        attester_sig: zero_signature(),
        attester_revoke_sig: zero_signature(),
        schema_id: *schema_id.at(0),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(0),
        valid_until: *valid_until.at(0),
        revoked: false
    };
    let metadata1 = AttestationMetadata {
        attester_sig: zero_signature(),
        attester_revoke_sig: zero_signature(),
        schema_id: *schema_id.at(1),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(1),
        valid_until: *valid_until.at(1),
        revoked: false
    };
    let metadata2 = AttestationMetadata {
        attester_sig: zero_signature(),
        attester_revoke_sig: zero_signature(),
        schema_id: *schema_id.at(2),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(2),
        valid_until: *valid_until.at(2),
        revoked: false
    };
    let (metadata0_, data0_) = dispatcher.get_onchain_attestation(
        *attestation_id.at(0)
    ).unwrap();
    let (metadata1_, data1_) = dispatcher.get_onchain_attestation(
        *attestation_id.at(1)
    ).unwrap();
    let (metadata2_, data2_) = dispatcher.get_onchain_attestation(
        *attestation_id.at(2)
    ).unwrap();
    assert(
        compare_attestations_with_data(
            metadata0, 
            *data.at(0), 
            metadata0_, 
            data0_
        ) &&
        compare_attestations_with_data(
            metadata1, 
            *data.at(1), 
            metadata1_, 
            data1_
        ) &&
        compare_attestations_with_data(
            metadata2, 
            *data.at(2), 
            metadata2_, 
            data2_
        ), 
        'Attestations should match'
    );
}

#[test]
fn notary_attest_test() {
    let dispatcher = deploy_sas();
    let (schema_id, schema) = register_basic_schema(dispatcher);
    let attestation_id = 'testAId';
    let attester: ContractAddress = 123.try_into().unwrap();
    let attester_sig = Signature { r: 1, s: 1, y_parity: true };
    let recipient: ContractAddress = Zeroable::zero();
    let valid_until = get_block_timestamp();
    let data = (array!['0', '1', '22']).span();
    // Check if function call is successful
    match dispatcher.notary_attest(
        attestation_id,
        schema_id,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Checking storage
    let (metadata_, data_) = dispatcher.get_onchain_attestation(
        attestation_id
    ).unwrap();
    let metadata = AttestationMetadata {
        attester_sig: attester_sig,
        attester_revoke_sig: zero_signature(),
        schema_id: schema_id,
        attester: attester,
        notary: test_address(),
        recipient: recipient,
        valid_until: valid_until,
        revoked: false
    };
    assert(
        compare_attestations_with_data(
            metadata, data, metadata_, data_
        ), 
        'Attestations should match'
    );
    // The other checks are already done in self_attest_test
}

// #[test]
// #[ignore]
// fn notary_attest_batch_test() {

// }