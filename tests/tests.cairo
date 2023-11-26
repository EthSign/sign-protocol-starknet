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
    let schemaId = 'testSId';
    let schema = Schema {
        schema: 'test schema data',
        dataLength: 3,
        hook: Zeroable::zero(),
        revocable: false,
        maxValidFor: 1000
    };
    dispatcher.register(
        schemaId,
        schema.schema, 
        schema.dataLength, 
        schema.hook, 
        schema.revocable, 
        schema.maxValidFor
    );
    (schemaId, schema)
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
#[ignore]
fn register_test() {
    let dispatcher = deploy_sas();
    let schemaId = 'testId';
    let schema = Schema {
        schema: 'test schema data',
        dataLength: 1,
        hook: Zeroable::zero(),
        revocable: false,
        maxValidFor: 0
    };
    match dispatcher.register(
        schemaId,
        schema.schema, 
        schema.dataLength, 
        schema.hook, 
        schema.revocable, 
        schema.maxValidFor
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check if schema is properly stored
    assert(
        schema == dispatcher.get_schema(schemaId).unwrap(), 
        'Schema mismatch'
    );
    // Duplicate schemaId, should panic
    match dispatcher.register(
        schemaId,
        schema.schema, 
        schema.dataLength, 
        schema.hook, 
        schema.revocable, 
        schema.maxValidFor
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
#[ignore]
fn self_attest_test() {
    let dispatcher = deploy_sas();
    let (schemaId, schema) = register_basic_schema(dispatcher);
    let attestationId = 'testAId';
    let recipient: ContractAddress = Zeroable::zero();
    let validUntil = get_block_timestamp();
    let data = (array!['0', '1', '22']).span();
    // Check if function call is successful
    match dispatcher.self_attest(
        attestationId,
        schemaId,
        recipient,
        validUntil,
        data
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check if data is properly stored
    let (metadata_, data_) = dispatcher.get_onchain_attestation(
        attestationId
    ).unwrap();
    let metadata = AttestationMetadata {
        attesterSig: zero_signature(),
        attesterRevokeSig: zero_signature(),
        schemaId: schemaId,
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: recipient,
        validUntil: validUntil,
        revoked: false
    };
    assert(
        compare_attestations_with_data(
            metadata, data, metadata_, data_
        ), 
        'Attestations should match'
    );
    // Duplicate attestationId, should panic
    match dispatcher.self_attest(
        attestationId,
        schemaId,
        recipient,
        validUntil,
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
    let attestationId1 = 'testAId1';
    let invalidValidUntil = get_block_timestamp() + schema.maxValidFor;
    match dispatcher.self_attest(
        attestationId1,
        schemaId,
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
    // Invalid schemaId, should panic
    // Reusing attestationId1 since it panicked
    let invalidSchemaId = 'aijsdncfoiawun';
    match dispatcher.self_attest(
        attestationId1,
        invalidSchemaId,
        recipient,
        validUntil,
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
#[ignore]
fn self_attest_batch_test() {
    let dispatcher = deploy_sas();
    let (_schemaId, schema) = register_basic_schema(dispatcher);
    let attestationId = (array!['id0', 'id1', 'id2']).span();
    let schemaId = (array![_schemaId, _schemaId, _schemaId]).span();
    let _recipient: ContractAddress = Zeroable::zero();
    let recipient = (array![_recipient, _recipient, _recipient]).span();
    let _validUntil = get_block_timestamp() + schema.maxValidFor - 1;
    let validUntil = (array![_validUntil, _validUntil, _validUntil]).span();
    let _data = (array!['0', '1', '2']).span();
    let data = (array![_data, _data, _data]).span();
    // Check if function call is successful
    match dispatcher.self_attest_batch(
        attestationId,
        schemaId,
        recipient,
        validUntil,
        data
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => panic_with_felt252(
            *data.at(0)
        )
    }
    // Check storage
    let metadata0 = AttestationMetadata {
        attesterSig: zero_signature(),
        attesterRevokeSig: zero_signature(),
        schemaId: *schemaId.at(0),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(0),
        validUntil: *validUntil.at(0),
        revoked: false
    };
    let metadata1 = AttestationMetadata {
        attesterSig: zero_signature(),
        attesterRevokeSig: zero_signature(),
        schemaId: *schemaId.at(1),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(1),
        validUntil: *validUntil.at(1),
        revoked: false
    };
    let metadata2 = AttestationMetadata {
        attesterSig: zero_signature(),
        attesterRevokeSig: zero_signature(),
        schemaId: *schemaId.at(2),
        attester: test_address(),
        notary: Zeroable::zero(),
        recipient: *recipient.at(2),
        validUntil: *validUntil.at(2),
        revoked: false
    };
    let (metadata0_, data0_) = dispatcher.get_onchain_attestation(
        *attestationId.at(0)
    ).unwrap();
    let (metadata1_, data1_) = dispatcher.get_onchain_attestation(
        *attestationId.at(1)
    ).unwrap();
    let (metadata2_, data2_) = dispatcher.get_onchain_attestation(
        *attestationId.at(2)
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
