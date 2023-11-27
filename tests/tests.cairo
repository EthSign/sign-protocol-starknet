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

fn register_revocable_schema(
    dispatcher: ISASSafeDispatcher
) -> (felt252, Schema) {
    let schema_id = 'testSId_revocable';
    let schema = Schema {
        schema: 'test schema data',
        data_length: 3,
        hook: Zeroable::zero(),
        revocable: true,
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
    dispatcher.register(
        schema_id,
        schema.schema, 
        schema.data_length, 
        schema.hook, 
        schema.revocable, 
        schema.max_valid_for
    );
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
    dispatcher.self_attest(
        attestation_id,
        schema_id,
        recipient,
        valid_until,
        data
    );
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
    let data_with_wrong_length = (array![_data, _data]).span();
    // Check if function call is successful
    dispatcher.self_attest_batch(
        attestation_id,
        schema_id,
        recipient,
        valid_until,
        data
    );
    // Check storage
    let mut i: u32 = 0;
    loop {
        if (i == attestation_id.len()) {
            break;
        }
        let metadata = AttestationMetadata {
            attester_sig: zero_signature(),
            attester_revoke_sig: zero_signature(),
            schema_id: *schema_id.at(i),
            attester: test_address(),
            notary: Zeroable::zero(),
            recipient: *recipient.at(i),
            valid_until: *valid_until.at(i),
            revoked: false
        };
        let (metadata_, data_) = dispatcher.get_onchain_attestation(
            *attestation_id.at(i)
        ).unwrap();
        assert(
            compare_attestations_with_data(
                metadata, 
                *data.at(i), 
                metadata_, 
                data_
            ), 
            'Attestations should match'
        );
        i += 1;
    };
    // Check inconsistent input length
    let attestation_id1 = (array!['id3', 'id4', 'id5']).span();
    match dispatcher.self_attest_batch(
        attestation_id1,
        schema_id,
        recipient,
        valid_until,
        data_with_wrong_length
    ) {
        Result::Ok(_) => {},
        Result::Err(data) => assert(
            *data.at(0) == 'Index out of bounds', 
            ''
        )
    }
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
    dispatcher.notary_attest(
        attestation_id,
        schema_id,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    );
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

#[test]
fn notary_attest_batch_test() {
    let dispatcher = deploy_sas();
    let (_schema_id, schema) = register_basic_schema(dispatcher);
    let attestation_id = (array!['id0', 'id1', 'id2']).span();
    let attester_sig = (array![
        Signature { r: 1, s: 1, y_parity: true }, 
        Signature { r: 2, s: 2, y_parity: true }, 
        Signature { r: 3, s: 3, y_parity: true }
    ]).span();
    let attester0: ContractAddress = 123.try_into().unwrap();
    let attester = (array![
        attester0, 
        456.try_into().unwrap(), 
        789.try_into().unwrap()
    ]).span();
    let schema_id = (array![_schema_id, _schema_id, _schema_id]).span();
    let _recipient: ContractAddress = Zeroable::zero();
    let recipient = (array![_recipient, _recipient, _recipient]).span();
    let _valid_until = get_block_timestamp() + schema.max_valid_for - 1;
    let valid_until = (array![_valid_until, _valid_until, _valid_until]).span();
    let _data = (array!['0', '1', '2']).span();
    let data = (array![_data, _data, _data]).span();
    // Check if function call is successful
    dispatcher.notary_attest_batch(
        attestation_id,
        schema_id,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    );
    // Checking storage
        let mut i: u32 = 0;
    loop {
        if (i == attestation_id.len()) {
            break;
        }
        let metadata = AttestationMetadata {
            attester_sig: *attester_sig.at(i),
            attester_revoke_sig: zero_signature(),
            schema_id: *schema_id.at(i),
            attester: *attester.at(i),
            notary: test_address(),
            recipient: *recipient.at(i),
            valid_until: *valid_until.at(i),
            revoked: false
        };
        let (metadata_, data_) = dispatcher.get_onchain_attestation(
            *attestation_id.at(i)
        ).unwrap();
        assert(
            compare_attestations_with_data(
                metadata, 
                *data.at(i), 
                metadata_, 
                data_
            ), 
            'Attestations should match'
        );
        i += 1;
    };
}

#[test]
fn revoke_test() {
    // Revoking a notary attestation
    let dispatcher = deploy_sas();
    let (schema_id, schema) = register_revocable_schema(dispatcher);
    let attestation_id = 'testAId';
    let attester: ContractAddress = 123.try_into().unwrap();
    let attester_sig = Signature { r: 1, s: 1, y_parity: true };
    let attester_revoke_sig = Signature { r: 3, s: 3, y_parity: true };
    let recipient: ContractAddress = Zeroable::zero();
    let valid_until = get_block_timestamp();
    let data = (array!['0', '1', '22']).span();
    dispatcher.notary_attest(
        attestation_id,
        schema_id,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    );
    dispatcher.revoke(
        attestation_id,
        true,
        attester_revoke_sig
    );
    // Checking storage
    let (metadata_, _) = dispatcher.get_onchain_attestation(
        attestation_id
    ).unwrap();
    assert(
        metadata_.attester_revoke_sig == attester_revoke_sig &&
        metadata_.revoked, 
        'Data should match'
    );
    // Should panic if using irrevocable schema
    let attestation_id1 = 'testAId1';
    let (schema_id1, schema1) = register_basic_schema(dispatcher);
    dispatcher.notary_attest(
        attestation_id1,
        schema_id1,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    );
    match dispatcher.revoke(
        attestation_id1,
        true,
        attester_revoke_sig
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic'
        ),
        Result::Err(data) => assert(
            *data.at(0) == SASErrors::SCHEMA_NOT_REVOCABLE, 
            *data.at(0)
        )
    }
    // Revoking a self attestation
    let attestation_id2 = 'testAId2';
    dispatcher.self_attest(
        attestation_id2,
        schema_id,
        recipient,
        valid_until,
        data
    );
    dispatcher.revoke(
        attestation_id2,
        false,
        zero_signature()
    );
    // Should panic if revoke a revoked attestation
    match dispatcher.revoke(
        attestation_id2,
        false,
        zero_signature()
    ) {
        Result::Ok(_) => panic_with_felt252(
            'Should panic'
        ),
        Result::Err(data) => assert(
            *data.at(0) == SASErrors::ATTESTATION_ALREADY_REVOKED, 
            ''
        )
    }
}

#[test]
fn revoke_batch_test() {
    let dispatcher = deploy_sas();
    let (_schema_id, schema) = register_revocable_schema(dispatcher);
    let attestation_id = (array!['id0', 'id1', 'id2']).span();
    let attester_sig = (array![
        Signature { r: 1, s: 1, y_parity: true }, 
        Signature { r: 2, s: 2, y_parity: true }, 
        Signature { r: 3, s: 3, y_parity: true }
    ]).span();
    let attester0: ContractAddress = 123.try_into().unwrap();
    let attester = (array![
        attester0, 
        456.try_into().unwrap(), 
        789.try_into().unwrap()
    ]).span();
    let schema_id = (array![_schema_id, _schema_id, _schema_id]).span();
    let _recipient: ContractAddress = Zeroable::zero();
    let recipient = (array![_recipient, _recipient, _recipient]).span();
    let _valid_until = get_block_timestamp() + schema.max_valid_for - 1;
    let valid_until = (array![_valid_until, _valid_until, _valid_until]).span();
    let _data = (array!['0', '1', '2']).span();
    let data = (array![_data, _data, _data]).span();
    dispatcher.notary_attest_batch(
        attestation_id,
        schema_id,
        attester_sig,
        attester,
        recipient,
        valid_until,
        data
    );
    dispatcher.revoke_batch(
        attestation_id,
        (array![true, true, true]).span(),
        attester_sig
    );
}

#[test]
fn attest_offchain_test() {
    let dispatcher = deploy_sas();
    let attestation_id = 'testAId';
    dispatcher.attest_offchain(attestation_id);
    let timestamp = dispatcher.get_offchain_attestation_timestamp(
        attestation_id
    ).unwrap();
    assert(timestamp == get_block_timestamp(), 'Should match');
}

#[test]
fn attest_offchain_batch_test() {
    let dispatcher = deploy_sas();
    let attestation_id = (array!['id0', 'id1', 'id2']).span();
    dispatcher.attest_offchain_batch(attestation_id);
}

#[test]
fn revoke_offchain_test() {
    let dispatcher = deploy_sas();
    let attestation_id = 'testAId';
    dispatcher.attest_offchain(attestation_id);
    dispatcher.revoke_offchain(attestation_id);
    let timestamp = dispatcher.get_offchain_attestation_timestamp(
        attestation_id
    ).unwrap();
    assert(timestamp == 0, 'Should be 0');
    match dispatcher.revoke_offchain('adasdsa') {
        Result::Ok(_) => panic_with_felt252(
            'Should panic'
        ),
        Result::Err(data) => assert(
            *data.at(0) == SASErrors::ATTESTATION_ID_DOES_NOT_EXIST, 
            *data.at(0)
        )
    }
}

#[test]
fn revoke_offchain_batch_test() {
    let dispatcher = deploy_sas();
    let attestation_id = (array!['id0', 'id1', 'id2']).span();
    dispatcher.attest_offchain_batch(attestation_id);
    dispatcher.revoke_offchain_batch(attestation_id);
    let timestamp = dispatcher.get_offchain_attestation_timestamp(
        *attestation_id.at(2)
    ).unwrap();
    assert(timestamp == 0, 'Should be 0');
}