use starknet::{ContractAddress, secp256_trait::Signature};
use starknet_attestation_service::SAS::structs::{
    attestation::AttestationMetadata,
    schema::Schema
};

#[starknet::interface]
trait ISAS<TContractState> {
    // Schema registration
    fn register(
        ref self: TContractState, 
        schemaId: felt252, 
        schema: felt252, 
        dataLength: u32, 
        hook: ContractAddress, 
        revocable: bool, 
        maxValidFor: u64
    );
    // On-chain attestation
    fn self_attest(
        ref self: TContractState, 
        attestationId: felt252, 
        schemaId: felt252, 
        recipient: ContractAddress, 
        validUntil: u64, 
        data: Span::<felt252>
    ) -> bool;
    fn self_attest_batch(
        ref self: TContractState, 
        attestationId: Span::<felt252>, 
        schemaId: Span::<felt252>, 
        recipient: Span::<ContractAddress>, 
        validUntil: Span::<u64>, 
        data: Span::<Span::<felt252>>
    ) -> Span::<bool>;
    fn notary_attest(
        ref self: TContractState, 
        attestationId: felt252, 
        schemaId: felt252, 
        attesterSig: Signature, 
        attester: ContractAddress, 
        recipient: ContractAddress, 
        validUntil: u64, 
        data: Span::<felt252>
    ) -> bool;
    fn notary_attest_batch(
        ref self: TContractState, 
        attestationId: Span::<felt252>, 
        schemaId: Span::<felt252>, 
        attesterSig: Span::<Signature>, 
        attester: Span::<ContractAddress>, 
        recipient: Span::<ContractAddress>, 
        validUntil: Span::<u64>, 
        data: Span::<Span::<felt252>>
    ) -> Span::<bool>;
    fn revoke(
        ref self: TContractState, 
        attestationId: felt252, 
        isCallerNotary: bool, 
        attesterRevokeSig: Signature
    ) -> bool;
    fn revoke_batch(
        ref self: TContractState, 
        attestationId: Span::<felt252>, 
        isCallerNotary: Span::<bool>, 
        attesterRevokeSig:Span::<Signature>
    ) -> Span::<bool>;
    // Off-chain attestation
    fn attest_offchain(
        ref self: TContractState, 
        attestationId: felt252
    );
    fn attest_offchain_batch(
        ref self: TContractState, 
        attestationId: Span::<felt252>
    );
    fn revoke_offchain(
        ref self: TContractState, 
        attestationId: felt252
    );
    fn revoke_offchain_batch(
        ref self: TContractState, 
        attestationId: Span::<felt252>
    );
    // View
    fn get_schema(
        self: @TContractState, 
        schemaId: felt252
    ) -> Schema;
    fn get_onchain_attestation(
        self: @TContractState, 
        attestationId: felt252
    ) -> (AttestationMetadata, Span::<felt252>);
    fn get_offchain_attestation_timestamp(
        self: @TContractState, 
        attestationId: felt252
    ) -> u64;
}

mod SASErrors {
    const CALLER_UNAUTHORIZED: felt252 = '00';
    const ATTESTATION_ID_EXISTS: felt252 = '10';
    const ATTESTATION_ID_DOES_NOT_EXIST: felt252 = '11';
    const ATTESTATION_INVALID_DURATION: felt252 = '12';
    const ATTESTATION_ALREADY_REVOKED: felt252 = '13';
    const ATTESTATION_INVALID_DATA_LENGTH: felt252 = '14';
    const SCHEMA_ID_EXISTS: felt252 = '20';
    const SCHEMA_ID_DOES_NOT_EXIST: felt252 = '21';
    const SCHEMA_NOT_REVOCABLE: felt252 = '22';
}