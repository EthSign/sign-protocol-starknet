use starknet::ContractAddress;
use starknet::secp256_trait::Signature;

#[starknet::interface]
trait ISAS<TContractState> {
    // On-chain
    fn self_attest(ref self: TContractState, attestationId: felt252, schemaId: felt252, validUntil: u64, data: Span::<felt252>);
    fn self_attest_batch(ref self: TContractState, attestationId: Span::<felt252>, schemaId: Span::<felt252>, validUntil: Array::<u64>, data: Span::<Span::<felt252>>);
    fn notary_attest(ref self: TContractState, attestationId: felt252, schemaId: felt252, attesterSig: Signature, attester: ContractAddress, validUntil: u64, data: Span::<felt252>);
    fn notary_attest_batch(ref self: TContractState, attestationId: Span::<felt252>, schemaId: Span::<felt252>, attesterSig: Span::<Signature>, attester: Span::<ContractAddress>, validUntil: Span::<u64>, data: Span::<Span::<felt252>>);
    fn unattest(ref self: TContractState, attestationId: felt252, isCallerNotary: bool, attesterUnattestSig: Signature);
    fn unattest_batch(ref self: TContractState, attestationId: Span::<felt252>, isCallerNotary: Span::<bool>,  attesterUnattestSig:Span::<Signature>);
    // Off-chain
    fn attest_offchain(ref self: TContractState, attestationId: felt252);
    fn attest_offchain_batch(ref self: TContractState, attestationId: Span::<felt252>);
    fn unattest_offchain(ref self: TContractState, attestationId: felt252);
    fn unattest_offchain_batch(ref self: TContractState, attestationId: Span::<felt252>);
}

mod SASErrors {
    const CALLER_UNAUTHORIZED: felt252 = '00';
    const ATTESTATION_ID_EXISTS: felt252 = '10';
    const ATTESTATION_ID_DOES_NOT_EXIST: felt252 = '11';
    const ATTESTATION_INVALID_DURATION: felt252 = '12';
    const ATTESTATION_ALREADY_REVOKED: felt252 = '13';
    const SCHEMA_ID_EXISTS: felt252 = '20';
    const SCHEMA_ID_DOES_NOT_EXIST: felt252 = '21';
    const SCHEMA_NOT_REVOCABLE: felt252 = '22';
}