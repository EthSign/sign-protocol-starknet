use starknet::ContractAddress;
use starknet::secp256_trait::Signature;

#[starknet::interface]
trait ISAS<TContractState> {
    fn self_attest(ref self: TContractState, attestationId: felt252, schemaId: felt252, validUntil: u64, data: Span::<felt252>);
    fn self_attest_batch(ref self: TContractState, attestationId: Span::<felt252>, schemaId: Span::<felt252>, validUntil: Array::<u64>, data: Span::<Span::<felt252>>);
    fn notary_attest(ref self: TContractState, attestationId: felt252, schemaId: felt252, attesterSig: Signature, attester: ContractAddress, validUntil: u64, data: Span::<felt252>);
}

mod SASErrors {
    const ATTESTATION_ID_EXISTS: felt252 = '10';
    const ATTESTATION_ID_DOES_NOT_EXIST: felt252 = '11';
    const ATTESTATION_INVALID_DURATION: felt252 = '12';
    const SCHEMA_ID_EXISTS: felt252 = '20';
    const SCHEMA_ID_DOES_NOT_EXIST: felt252 = '21';
}