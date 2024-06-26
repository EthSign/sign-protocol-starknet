use starknet::{ContractAddress, secp256_trait::Signature};
use sign_protocol::sp::model::{attestation::{Attestation, OffchainAttestation}, schema::Schema};

#[starknet::interface]
trait ISP<TContractState> {
    fn register(ref self: TContractState, schema: Schema, delegate_signature: Span<felt252>,);

    fn attest(
        ref self: TContractState,
        attestation: Attestation,
        hook_fees_erc20_token: ContractAddress,
        hook_fees_erc20_amount: u256,
        indexing_key: felt252,
        delegate_signature: Span<felt252>,
        extra_data: Span<felt252>,
    ) -> u64;

    fn revoke(
        ref self: TContractState,
        attestation_id: u64,
        reason: felt252,
        hook_fees_erc20_token: ContractAddress,
        hook_fees_erc20_amount: u256,
        delegate_signature: Span<felt252>,
        extra_data: Span<felt252>,
    );

    fn attest_offchain(
        ref self: TContractState,
        offchain_attestation_id: felt252,
        delegate_attester: ContractAddress,
        delegate_signature: Span<felt252>,
    );

    fn revoke_offchain(
        ref self: TContractState,
        offchain_attestation_id: felt252,
        reason: felt252,
        delegate_signature: Span<felt252>,
    );

    fn get_schema(self: @TContractState, schema_id: felt252,) -> Schema;

    fn get_attestation(self: @TContractState, attestation_id: felt252,) -> Attestation;

    fn get_offchain_attestation(
        self: @TContractState, offchain_attestation_id: felt252,
    ) -> OffchainAttestation;

    fn get_delegated_register_hash(self: @TContractState, schema: Schema,) -> felt252;

    fn get_delegated_attest_hash(self: @TContractState, attestation: Attestation,) -> felt252;

    fn get_delegated_offchain_attest_hash(
        self: @TContractState, offchain_attestation_id: felt252,
    ) -> felt252;

    fn get_delegated_revoke_hash(
        self: @TContractState, attestation_id: u64, reason: felt252,
    ) -> felt252;

    fn get_delegated_offchain_revoke_hash(
        self: @TContractState, offchain_attestation_id: felt252, reason: felt252,
    ) -> felt252;

    fn schema_counter(self: @TContractState) -> u64;

    fn attestation_counter(self: @TContractState) -> u64;
}

mod SPEvents {
    #[derive(Drop, starknet::Event)]
    struct SchemaRegistered {
        schema_id: felt252,
    }
    #[derive(Drop, starknet::Event)]
    struct AttestationMade {
        attestation_id: u64,
        indexing_key: felt252,
    }
    #[derive(Drop, starknet::Event)]
    struct AttestationRevoked {
        attestation_id: u64,
        reason: felt252,
    }
    #[derive(Drop, starknet::Event)]
    struct OffchainAttestationMade {
        attestation_id: felt252,
    }
    #[derive(Drop, starknet::Event)]
    struct OffchainAttestationRevoked {
        attestation_id: felt252,
        reason: felt252,
    }
}

mod SPErrors {
    const PAUSED: felt252 = 'PAUSED';
    const SCHEMA_NONEXISTENT: felt252 = 'SCHEMA_NONEXISTENT';
    const SCHEMA_WRONG_REGISTRANT: felt252 = 'SCHEMA_WRONG_REGISTRANT';
    const ATTESTATION_IRREVOCABLE: felt252 = 'ATTESTATION_IRREVOCABLE';
    const ATTESTATION_NONEXISTENT: felt252 = 'ATTESTATION_NONEXISTENT';
    const ATTESTATION_INVALID_DURATION: felt252 = 'ATTESTATION_INVALID_DURATION';
    const ATTESTATION_ALREADY_REVOKED: felt252 = 'ATTESTATION_ALREADY_REVOKED';
    const ATTESTATION_WRONG_ATTESTER: felt252 = 'ATTESTATION_WRONG_ATTESTER';
    const OFFCHAIN_ATTESTATION_EXIST: felt252 = 'OC_ATTESTATION_EXIST';
    const OFFCHAIN_ATTESTATION_NONEXISTENT: felt252 = 'OC_ATTESTATION_NONEXISTENT';
    const OFFCHAIN_ATTESTATION_ALREADY_REVOKED: felt252 = 'OC_ATTESTATION_ALREADY_REVOKED';
    const INVALID_DELEGATE_SIGNATURE: felt252 = 'INVALID_DELEGATE_SIGNATURE';
}
