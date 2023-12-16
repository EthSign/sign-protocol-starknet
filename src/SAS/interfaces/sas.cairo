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
        schema_id: felt252, 
        schema: felt252, 
        resolver: ContractAddress, 
        revocable: bool, 
        max_valid_for: u64,
        revert_if_resolver_failed: bool,
    );
    // On-chain attestation
    fn self_attest(
        ref self: TContractState, 
        attestation_id: felt252,
        schema_id: felt252, 
        recipient: ContractAddress, 
        valid_until: u64, 
        data: Span::<felt252>
    ) -> bool;

    fn revoke(
        ref self: TContractState, 
        attestation_id: felt252,
    ) -> bool;

    // Off-chain attestation
    fn attest_offchain(
        ref self: TContractState, 
        attestation_id: felt252
    );

    fn revoke_offchain(
        ref self: TContractState, 
        attestation_id: felt252
    );

    // View
    fn get_schema(
        self: @TContractState, 
        schema_id: felt252
    ) -> Schema;

    fn get_onchain_attestation(
        self: @TContractState, 
        attestation_id: felt252
    ) -> (AttestationMetadata, Span::<felt252>);
    
    fn get_offchain_attestation_timestamp(
        self: @TContractState, 
        attestation_id: felt252
    ) -> u64;
}

mod SASEvents {
    #[derive(Drop, starknet::Event)]
    struct Registered {
        #[key]
        by: super::ContractAddress,
        #[key]
        schema_id: felt252
    }
    #[derive(Drop, starknet::Event)]
    struct Attested {
        #[key]
        attester: super::ContractAddress,
        #[key]
        recipient: super::ContractAddress,
        #[key]
        attestation_id: felt252,
        #[key]
        schema_id: felt252
    }
    #[derive(Drop, starknet::Event)]
    struct Revoked {
        #[key]
        attester: super::ContractAddress,
        #[key]
        recipient: super::ContractAddress,
        #[key]
        attestation_id: felt252,
        #[key]
        schema_id: felt252
    }
    #[derive(Drop, starknet::Event)]
    struct AttestedOffchain {
        #[key]
        attester: super::ContractAddress,
        #[key]
        attestation_id: felt252,
        #[key]
        timestamp: u64
    }
    #[derive(Drop, starknet::Event)]
    struct RevokedOffchain {
        #[key]
        attester: super::ContractAddress,
        #[key]
        attestation_id: felt252,
        #[key]
        timestamp: u64
    }
}

mod SASErrors {
    const CALLER_UNAUTHORIZED: felt252 = 'CALLER_UNAUTHORIZED';
    const ATTESTATION_ID_EXISTS: felt252 = 'ATTESTATION_ID_EXISTS';
    const ATTESTATION_ID_DOES_NOT_EXIST: felt252 = 'ATTESTATION_ID_DOES_NOT_EXIST';
    const ATTESTATION_INVALID_DURATION: felt252 = 'ATTESTATION_INVALID_DURATION';
    const ATTESTATION_ALREADY_REVOKED: felt252 = 'ATTESTATION_ALREADY_REVOKED';
    const SCHEMA_ID_EXISTS: felt252 = 'SCHEMA_ID_EXISTS';
    const SCHEMA_ID_DOES_NOT_EXIST: felt252 = 'SCHEMA_ID_DOES_NOT_EXIST';
    const SCHEMA_NOT_REVOCABLE: felt252 = 'SCHEMA_NOT_REVOCABLE';
    const RESOLVER_RETURNED_FALSE: felt252 = 'RESOLVER_RETURNED_FALSE';
}