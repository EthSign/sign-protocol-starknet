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
        data_length: u32, 
        hook: ContractAddress, 
        revocable: bool, 
        max_valid_for: u64
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

    fn notary_attest(
        ref self: TContractState, 
        attestation_id: felt252, 
        schema_id: felt252, 
        attester_sig: Signature, 
        attester: ContractAddress, 
        recipient: ContractAddress, 
        valid_until: u64, 
        data: Span::<felt252>
    ) -> bool;

    fn revoke(
        ref self: TContractState, 
        attestation_id: felt252, 
        is_caller_notary: bool, 
        attester_revoke_sig: Signature
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
        notary: super::ContractAddress,
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
        notary: super::ContractAddress,
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