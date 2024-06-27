use starknet::{ContractAddress, secp256_trait::Signature};
use sign_protocol::sp::util::{hashfelt252span::HashFelt252Span, storefelt252span::StoreFelt252Span};
use core::poseidon::PoseidonTrait;
use core::poseidon::poseidon_hash_span;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store, Hash)]
struct Attestation {
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
}

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store, Hash)]
struct OffchainAttestation {
    attester: ContractAddress,
    timestamp: u64,
}

