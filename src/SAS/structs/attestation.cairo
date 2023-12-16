use starknet::{ContractAddress, secp256_trait::Signature};

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct AttestationMetadata {
    schema_id: felt252,
    attester: ContractAddress,
    recipient: ContractAddress,
    valid_until: u64,
    revoked: bool
}