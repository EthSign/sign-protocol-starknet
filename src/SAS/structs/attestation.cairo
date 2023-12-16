use starknet::{ContractAddress, secp256_trait::Signature};

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct AttestationMetadata {
    attester_sig: Signature,
    attester_revoke_sig: Signature,
    schema_id: felt252,
    attester: ContractAddress,
    notary: ContractAddress,
    resolver: ContractAddress,
    valid_until: u64,
    revoked: bool
}