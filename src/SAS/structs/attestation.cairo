use starknet::{ContractAddress, secp256_trait::Signature};
use starknet_attestation_service::SAS::StoreFelt252Span;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct AttestationMetadata {
    schema_id: felt252,
    attester: ContractAddress,
    valid_until: u64,
    revoked: bool,
    recipients: Span<felt252>,
}