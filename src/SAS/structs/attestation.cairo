use starknet::ContractAddress;
use starknet::secp256_trait::Signature;

#[derive(Drop, Serde, Copy, starknet::Store)]
struct AttestationMetadata {
    attesterSig: Signature,
    attesterUnattestSig: Signature,
    schemaId: felt252,
    attester: ContractAddress,
    notary: ContractAddress,
    validUntil: u64,
    revoked: bool
}