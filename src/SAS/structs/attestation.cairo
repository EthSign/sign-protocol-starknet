use starknet::{ContractAddress, secp256_trait::Signature};

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct AttestationMetadata {
    attesterSig: Signature,
    attesterRevokeSig: Signature,
    schemaId: felt252,
    attester: ContractAddress,
    notary: ContractAddress,
    recipient: ContractAddress,
    validUntil: u64,
    revoked: bool
}