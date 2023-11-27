use starknet::ContractAddress;

#[derive(Drop, starknet::Event)]
struct Registered {
    #[key]
    by: ContractAddress,
    #[key]
    schema_id: felt252
}

#[derive(Drop, starknet::Event)]
struct Attested {
    #[key]
    attester: ContractAddress,
    #[key]
    notary: ContractAddress,
    #[key]
    recipient: ContractAddress,
    #[key]
    attestation_id: felt252,
    #[key]
    schema_id: felt252
}

#[derive(Drop, starknet::Event)]
struct Revoked {
    #[key]
    attester: ContractAddress,
    #[key]
    notary: ContractAddress,
    #[key]
    recipient: ContractAddress,
    #[key]
    attestation_id: felt252,
    #[key]
    schema_id: felt252
}

#[derive(Drop, starknet::Event)]
struct AttestedOffchain {
    #[key]
    attester: ContractAddress,
    #[key]
    attestation_id: felt252,
    #[key]
    timestamp: u64
}

#[derive(Drop, starknet::Event)]
struct RevokedOffchain {
    #[key]
    attester: ContractAddress,
    #[key]
    attestation_id: felt252,
    #[key]
    timestamp: u64
}