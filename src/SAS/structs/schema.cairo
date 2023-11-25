use starknet::ContractAddress;

#[derive(Drop, Serde, Copy, starknet::Store)]
struct Schema {
    schema: felt252,
    dataLength: u256,
    hook: ContractAddress,
    revocable: bool,
    maxValidFor: u64
}