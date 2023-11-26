use starknet::ContractAddress;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct Schema {
    schema: felt252,
    dataLength: u32,
    hook: ContractAddress,
    revocable: bool,
    maxValidFor: u64
}