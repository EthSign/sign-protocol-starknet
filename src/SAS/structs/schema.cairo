use starknet::ContractAddress;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct Schema {
    schema: felt252,
    data_length: u32,
    hook: ContractAddress,
    revocable: bool,
    max_valid_for: u64
}