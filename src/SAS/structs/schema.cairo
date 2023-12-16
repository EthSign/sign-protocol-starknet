use starknet::ContractAddress;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct Schema {
    schema: felt252,
    hook: ContractAddress,
    revocable: bool,
    max_valid_for: u64,
    revert_if_hook_failed: bool,
}