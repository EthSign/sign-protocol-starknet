use starknet::ContractAddress;
use sign_protocol::sp::felt252span::StoreFelt252Span;

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store)]
struct Schema {
    registrant: ContractAddress,
    revocable: bool,
    data_location: u8,
    max_valid_for: u64,
    timestamp: u64,
    hook: ContractAddress,
    data: Span<felt252>,
}
