use starknet::ContractAddress;
use sign_protocol::sp::util::{hashfelt252span::HashFelt252Span, storefelt252span::StoreFelt252Span};

#[derive(PartialEq, Drop, Serde, Copy, starknet::Store, Hash)]
struct Schema {
    registrant: ContractAddress,
    revocable: bool,
    data_location: u8,
    max_valid_for: u64,
    timestamp: u64,
    hook: ContractAddress,
    data: Span<felt252>,
}
