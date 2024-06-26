use starknet::ContractAddress;

#[starknet::interface]
trait ISPHook<TContractState> {
    fn did_receive_attestation(
        ref self: TContractState,
        attester: ContractAddress,
        schema_id: u64,
        attestation_id: u64,
        fee_token: ContractAddress,
        fee_amount: u256,
        extra_data: Span<felt252>,
    );
    fn did_receive_revocation(
        ref self: TContractState,
        attester: ContractAddress,
        schema_id: u64,
        attestation_id: u64,
        fee_token: ContractAddress,
        fee_amount: u256,
        extra_data: Span<felt252>,
    );
}
