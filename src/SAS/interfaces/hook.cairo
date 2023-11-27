#[starknet::interface]
trait ISASReceiverHook<TContractState> {
    fn did_receive_attestation(
        ref self: TContractState, 
        attestation_id: felt252, 
        is_revoked: bool
    ) -> bool;
} 