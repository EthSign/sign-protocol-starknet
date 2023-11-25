#[starknet::interface]
trait ISASReceiverHook<TContractState> {
    fn didReceiveAttestation(ref self: TContractState, attestationId: felt252, isRevoked: bool) -> bool;
} 