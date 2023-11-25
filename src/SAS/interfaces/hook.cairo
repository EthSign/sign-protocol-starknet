#[starknet::interface]
trait ISASHook<TContractState> {
    fn didReceiveAttestation(ref self: TContractState, attestationId: felt252) -> bool;
} 