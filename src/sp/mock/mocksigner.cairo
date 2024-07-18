#[starknet::contract]
mod MockSigner {
    use core::{
        array::SpanTrait, zeroable::Zeroable, poseidon::PoseidonTrait,
        hash::{HashStateTrait, HashStateExTrait}
    };
    use starknet::{
        ContractAddress, event::EventEmitter, get_caller_address, get_contract_address,
        get_block_timestamp
    };
    use openzeppelin::{
        access::ownable::OwnableComponent, upgrades::upgradeable::UpgradeableComponent,
        account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait}, security::PausableComponent
    };
    use sign_protocol::sp::{
        interface::{
            sp::{ISP, SPErrors, SPEvents},
            sphook::{ISPHook, ISPHookDispatcher, ISPHookDispatcherTrait}, versionable::IVersionable
        },
        model::{
            attestation::{Attestation, AttestationInternal, OffchainAttestation}, schema::Schema
        },
        util::{storefelt252span::StoreFelt252Span}
    };

    #[starknet::interface]
    trait IMockSigner<TContractState> {
        fn is_valid_signature(
            self: @TContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252;

        fn sign(ref self: TContractState, hash: felt252);
    }

    #[storage]
    struct Storage {
        signing_registry: LegacyMap<felt252, u8>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockSigner of IMockSigner<ContractState> {
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self.signing_registry.read(hash) == 1 {
                starknet::VALIDATED
            } else {
                0
            }
        }

        fn sign(ref self: ContractState, hash: felt252) {
            self.signing_registry.write(hash, 1);
        }
    }
}
