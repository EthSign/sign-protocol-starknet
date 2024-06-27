#[starknet::contract]
mod SP {
    use core::array::SpanTrait;
    use starknet::{
        ContractAddress, event::EventEmitter, get_caller_address, get_contract_address,
        get_block_timestamp
    };
    use openzeppelin::{
        access::ownable::OwnableComponent, upgrades::upgradeable::UpgradeableComponent,
        account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait}
    };
    use sign_protocol::sp::{
        interface::{
            sp::{ISP, SPErrors, SPEvents}, sphook::{ISPHookDispatcher, ISPHookDispatcherTrait},
            versionable::IVersionable
        },
        model::{attestation::{Attestation, OffchainAttestation}, schema::Schema}
    };


    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalOwnableImpl = OwnableComponent::InternalImpl<ContractState>;
    impl InternalUpgradeableImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    ///
    }

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl Versionable of IVersionable<ContractState> {
        fn version(self: @ContractState) -> felt252 {
            '1.1.1'
        }
    }

    #[abi(embed_v0)]
    impl SP of ISP<ContractState> {
        fn register(ref self: ContractState, schema: Schema, delegate_signature: Array<felt252>,) {
            if delegate_signature.len() > 0 {}
        }

        fn get_delegated_register_hash(self: @ContractState, schema: Schema,) -> felt252 {}
    }

    #[generate_trait]
    impl SPInternalImpl of SPInternalTrait {
        fn _check_delegation_signature(
            self: @ContractState,
            delegate_attester: ContractAddress,
            hash: felt252,
            delegate_signature: Array<felt252>
        ) {
            let isrc6_account = ISRC6Dispatcher { contract_address: delegate_attester };
            assert(
                isrc6_account.is_valid_signature(hash, delegate_signature) == 'VALID',
                SPErrors::INVALID_DELEGATE_SIGNATURE
            );
        }
    }
}
