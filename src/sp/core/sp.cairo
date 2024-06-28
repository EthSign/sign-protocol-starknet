#[starknet::contract]
mod SP {
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
            sp::{ISP, SPErrors, SPEvents}, sphook::{ISPHookDispatcher, ISPHookDispatcherTrait},
            versionable::IVersionable
        },
        model::{attestation::{Attestation, OffchainAttestation}, schema::Schema}
    };


    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalOwnableImpl = OwnableComponent::InternalImpl<ContractState>;
    impl InternalUpgradeableImpl = UpgradeableComponent::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl InternalPausableImpl = PausableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
        ///
        schema_counter: u64,
        schema_registry: LegacyMap<u64, Schema>,
        attestation_counter: u64,
        attestation_registry: LegacyMap<u64, Attestation>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        ///
        SchemaRegistered: SPEvents::SchemaRegistered,
        AttestationMade: SPEvents::AttestationMade,
        AttestationRevoked: SPEvents::AttestationRevoked,
        OffchainAttestationMade: SPEvents::OffchainAttestationMade,
        OffchainAttestationRevoked: SPEvents::OffchainAttestationRevoked,
    }

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
        self.schema_counter.write(1);
    }

    #[abi(embed_v0)]
    impl Versionable of IVersionable<ContractState> {
        fn version(self: @ContractState) -> felt252 {
            '1.1.1'
        }
    }

    #[abi(embed_v0)]
    impl SP of ISP<ContractState> {
        fn register(
            ref self: ContractState, schema: Schema, delegate_signature: Array<felt252>,
        ) -> u64 {
            self.pausable.assert_not_paused();
            if delegate_signature.len() > 0 {
                self
                    ._check_delegation_signature(
                        schema.registrant,
                        self.get_delegated_register_hash(schema),
                        delegate_signature
                    );
            } else {
                assert(
                    schema.registrant == get_caller_address(), SPErrors::SCHEMA_WRONG_REGISTRANT
                );
            }
            let mut new_schema = schema.clone();
            new_schema.timestamp = get_block_timestamp();
            let schema_id = self.schema_counter.read();
            self.schema_counter.write(schema_id + 1);
            self.schema_registry.write(schema_id, schema);
            self.emit(Event::SchemaRegistered(SPEvents::SchemaRegistered { schema_id }));
            schema_id
        }

        fn attest(
            ref self: ContractState,
            attestation: Attestation,
            hook_fees_erc20_token: ContractAddress,
            hook_fees_erc20_amount: u256,
            indexing_key: felt252,
            delegate_signature: Array<felt252>,
            extra_data: Span<felt252>,
        ) -> u64 {
            self.pausable.assert_not_paused();
            if delegate_signature.len() > 0 {
                self
                    ._check_delegation_signature(
                        attestation.attester,
                        self.get_delegated_attest_hash(attestation),
                        delegate_signature
                    );
            } else {
                assert(
                    attestation.attester == get_caller_address(),
                    SPErrors::ATTESTATION_WRONG_ATTESTER
                );
            }
            let attestation_id = self.attestation_counter.read();
            self.attestation_counter.write(attestation_id + 1);
            assert(
                attestation.linked_attestation_id < attestation_id,
                SPErrors::ATTESTATION_NONEXISTENT
            );
            assert(
                attestation.linked_attestation_id > 0
                    && self
                        .attestation_registry
                        .read(attestation.linked_attestation_id)
                        .attester == attestation
                        .attester,
                SPErrors::ATTESTATION_WRONG_ATTESTER
            );
            assert(
                attestation.schema_id < self.schema_counter.read(), SPErrors::SCHEMA_NONEXISTENT
            );
            let schema = self.schema_registry.read(attestation.schema_id);
            assert(
                schema.max_valid_for == 0 || schema.max_valid_for >= attestation.valid_until
                    - get_block_timestamp(),
                SPErrors::ATTESTATION_INVALID_DURATION
            );
            self.attestation_registry.write(attestation_id, attestation);
            self
                .emit(
                    Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id, indexing_key }
                    )
                );
            if schema.hook.is_non_zero() {
                let hook = ISPHookDispatcher { contract_address: schema.hook };
                hook
                    .did_receive_attestation(
                        attestation.attester,
                        attestation.schema_id,
                        attestation_id,
                        hook_fees_erc20_token,
                        hook_fees_erc20_amount,
                        extra_data
                    );
            }
            attestation_id
        }

        fn get_schema(self: @ContractState, schema_id: u64,) -> Schema {
            self.schema_registry.read(schema_id)
        }

        fn get_attestation(self: @ContractState, attestation_id: u64,) -> Attestation {
            self.attestation_registry.read(attestation_id)
        }

        fn get_delegated_register_hash(self: @ContractState, schema: Schema,) -> felt252 {
            PoseidonTrait::new().update_with(schema).update_with('REGISTER').finalize()
        }

        fn get_delegated_attest_hash(self: @ContractState, attestation: Attestation,) -> felt252 {
            PoseidonTrait::new().update_with(attestation).update_with('ATTEST').finalize()
        }
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
