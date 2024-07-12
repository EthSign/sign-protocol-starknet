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
        model::{
            attestation::{Attestation, AttestationInternal, OffchainAttestation}, schema::Schema
        },
        util::{storefelt252span::StoreFelt252Span}
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
        attestation_registry: LegacyMap<u64, AttestationInternal>,
        attestation_data_registry: LegacyMap<u64, Span<felt252>>,
        offchain_attestation_registry: LegacyMap<felt252, OffchainAttestation>,
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
        self.attestation_counter.write(1);
    }

    #[abi(embed_v0)]
    impl Versionable of IVersionable<ContractState> {
        fn version(self: @ContractState) -> felt252 {
            '1.1.2'
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
                attestation.linked_attestation_id == 0
                    || self
                        .attestation_registry
                        .read(attestation.linked_attestation_id)
                        .attester == attestation
                        .attester,
                SPErrors::ATTESTATION_WRONG_ATTESTER
            );
            assert(
                !attestation.revoked && attestation.revoke_timestamp.is_zero(),
                SPErrors::ATTESTATION_ALREADY_REVOKED
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
            self
                .attestation_registry
                .write(
                    attestation_id,
                    AttestationInternal {
                        schema_id: attestation.schema_id,
                        linked_attestation_id: attestation.linked_attestation_id,
                        attest_timestamp: get_block_timestamp(),
                        revoke_timestamp: 0,
                        attester: attestation.attester,
                        valid_until: attestation.valid_until,
                        data_location: attestation.data_location,
                        revoked: false,
                        recipients: attestation.recipients
                    }
                );
            self.attestation_data_registry.write(attestation_id, attestation.data);
            self
                .emit(
                    Event::AttestationMade(
                        SPEvents::AttestationMade { attestation_id, indexing_key }
                    )
                );
            self
                ._call_hook(
                    true,
                    attestation.schema_id,
                    schema.hook,
                    attestation.attester,
                    attestation_id,
                    hook_fees_erc20_token,
                    hook_fees_erc20_amount,
                    extra_data
                );
            attestation_id
        }

        fn revoke(
            ref self: ContractState,
            attestation_id: u64,
            reason: felt252,
            hook_fees_erc20_token: ContractAddress,
            hook_fees_erc20_amount: u256,
            delegate_signature: Array<felt252>,
            extra_data: Span<felt252>,
        ) {
            self.pausable.assert_not_paused();
            let mut attestation = self.attestation_registry.read(attestation_id);
            assert(!attestation.revoked, SPErrors::ATTESTATION_ALREADY_REVOKED);
            let schema = self.schema_registry.read(attestation.schema_id);
            assert(schema.revocable, SPErrors::ATTESTATION_IRREVOCABLE);
            if delegate_signature.len() > 0 {
                self
                    ._check_delegation_signature(
                        attestation.attester,
                        self.get_delegated_revoke_hash(attestation_id, reason),
                        delegate_signature
                    );
            } else {
                assert(
                    attestation.attester == get_caller_address(),
                    SPErrors::ATTESTATION_WRONG_ATTESTER
                );
            }
            attestation.revoked = true;
            attestation.revoke_timestamp = get_block_timestamp();

            // Believe Need This to Ensure The Attestation is Updated 
            self
                .attestation_registry
                .write(
                    attestation_id,
                    AttestationInternal {
                        schema_id: attestation.schema_id,
                        linked_attestation_id: attestation.linked_attestation_id,
                        attest_timestamp: attestation.attest_timestamp,
                        revoke_timestamp: attestation.revoke_timestamp,
                        attester: attestation.attester,
                        valid_until: attestation.valid_until,
                        data_location: attestation.data_location,
                        revoked: attestation.revoked,
                        recipients: attestation.recipients
                    }
                );

            self
                .emit(
                    Event::AttestationRevoked(
                        SPEvents::AttestationRevoked { attestation_id, reason }
                    )
                );
            self
                ._call_hook(
                    false,
                    attestation.schema_id,
                    schema.hook,
                    attestation.attester,
                    attestation_id,
                    hook_fees_erc20_token,
                    hook_fees_erc20_amount,
                    extra_data
                );
        }

        fn attest_offchain(
            ref self: ContractState,
            offchain_attestation_id: felt252,
            delegate_attester: ContractAddress,
            delegate_signature: Array<felt252>,
        ) {
            self.pausable.assert_not_paused();
            let mut offchain_attestation = self
                .offchain_attestation_registry
                .read(offchain_attestation_id);
            assert(offchain_attestation.timestamp.is_zero(), SPErrors::OFFCHAIN_ATTESTATION_EXIST);
            let mut attester = get_caller_address();
            if delegate_signature.len() > 0 {
                self
                    ._check_delegation_signature(
                        delegate_attester,
                        self.get_delegated_offchain_attest_hash(offchain_attestation_id),
                        delegate_signature
                    );
                attester = delegate_attester;
            }
            offchain_attestation.timestamp = get_block_timestamp();
            offchain_attestation.attester = attester;
            self.offchain_attestation_registry.write(offchain_attestation_id, offchain_attestation);
            self
                .emit(
                    Event::OffchainAttestationMade(
                        SPEvents::OffchainAttestationMade { offchain_attestation_id }
                    )
                );
        }

        fn revoke_offchain(
            ref self: ContractState,
            offchain_attestation_id: felt252,
            reason: felt252,
            delegate_signature: Array<felt252>,
        ) {
            self.pausable.assert_not_paused();
            let mut offchain_attestation = self
                .offchain_attestation_registry
                .read(offchain_attestation_id);
            assert(
                offchain_attestation.timestamp.is_non_zero(),
                SPErrors::OFFCHAIN_ATTESTATION_NONEXISTENT
            );
            assert(
                offchain_attestation.timestamp > 1, SPErrors::OFFCHAIN_ATTESTATION_ALREADY_REVOKED
            );
            if delegate_signature.len() > 0 {
                self
                    ._check_delegation_signature(
                        offchain_attestation.attester,
                        self.get_delegated_offchain_revoke_hash(offchain_attestation_id, reason),
                        delegate_signature
                    );
            } else {
                assert(
                    offchain_attestation.attester == get_caller_address(),
                    SPErrors::ATTESTATION_WRONG_ATTESTER
                );
            }
            offchain_attestation.timestamp = 1;
            self.offchain_attestation_registry.write(offchain_attestation_id, offchain_attestation);
            self
                .emit(
                    Event::OffchainAttestationRevoked(
                        SPEvents::OffchainAttestationRevoked { offchain_attestation_id, reason }
                    )
                );
        }

        fn get_schema(self: @ContractState, schema_id: u64,) -> Schema {
            self.schema_registry.read(schema_id)
        }

        fn get_attestation(self: @ContractState, attestation_id: u64,) -> Attestation {
            let attestation = self.attestation_registry.read(attestation_id);
            Attestation {
                schema_id: attestation.schema_id,
                linked_attestation_id: attestation.linked_attestation_id,
                attest_timestamp: attestation.attest_timestamp,
                revoke_timestamp: attestation.revoke_timestamp,
                attester: attestation.attester,
                valid_until: attestation.valid_until,
                data_location: attestation.data_location,
                revoked: attestation.revoked,
                recipients: attestation.recipients,
                data: self.attestation_data_registry.read(attestation_id)
            }
        }

        fn get_offchain_attestation(
            self: @ContractState, offchain_attestation_id: felt252,
        ) -> OffchainAttestation {
            self.offchain_attestation_registry.read(offchain_attestation_id)
        }

        fn get_delegated_register_hash(self: @ContractState, schema: Schema,) -> felt252 {
            PoseidonTrait::new().update_with(schema).update_with('REGISTER').finalize()
        }

        fn get_delegated_attest_hash(self: @ContractState, attestation: Attestation,) -> felt252 {
            PoseidonTrait::new().update_with(attestation).update_with('ATTEST').finalize()
        }

        fn get_delegated_revoke_hash(
            self: @ContractState, attestation_id: u64, reason: felt252,
        ) -> felt252 {
            PoseidonTrait::new()
                .update_with('REVOKE')
                .update_with(attestation_id)
                .update_with(reason)
                .finalize()
        }

        fn get_delegated_offchain_attest_hash(
            self: @ContractState, offchain_attestation_id: felt252,
        ) -> felt252 {
            PoseidonTrait::new()
                .update_with('ATTEST_OFFCHAIN')
                .update_with(offchain_attestation_id)
                .finalize()
        }

        fn get_delegated_offchain_revoke_hash(
            self: @ContractState, offchain_attestation_id: felt252, reason: felt252,
        ) -> felt252 {
            PoseidonTrait::new()
                .update_with('REVOKE_OFFCHAIN')
                .update_with(offchain_attestation_id)
                .finalize()
        }

        fn schema_counter(self: @ContractState) -> u64 {
            self.schema_counter.read()
        }

        fn attestation_counter(self: @ContractState) -> u64 {
            self.attestation_counter.read()
        }
    }

    #[generate_trait]
    impl SPInternalImpl of SPInternalTrait {
        fn _call_hook(
            ref self: ContractState,
            is_attestation: bool,
            schema_id: u64,
            schema_hook: ContractAddress,
            attester: ContractAddress,
            attestation_id: u64,
            hook_fees_erc20_token: ContractAddress,
            hook_fees_erc20_amount: u256,
            extra_data: Span<felt252>,
        ) {
            if schema_hook.is_non_zero() {
                let hook = ISPHookDispatcher { contract_address: schema_hook };
                if is_attestation {
                    hook
                        .did_receive_attestation(
                            attester,
                            schema_id,
                            attestation_id,
                            hook_fees_erc20_token,
                            hook_fees_erc20_amount,
                            extra_data
                        );
                } else {
                    hook
                        .did_receive_revocation(
                            attester,
                            schema_id,
                            attestation_id,
                            hook_fees_erc20_token,
                            hook_fees_erc20_amount,
                            extra_data
                        );
                }
            }
        }

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
