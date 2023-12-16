#[starknet::contract]
mod SAS {
    mod interfaces;
    mod structs;
    mod felt252span;
    use zeroable::Zeroable;
    use starknet::{
        ContractAddress, 
        get_block_timestamp, 
        get_caller_address, 
        secp256_trait::Signature
    };
    use structs::{
        schema::Schema, 
        attestation::AttestationMetadata,
    };
    use interfaces::{
        versionable::IVersionable, 
        sas::{
            ISAS, 
            SASErrors,
            SASEvents::{
                Registered,
                Attested, 
                Revoked, 
                AttestedOffchain, 
                RevokedOffchain
            },
        }, 
        resolver::{
            ISASResolverDispatcher, 
            ISASResolverDispatcherTrait
        }
    };
    use felt252span::StoreFelt252Span;

    #[storage]
    struct Storage {
        schemas: LegacyMap::<felt252, Schema>,
        attestation_metadatas: LegacyMap::<felt252, AttestationMetadata>,
        attestation_datas: LegacyMap::<felt252, Span::<felt252>>,
        offchain_data_timestamps: LegacyMap::<felt252, u64>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Registered: Registered,
        Attested: Attested,
        Revoked: Revoked,
        AttestedOffchain: AttestedOffchain,
        RevokedOffchain: RevokedOffchain
    }

    #[abi(embed_v0)]
    impl SASVersion of IVersionable<ContractState> {
        fn version(self: @ContractState) -> felt252 {
            '1.0.0'
        }
    }

    #[abi(embed_v0)]
    impl SASImpl of ISAS<ContractState> {
        fn register(
            ref self: ContractState, 
            schema_id: felt252, 
            schema: felt252, 
            resolver: ContractAddress, 
            revocable: bool, 
            max_valid_for: u64,
            revert_if_resolver_failed: bool,
        ) {
            let current_schema = self.schemas.read(schema_id);
            assert(
                current_schema.schema.is_zero(), 
                SASErrors::SCHEMA_ID_EXISTS
            );
            let newSchema = Schema {
                schema,
                resolver,
                revocable,
                max_valid_for,
                revert_if_resolver_failed,
            };
            self.schemas.write(schema_id, newSchema);
            self.emit(
                Event::Registered(
                    Registered {
                        by: get_caller_address(),
                        schema_id: schema_id
                    }
                )
            );
        }

        fn attest(
            ref self: ContractState, 
            attestation_id: felt252, 
            schema_id: felt252, 
            recipient: ContractAddress, 
            valid_until: u64, 
            data: Span::<felt252>,
            resolver_fee_token: ContractAddress,
            resolver_fee_amount: u256,
        ) -> bool {
            self._validate_attest_input_or_throw(
                attestation_id, 
                schema_id, 
                valid_until,
            );
            self._unsafe_attest(
                attestation_id: attestation_id, 
                schema_id: schema_id,
                attester: get_caller_address(),
                recipient: recipient,
                valid_until: valid_until,
                revoked: false,
                data: data
            );
            self._call_receiver_resolver_if_defined(
                attestation_id, 
                schema_id, 
                false,
                resolver_fee_token,
                resolver_fee_amount,
            )
        }

        fn revoke(
            ref self: ContractState, 
            attestation_id: felt252, 
            resolver_fee_token: ContractAddress,
            resolver_fee_amount: u256,
        ) -> bool {
            self._validate_revoke_input_or_throw(
                attestation_id,
            );
            self._unsafe_revoke(attestation_id);
            self._call_receiver_resolver_if_defined(
                attestation_id, 
                self.attestation_metadatas.read(attestation_id).schema_id, 
                false,
                resolver_fee_token,
                resolver_fee_amount,
            )
        }

        fn attest_offchain(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            self._validate_offchain_attest_input_or_throw(attestation_id);
            self._unsafe_offchain_attest(attestation_id);
        }

        fn revoke_offchain(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            self._validate_offchain_revoke_input_or_throw(attestation_id);
            self._unsafe_offchain_revoke(attestation_id);
        }

        fn get_schema(
            self: @ContractState, 
            schema_id: felt252
        ) -> Schema {
            self.schemas.read(schema_id)
        }

        fn get_onchain_attestation(
            self: @ContractState, 
            attestation_id: felt252
        ) -> (AttestationMetadata, Span::<felt252>) {
            (
                self.attestation_metadatas.read(attestation_id), 
                self.attestation_datas.read(attestation_id)
            )
        }

        fn get_offchain_attestation_timestamp(
            self: @ContractState, 
            attestation_id: felt252
        ) -> u64 {
            self.offchain_data_timestamps.read(attestation_id)
        }
    }

    #[generate_trait]
    impl SASInternalFunctions of SASInternalFunctionsTrait {
        fn _validate_attest_input_or_throw(
            ref self: ContractState, 
            attestation_id: felt252, 
            schema_id: felt252, 
            valid_until: u64,
        ) {
            let attestation_metadata = self.attestation_metadatas.read(
                attestation_id
            );
            assert(
                attestation_metadata.attester.is_zero(), 
                SASErrors::ATTESTATION_ID_EXISTS
            );
            let schema = self.schemas.read(schema_id);
            assert(
                schema.schema.is_non_zero(), 
                SASErrors::SCHEMA_ID_DOES_NOT_EXIST
            );
            assert(
                schema.max_valid_for > valid_until - get_block_timestamp(), 
                SASErrors::ATTESTATION_INVALID_DURATION
            );
        }

        fn _unsafe_attest(
            ref self: ContractState, 
            attestation_id: felt252, 
            schema_id: felt252, 
            attester: ContractAddress, 
            recipient: ContractAddress, 
            valid_until: u64, 
            revoked: bool, 
            data: Span::<felt252>
        ) {
            let attester_revoke_sig = _zero_signature();
            let new_attestation_metadata = AttestationMetadata { 
                schema_id,
                attester,
                recipient,
                valid_until,
                revoked
             };
             self.attestation_metadatas.write(
                attestation_id, 
                new_attestation_metadata
            );
             self.attestation_datas.write(attestation_id, data);
             self.emit(
                Event::Attested(
                    Attested {
                        attester,
                        recipient,
                        attestation_id,
                        schema_id
                    }
                )
             );
        }

        fn _validate_revoke_input_or_throw(
            ref self: ContractState, 
            attestation_id: felt252,
        ) {
            let attestation_metadata = self.attestation_metadatas.read(
                attestation_id
            );
            assert(
                attestation_metadata.attester.is_non_zero(), 
                SASErrors::ATTESTATION_ID_DOES_NOT_EXIST
            );
            assert(
                !attestation_metadata.revoked, 
                SASErrors::ATTESTATION_ALREADY_REVOKED
            );
            assert(
                attestation_metadata.attester == get_caller_address(), 
                SASErrors::CALLER_UNAUTHORIZED
            );
            let schema = self.schemas.read(
                attestation_metadata.schema_id
            );
            assert(schema.revocable, SASErrors::SCHEMA_NOT_REVOCABLE);
        }

        fn _unsafe_revoke(
            ref self: ContractState, 
            attestation_id: felt252,
        ) {
            let mut attestation_metadata = self.attestation_metadatas.read(
                attestation_id
            );
            attestation_metadata.revoked = true;
            self.attestation_metadatas.write(
                attestation_id, 
                attestation_metadata
            );
            self.emit(
                Event::Revoked(
                    Revoked {
                        attester: attestation_metadata.attester,
                        recipient: attestation_metadata.recipient,
                        attestation_id: attestation_id,
                        schema_id: attestation_metadata.schema_id
                    }
                )
            );
        }

        fn _validate_offchain_attest_input_or_throw(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            let offchain_data_timestamp = self.offchain_data_timestamps.read(
                attestation_id
            );
            assert(
                offchain_data_timestamp.is_zero(), 
                SASErrors::ATTESTATION_ID_EXISTS
            );
        }

        fn _unsafe_offchain_attest(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            self.offchain_data_timestamps.write(
                attestation_id, 
                get_block_timestamp()
            );
            self.emit(
                Event::AttestedOffchain(
                    AttestedOffchain {
                        attester: get_caller_address(),
                        attestation_id: attestation_id,
                        timestamp: get_block_timestamp()
                    }
                )
             );
        }

        fn _validate_offchain_revoke_input_or_throw(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            let offchain_data_timestamp = self.offchain_data_timestamps.read(
                attestation_id
            );
            assert(
                offchain_data_timestamp.is_non_zero(), 
                SASErrors::ATTESTATION_ID_DOES_NOT_EXIST
            );
        }

        fn _unsafe_offchain_revoke(
            ref self: ContractState, 
            attestation_id: felt252
        ) {
            self.offchain_data_timestamps.write(attestation_id, 0);
            self.emit(
                Event::RevokedOffchain(
                    RevokedOffchain {
                        attester: get_caller_address(),
                        attestation_id: attestation_id,
                        timestamp: get_block_timestamp()
                    }
                )
             );
        }

        fn _call_receiver_resolver_if_defined(
            ref self: ContractState, 
            attestation_id: felt252, 
            schema_id: felt252, 
            is_revoked: bool,
            resolver_fee_token: ContractAddress,
            resolver_fee_amount: u256,
        ) -> bool {
            let schema = self.schemas.read(schema_id);
            let mut result = false;
            if schema.resolver.is_non_zero() {
                result = ISASResolverDispatcher { 
                    contract_address: schema.resolver 
                }.did_receive_attestation(
                    attestation_id, 
                    is_revoked, 
                    resolver_fee_token, 
                    resolver_fee_amount
                );
                if schema.revert_if_resolver_failed && !result {
                    panic_with_felt252(SASErrors::RESOLVER_RETURNED_FALSE);
                }
            }
            result
        }
    }

    fn _zero_signature() -> Signature {
        Signature { r: 0, s: 0, y_parity: false }
    }

}