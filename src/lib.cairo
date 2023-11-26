#[starknet::contract]
mod SAS {
    mod interfaces;
    mod structs;
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
        events::{
            Registered,
            Attested, 
            Revoked, 
            AttestedOffchain, 
            RevokedOffchain
        }
    };
    use interfaces::{
        versionable::IVersionable, 
        sas::{
            ISAS, 
            SASErrors
        }, 
        hook::{
            ISASReceiverHookDispatcher, 
            ISASReceiverHookDispatcherTrait
        }
    };
    use super::StoreFelt252Span;

    use debug::PrintTrait;

    #[storage]
    struct Storage {
        schemas: LegacyMap::<felt252, Schema>,
        attestationMetadatas: LegacyMap::<felt252, AttestationMetadata>,
        attestationDatas: LegacyMap::<felt252, Span::<felt252>>,
        offchainDataTimestamps: LegacyMap::<felt252, u64>,
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
            '0.1.0'
        }
    }

    #[abi(embed_v0)]
    impl SASImpl of ISAS<ContractState> {
        fn register(
            ref self: ContractState, 
            schemaId: felt252, 
            schema: felt252, 
            dataLength: u32, 
            hook: ContractAddress, 
            revocable: bool, 
            maxValidFor: u64
        ) {
            let currentSchema = self.schemas.read(schemaId);
            assert(
                currentSchema.schema.is_zero(), 
                SASErrors::SCHEMA_ID_EXISTS
            );
            let newSchema = Schema {
                schema,
                dataLength,
                hook,
                revocable,
                maxValidFor
            };
            self.schemas.write(schemaId, newSchema);
            self.emit(
                Event::Registered(
                    Registered {
                        by: get_caller_address(),
                        schemaId: schemaId
                    }
                )
            );
        }

        fn self_attest(
            ref self: ContractState, 
            attestationId: felt252, 
            schemaId: felt252, 
            recipient: ContractAddress, 
            validUntil: u64, 
            data: Span::<felt252>
        ) -> bool {
            self._validate_attest_input_or_throw(
                attestationId, 
                schemaId, 
                validUntil,
                data.len()
            );
            self._unsafe_attest(
                attestationId: attestationId, 
                attesterSig: _zero_signature(),
                schemaId: schemaId,
                attester: get_caller_address(),
                notary: Zeroable::zero(),
                recipient: recipient,
                validUntil: validUntil,
                revoked: false,
                data: data
            );
            self._call_receiver_hook_if_defined(attestationId, schemaId, false)
        }

        fn self_attest_batch(
            ref self: ContractState, 
            attestationId: Span::<felt252>, 
            schemaId: Span::<felt252>, 
            recipient: Span::<ContractAddress>, 
            validUntil: Span::<u64>, 
            data: Span::<Span::<felt252>>
        ) -> Span::<bool> {
            let mut i: u32 = 0;
            let length = attestationId.len();
            let mut resultArray = ArrayTrait::<bool>::new();
            loop {
                if i == length {
                    break;
                }
                self._validate_attest_input_or_throw(
                    *attestationId.at(i), 
                    *schemaId.at(i), 
                    *validUntil.at(i),
                    (*data.at(i)).len()
                );
                self._unsafe_attest(
                    attestationId: *attestationId.at(i), 
                    attesterSig: _zero_signature(),
                    schemaId: *schemaId.at(i),
                    attester: get_caller_address(),
                    notary: Zeroable::zero(),
                    recipient: *recipient.at(i),
                    validUntil: *validUntil.at(i),
                    revoked: false,
                    data: *data.at(i)
                );
                resultArray.append(
                    self._call_receiver_hook_if_defined(
                        *attestationId.at(i), 
                        *schemaId.at(i), 
                        false
                    )
                );
                i += 1;
            };
            resultArray.span()
        }

        fn notary_attest(
            ref self: ContractState, 
            attestationId: felt252, 
            schemaId: felt252, 
            attesterSig: Signature, 
            attester: ContractAddress, 
            recipient: ContractAddress, 
            validUntil: u64, 
            data: Span::<felt252>
        ) -> bool {
            self._validate_attest_input_or_throw(
                attestationId, 
                schemaId, 
                validUntil,
                data.len()
            );
            self._unsafe_attest(
                attestationId: attestationId, 
                attesterSig: attesterSig,
                schemaId: schemaId,
                attester: attester,
                notary: get_caller_address(),
                recipient: recipient,
                validUntil: validUntil,
                revoked: false,
                data: data
            );
            self._call_receiver_hook_if_defined(attestationId, schemaId, false)
        }

        fn notary_attest_batch(
            ref self: ContractState, 
            attestationId: Span::<felt252>, 
            schemaId: Span::<felt252>, 
            attesterSig: Span::<Signature>, 
            attester: Span::<ContractAddress>, 
            recipient: Span::<ContractAddress>, 
            validUntil: Span::<u64>, 
            data: Span::<Span::<felt252>>
        ) -> Span::<bool> {
            let mut i: u32 = 0;
            let length = attestationId.len();
            let mut resultArray = ArrayTrait::<bool>::new();
            loop {
                if i == length {
                    break;
                }
                self._validate_attest_input_or_throw(
                    *attestationId.at(i), 
                    *schemaId.at(i), 
                    *validUntil.at(i),
                    (*data.at(i)).len()
                );
                self._unsafe_attest(
                    attestationId: *attestationId.at(i), 
                    attesterSig: *attesterSig.at(i),
                    schemaId: *schemaId.at(i),
                    attester: *attester.at(i),
                    notary: get_caller_address(),
                    recipient: *recipient.at(i),
                    validUntil: *validUntil.at(i),
                    revoked: false,
                    data: *data.at(i)
                );
                resultArray.append(
                    self._call_receiver_hook_if_defined(
                        *attestationId.at(i), 
                        *schemaId.at(i), 
                        false
                    )
                );
                i += 1;
            };
            resultArray.span()
        }

        fn revoke(
            ref self: ContractState, 
            attestationId: felt252, 
            isCallerNotary: bool, 
            attesterRevokeSig: Signature
        ) -> bool {
            self._validate_revoke_input_or_throw(
                attestationId, 
                isCallerNotary
            );
            self._unsafe_revoke(attestationId, attesterRevokeSig);
            self._call_receiver_hook_if_defined(
                attestationId, 
                self.attestationMetadatas.read(attestationId).schemaId, 
                false
            )
        }

        fn revoke_batch(
            ref self: ContractState, 
            attestationId: Span::<felt252>, 
            isCallerNotary: Span::<bool>, 
            attesterRevokeSig: Span::<Signature>
        ) -> Span::<bool> {
            let mut i: u32 = 0;
            let length = attestationId.len();
            let mut resultArray = ArrayTrait::<bool>::new();
            loop {
                if i == length {
                    break;
                }
                self._validate_revoke_input_or_throw(
                    *attestationId.at(i), 
                    *isCallerNotary.at(i)
                );
                self._unsafe_revoke(
                    *attestationId.at(i), 
                    *attesterRevokeSig.at(i)
                );
                resultArray.append(
                    self._call_receiver_hook_if_defined(
                        *attestationId.at(i), 
                        self.attestationMetadatas.read(
                            *attestationId.at(i)
                        ).schemaId, 
                        true
                    )
                );
                i += 1;
            };
            resultArray.span()
        }

        fn attest_offchain(ref self: ContractState, attestationId: felt252) {
            self._validate_offchain_attest_input_or_throw(attestationId);
            self._unsafe_offchain_attest(attestationId);
        }

        fn attest_offchain_batch(
            ref self: ContractState, 
            attestationId: Span::<felt252>
        ) {
            let mut i: u32 = 0;
            let length = attestationId.len();
            loop {
                if i == length {
                    break;
                }
                self._validate_offchain_attest_input_or_throw(
                    *attestationId.at(i)
                );
                self._unsafe_offchain_attest(*attestationId.at(i));
                i += 1;
            };
        }

        fn revoke_offchain(ref self: ContractState, attestationId: felt252) {
            self._validate_offchain_revoke_input_or_throw(attestationId);
            self._unsafe_offchain_revoke(attestationId);
        }

        fn revoke_offchain_batch(
            ref self: ContractState, 
            attestationId: Span::<felt252>
        ) {
            let mut i: u32 = 0;
            let length = attestationId.len();
            loop {
                if i == length {
                    break;
                }
                self._validate_offchain_revoke_input_or_throw(
                    *attestationId.at(i)
                );
                self._unsafe_offchain_revoke(*attestationId.at(i));
                i += 1;
            };
        }

        fn get_schema(
            self: @ContractState, 
            schemaId: felt252
        ) -> Schema {
            self.schemas.read(schemaId)
        }

        fn get_onchain_attestation(
            self: @ContractState, 
            attestationId: felt252
        ) -> (AttestationMetadata, Span::<felt252>) {
            (
                self.attestationMetadatas.read(attestationId), 
                self.attestationDatas.read(attestationId)
            )
        }

        fn get_offchain_attestation_timestamp(
            self: @ContractState, 
            attestationId: felt252
        ) -> u64 {
            self.offchainDataTimestamps.read(attestationId)
        }
    }

    #[generate_trait]
    impl SASInternalFunctions of SASInternalFunctionsTrait {
        fn _validate_attest_input_or_throw(
            ref self: ContractState, 
            attestationId: felt252, 
            schemaId: felt252, 
            validUntil: u64,
            dataLength: u32
        ) {
            let attestationMetadata = self.attestationMetadatas.read(
                attestationId
            );
            assert(
                attestationMetadata.attester.is_zero(), 
                SASErrors::ATTESTATION_ID_EXISTS
            );
            let schema = self.schemas.read(schemaId);
            assert(
                schema.schema.is_non_zero(), 
                SASErrors::SCHEMA_ID_DOES_NOT_EXIST
            );
            assert(
                schema.maxValidFor > validUntil - get_block_timestamp(), 
                SASErrors::ATTESTATION_INVALID_DURATION
            );
            assert(
                dataLength == schema.dataLength,
                SASErrors::ATTESTATION_INVALID_DATA_LENGTH
            );
        }

        fn _unsafe_attest(
            ref self: ContractState, 
            attestationId: felt252, 
            attesterSig: Signature, 
            schemaId: felt252, 
            attester: ContractAddress, 
            notary: ContractAddress, 
            recipient: ContractAddress, 
            validUntil: u64, 
            revoked: bool, 
            data: Span::<felt252>
        ) {
            let attesterRevokeSig = _zero_signature();
            let newAttestationMetadata = AttestationMetadata { 
                attesterSig,
                attesterRevokeSig,
                schemaId,
                attester,
                notary,
                recipient,
                validUntil,
                revoked
             };
             self.attestationMetadatas.write(
                attestationId, 
                newAttestationMetadata
            );
             self.attestationDatas.write(attestationId, data);
             self.emit(
                Event::Attested(
                    Attested {
                        attester,
                        notary,
                        recipient,
                        attestationId,
                        schemaId
                    }
                )
             );
        }

        fn _validate_revoke_input_or_throw(
            ref self: ContractState, 
            attestationId: felt252, 
            isCallerNotary: bool
        ) {
            let attestationMetadata = self.attestationMetadatas.read(
                attestationId
            );
            assert(
                attestationMetadata.attester.is_non_zero(), 
                SASErrors::ATTESTATION_ID_DOES_NOT_EXIST
            );
            assert(
                !attestationMetadata.revoked, 
                SASErrors::ATTESTATION_ALREADY_REVOKED
            );
            if isCallerNotary {
                assert(
                    attestationMetadata.notary == get_caller_address(), 
                    SASErrors::CALLER_UNAUTHORIZED
                );
            } else {
                assert(
                    attestationMetadata.attester == get_caller_address(), 
                    SASErrors::CALLER_UNAUTHORIZED
                );
            }
            let schema = self.schemas.read(
                attestationMetadata.schemaId
            );
            assert(schema.revocable, SASErrors::SCHEMA_NOT_REVOCABLE);
        }

        fn _unsafe_revoke(
            ref self: ContractState, 
            attestationId: felt252, 
            attesterRevokeSig: Signature
        ) {
            let mut attestationMetadata = self.attestationMetadatas.read(
                attestationId
            );
            attestationMetadata.revoked = true;
            attestationMetadata.attesterRevokeSig = attesterRevokeSig;
            self.attestationMetadatas.write(
                attestationId, 
                attestationMetadata
            );
            self.emit(
                Event::Revoked(
                    Revoked {
                        attester: attestationMetadata.attester,
                        notary: attestationMetadata.notary,
                        recipient: attestationMetadata.recipient,
                        attestationId: attestationId,
                        schemaId: attestationMetadata.schemaId
                    }
                )
            );
        }

        fn _validate_offchain_attest_input_or_throw(
            ref self: ContractState, 
            attestationId: felt252
        ) {
            let offchainDataTimestamp = self.offchainDataTimestamps.read(
                attestationId
            );
            assert(
                offchainDataTimestamp.is_zero(), 
                SASErrors::ATTESTATION_ID_EXISTS
            );
        }

        fn _unsafe_offchain_attest(
            ref self: ContractState, 
            attestationId: felt252
        ) {
            self.offchainDataTimestamps.write(
                attestationId, 
                get_block_timestamp()
            );
            self.emit(
                Event::AttestedOffchain(
                    AttestedOffchain {
                        attester: get_caller_address(),
                        attestationId: attestationId,
                        timestamp: get_block_timestamp()
                    }
                )
             );
        }

        fn _validate_offchain_revoke_input_or_throw(
            ref self: ContractState, 
            attestationId: felt252
        ) {
            let offchainDataTimestamp = self.offchainDataTimestamps.read(
                attestationId
            );
            assert(
                offchainDataTimestamp.is_non_zero(), 
                SASErrors::ATTESTATION_ID_DOES_NOT_EXIST
            );
        }

        fn _unsafe_offchain_revoke(
            ref self: ContractState, 
            attestationId: felt252
        ) {
            self.offchainDataTimestamps.write(attestationId, 0);
            self.emit(
                Event::RevokedOffchain(
                    RevokedOffchain {
                        attester: get_caller_address(),
                        attestationId: attestationId,
                        timestamp: get_block_timestamp()
                    }
                )
             );
        }

        fn _call_receiver_hook_if_defined(
            ref self: ContractState, 
            attestationId: felt252, 
            schemaId: felt252, 
            isRevoked: bool
        ) -> bool {
            let schema = self.schemas.read(schemaId);
            let mut result = false;
            if schema.hook.is_non_zero() {
                result = ISASReceiverHookDispatcher { 
                    contract_address: schema.hook 
                }.didReceiveAttestation(attestationId, isRevoked)
            }
            result
        }
    }

    fn _zero_signature() -> Signature {
        Signature { r: 0, s: 0, y_parity: false }
    }

}

// ===== Implementing Span in storage =====
// Based on: 
// https://starknet-by-example.voyager.online/ch02/storing_arrays.html
use starknet::storage_access::Store;
use starknet::storage_access::StorageBaseAddress;
use starknet::syscalls::SyscallResult;

impl StoreFelt252Span of Store<Span<felt252>> {
    fn read(
        address_domain: u32, 
        base: StorageBaseAddress
    ) -> SyscallResult<Span<felt252>> {
        StoreFelt252Span::read_at_offset(address_domain, base, 0)
    }

    fn write(
        address_domain: u32, 
        base: StorageBaseAddress, 
        value: Span<felt252>
    ) -> SyscallResult<()> {
        StoreFelt252Span::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, 
        base: StorageBaseAddress, 
        mut offset: u8
    ) -> SyscallResult<Span<felt252>> {
        let mut arr: Array<felt252> = ArrayTrait::new();

        // Read the stored array's length.
        // If the length is superior to 255, the read will fail.
        let len: u8 = Store::<u8>::read_at_offset(address_domain, base, offset)
            .expect('Storage Span too large');
        offset += 1;

        // Sequentially read all stored elements and append them to the array.
        let exit = len + offset;
        loop {
            if offset >= exit {
                break;
            }

            let value = Store::<felt252>::read_at_offset(
                address_domain, 
                base, 
                offset
            ).unwrap();
            arr.append(value);
            offset += Store::<felt252>::size();
        };

        // Return the array.
        Result::Ok(arr.span())
    }

    fn write_at_offset(
        address_domain: u32, 
        base: StorageBaseAddress, 
        mut offset: u8, 
        mut value: Span<felt252>
    ) -> SyscallResult<()> {
        // // Store the length of the array in the first storage slot.
        let len: u8 = value.len().try_into().expect(
            'Storage - Span too large'
        );
        Store::<u8>::write_at_offset(address_domain, base, offset, len);
        offset += 1;

        // Store the array elements sequentially
        loop {
            match value.pop_front() {
                Option::Some(element) => {
                    Store::<felt252>::write_at_offset(
                        address_domain, 
                        base, 
                        offset, 
                        *element
                    );
                    offset += Store::<felt252>::size();
                },
                Option::None(_) => { break Result::Ok(()); }
            };
        }
    }

    fn size() -> u8 {
        255 * Store::<felt252>::size()
    }
}