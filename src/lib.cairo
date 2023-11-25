#[starknet::contract]
mod SAS {
    use core::array::ArrayTrait;
mod interfaces;
    mod structs;

    use starknet::ContractAddress;
    use zeroable::Zeroable;
    use starknet::get_block_timestamp;
    use structs::schema::Schema;
    use structs::attestation::AttestationMetadata;
    use interfaces::versionable::IVersionable;
    use interfaces::sas::ISAS;
    use interfaces::sas::SASErrors;
    use super::StoreFelt252Span;
    use starknet::secp256_trait::Signature;
    use starknet::get_caller_address;

    #[storage]
    struct Storage {
        schemas: LegacyMap::<felt252, Schema>,
        attestationMetadatas: LegacyMap::<felt252, AttestationMetadata>,
        attestationDatas: LegacyMap::<felt252, Span::<felt252>>,
        dataTimestamps: LegacyMap::<felt252, u64>,
    }

    #[abi(embed_v0)]
    impl SASVersion of IVersionable<ContractState> {
        fn version(self: @ContractState) -> felt252 {
            '0.0.1'
        }
    }

    #[abi(embed_v0)]
    impl SASImpl of ISAS<ContractState> {
        fn self_attest(ref self: ContractState, attestationId: felt252, schemaId: felt252, validUntil: u64, data: Span::<felt252>) {
            self._validate_attest_input_or_throw(attestationId, schemaId, validUntil);
            self._write_attestation_to_storage(
                attestationId: attestationId, 
                attesterSig: _zero_signature(),
                schemaId: schemaId,
                attester: get_caller_address(),
                notary: Zeroable::zero(),
                validUntil: validUntil,
                revoked: false,
                data: data
            );
        }

        fn self_attest_batch(ref self: ContractState, attestationId: Span::<felt252>, schemaId: Span::<felt252>, validUntil: Array::<u64>, data: Span::<Span::<felt252>>) {
            let mut i: u32 = 0;
            let length = attestationId.len();
            loop {
                if i == length {
                    break;
                }
                self._validate_attest_input_or_throw(*attestationId.at(i), *schemaId.at(i), *validUntil.at(i));
                self._write_attestation_to_storage(
                    attestationId: *attestationId.at(i), 
                    attesterSig: _zero_signature(),
                    schemaId: *schemaId.at(i),
                    attester: get_caller_address(),
                    notary: Zeroable::zero(),
                    validUntil: *validUntil.at(i),
                    revoked: false,
                    data: *data.at(i)
                );
            }
        }

        fn notary_attest(ref self: ContractState, attestationId: felt252, schemaId: felt252, attesterSig: Signature, attester: ContractAddress, validUntil: u64, data: Span::<felt252>) {
            self._validate_attest_input_or_throw(attestationId, schemaId, validUntil);
            self._write_attestation_to_storage(
                attestationId: attestationId, 
                attesterSig: attesterSig,
                schemaId: schemaId,
                attester: attester,
                notary: get_caller_address(),
                validUntil: validUntil,
                revoked: false,
                data: data
            );
        }


    }

    #[generate_trait]
    impl SASInternalFunctions of SASInternalFunctionsTrait {
        fn _validate_attest_input_or_throw(ref self: ContractState, attestationId: felt252, schemaId: felt252, validUntil: u64) {
            let currentAttestationMetadata = self.attestationMetadatas.read(attestationId);
            assert(currentAttestationMetadata.attester.is_zero(), SASErrors::ATTESTATION_ID_EXISTS);
            let schema = self.schemas.read(schemaId);
            assert(schema.schema.is_non_zero(), SASErrors::SCHEMA_ID_DOES_NOT_EXIST);
            assert(schema.maxValidFor < validUntil - get_block_timestamp(), SASErrors::ATTESTATION_INVALID_DURATION);
        }

        fn _write_attestation_to_storage(ref self: ContractState, attestationId: felt252, attesterSig: Signature, schemaId: felt252, attester: ContractAddress, notary: ContractAddress, validUntil: u64, revoked: bool, data: Span::<felt252>) {
            let newAttestationMetadata = AttestationMetadata { 
                attesterSig,
                schemaId,
                attester,
                notary,
                validUntil,
                revoked
             };
             self.attestationMetadatas.write(attestationId, newAttestationMetadata);
             self.attestationDatas.write(attestationId, data);
        }
    }

    fn _zero_signature() -> Signature {
        Signature { r: 0, s: 0, y_parity: false }
    }

}

// ===== Implementing arrays in storage =====
// Source: https://starknet-by-example.voyager.online/ch02/storing_arrays.html?highlight=storing#storing-arrays
use starknet::storage_access::Store;
use starknet::storage_access::StorageBaseAddress;
use starknet::syscalls::SyscallResult;

impl StoreFelt252Span of Store<Span<felt252>> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Span<felt252>> {
        StoreFelt252Span::read_at_offset(address_domain, base, 0)
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: Span<felt252>
    ) -> SyscallResult<()> {
        StoreFelt252Span::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8
    ) -> SyscallResult<Span<felt252>> {
        let mut arr: Array<felt252> = ArrayTrait::new();

        // Read the stored array's length. If the length is superior to 255, the read will fail.
        let len: u8 = Store::<u8>::read_at_offset(address_domain, base, offset)
            .expect('Storage Span too large');
        offset += 1;

        // Sequentially read all stored elements and append them to the array.
        let exit = len + offset;
        loop {
            if offset >= exit {
                break;
            }

            let value = Store::<felt252>::read_at_offset(address_domain, base, offset).unwrap();
            arr.append(value);
            offset += Store::<felt252>::size();
        };

        // Return the array.
        Result::Ok(arr.span())
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8, mut value: Span<felt252>
    ) -> SyscallResult<()> {
        // // Store the length of the array in the first storage slot.
        let len: u8 = value.len().try_into().expect('Storage - Span too large');
        Store::<u8>::write_at_offset(address_domain, base, offset, len);
        offset += 1;

        // Store the array elements sequentially
        loop {
            match value.pop_front() {
                Option::Some(element) => {
                    Store::<felt252>::write_at_offset(address_domain, base, offset, *element);
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