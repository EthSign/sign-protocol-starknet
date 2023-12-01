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