#[starknet::contract]
mod MockHookContract {
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

    #[storage]
    struct Storage {
        attestation_counter: u64,
        revocation_counter: u64,
        balance: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct AttestationCounterEvent {
        attestation_counter: u64,
        balance: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct RevocationCounterEvent {
        revocation_counter: u64,
        balance: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AttestationCounter: AttestationCounterEvent,
        RevocationCounter: RevocationCounterEvent
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl SPHook of ISPHook<ContractState> {
        fn did_receive_attestation(
            ref self: ContractState,
            attester: ContractAddress,
            schema_id: u64,
            attestation_id: u64,
            hook_fees_erc20_token: ContractAddress,
            hook_fees_erc20_amount: u256,
            extra_data: Span<felt252>,
        ) {
            let _balance = self.balance.read() + hook_fees_erc20_amount;
            self.balance.write(_balance);
            let _counter = self.attestation_counter.read() + 1;
            self.attestation_counter.write(_counter);

            self
                .emit(
                    Event::AttestationCounter(
                        AttestationCounterEvent { attestation_counter: _counter, balance: _balance }
                    )
                );
        }

        fn did_receive_revocation(
            ref self: ContractState,
            attester: ContractAddress,
            schema_id: u64,
            attestation_id: u64,
            hook_fees_erc20_token: ContractAddress,
            hook_fees_erc20_amount: u256,
            extra_data: Span<felt252>,
        ) {
            let _balance = self.balance.read() + hook_fees_erc20_amount;
            self.balance.write(_balance);
            let _counter = self.revocation_counter.read() + 1;
            self.revocation_counter.write(_counter);

            self
                .emit(
                    Event::RevocationCounter(
                        RevocationCounterEvent { revocation_counter: _counter, balance: _balance }
                    )
                );
        }
    }

    // Getter Function
    fn attestation_counter(self: @ContractState) -> u64 {
        self.attestation_counter.read()
    }

    // Getter Function
    fn revocation_counter(self: @ContractState) -> u64 {
        self.revocation_counter.read()
    }
}
