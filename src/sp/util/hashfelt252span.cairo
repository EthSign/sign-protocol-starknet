use core::hash::{Hash, HashStateTrait, HashStateExTrait};

impl HashFelt252Span<S, +HashStateTrait<S>, +Drop<S>> of Hash<Span<felt252>, S> {
    fn update_state(state: S, value: Span<felt252>) -> S {
        let value_len = value.len();
        if value_len == 0 {
            return state;
        }
        let mut i = 1;
        let mut state_new = state.update(*value.at(0));
        loop {
            if i == value_len {
                break;
            }
            state_new = state_new.update_with(*value.at(i));
        };
        state_new
    }
}
