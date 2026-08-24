use crate::{ExtensionTurnInputV1, ExtensionTurnOutputV1};

/// Safe guest state machine implemented by a Rust WebAssembly extension.
pub trait GuestExtension: Default + 'static {
    /// Consume one engine input and return exactly one effect request, completion, or failure.
    fn turn(&mut self, input: ExtensionTurnInputV1) -> ExtensionTurnOutputV1;
}

/// Export the no-import `ScorchKit` ABI for one [`GuestExtension`] type.
///
/// The generated functions use safe thread-local buffers. The host writes only into a vector that
/// the guest has already resized, and Wasmi performs checked memory access in the worker.
#[macro_export]
macro_rules! export_extension {
    ($extension:ty) => {
        std::thread_local! {
            static SCORCHKIT_EXTENSION_STATE: std::cell::RefCell<$extension> =
                std::cell::RefCell::new(<$extension as std::default::Default>::default());
            static SCORCHKIT_EXTENSION_INPUT: std::cell::RefCell<std::vec::Vec<u8>> =
                const { std::cell::RefCell::new(std::vec::Vec::new()) };
            static SCORCHKIT_EXTENSION_OUTPUT: std::cell::RefCell<std::vec::Vec<u8>> =
                const { std::cell::RefCell::new(std::vec::Vec::new()) };
        }

        #[no_mangle]
        pub extern "C" fn scorchkit_abi_version() -> u32 {
            $crate::EXTENSION_ABI_V1
        }

        #[no_mangle]
        pub extern "C" fn scorchkit_reserve_input(length: u32) -> u32 {
            SCORCHKIT_EXTENSION_INPUT.with(|buffer| {
                let Ok(length) = usize::try_from(length) else { return 0 };
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                buffer.resize(length, 0);
                u32::try_from(buffer.as_mut_ptr() as usize).unwrap_or(0)
            })
        }

        #[no_mangle]
        pub extern "C" fn scorchkit_run(length: u32) -> u64 {
            let output = SCORCHKIT_EXTENSION_INPUT.with(|input| {
                let input = input.borrow();
                let Ok(length) = usize::try_from(length) else { return std::vec::Vec::new() };
                let Some(bytes) = input.get(..length) else { return std::vec::Vec::new() };
                let Ok(turn) = $crate::__private::serde_json::from_slice::<
                    $crate::ExtensionTurnInputV1,
                >(bytes) else {
                    return std::vec::Vec::new();
                };
                SCORCHKIT_EXTENSION_STATE.with(|state| {
                    $crate::__private::serde_json::to_vec(
                        &<$extension as $crate::GuestExtension>::turn(
                            &mut *state.borrow_mut(),
                            turn,
                        ),
                    )
                    .unwrap_or_default()
                })
            });
            SCORCHKIT_EXTENSION_OUTPUT.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                *buffer = output;
                let pointer = u32::try_from(buffer.as_ptr() as usize).unwrap_or(0);
                let length = u32::try_from(buffer.len()).unwrap_or(0);
                (u64::from(pointer) << 32) | u64::from(length)
            })
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExtensionFailureV1, ExtensionInvocationV1};

    #[derive(Default)]
    struct Fixture;

    impl GuestExtension for Fixture {
        fn turn(&mut self, input: ExtensionTurnInputV1) -> ExtensionTurnOutputV1 {
            let code = match input {
                ExtensionTurnInputV1::Start(_) => "started",
                ExtensionTurnInputV1::EffectResult(_) => "resumed",
            };
            ExtensionTurnOutputV1::Failure(ExtensionFailureV1 {
                code: code.to_string(),
                message: "fixture".to_string(),
            })
        }
    }

    #[test]
    fn guest_trait_is_a_turn_state_machine() {
        let mut guest = Fixture;
        let output = guest.turn(ExtensionTurnInputV1::Start(ExtensionInvocationV1::new(
            "invocation",
            "fixture",
            "http://127.0.0.1/",
        )));
        assert!(
            matches!(output, ExtensionTurnOutputV1::Failure(failure) if failure.code == "started")
        );
    }
}
