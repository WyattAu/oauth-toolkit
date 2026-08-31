#![no_main]

use libfuzzer_sys::fuzz_target;
use oauth_toolkit::pkce::verify_pkce;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz verify_pkce with arbitrary verifier, challenge, and method strings.
        // The function must handle any input without panicking.
        let _ = verify_pkce(s, s, s);
    }
});
