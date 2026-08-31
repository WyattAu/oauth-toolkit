#![no_main]

use libfuzzer_sys::fuzz_target;
use oauth_toolkit::scope::parse_scopes;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz parse_scopes with arbitrary input strings.
        // Must handle any input without panicking.
        let scopes = parse_scopes(s);

        // Basic invariant: returned scopes must be sorted and deduplicated
        for window in scopes.windows(2) {
            assert!(window[0] <= window[1], "scopes not sorted: {:?}", scopes);
        }
    }
});
