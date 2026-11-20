# PATTERN_ADOPTION

Pattern relationships for oauth-toolkit, declared against the WyattAu
pattern canon per references/adoption-format.md. Rows claim what the
code shows; patterns with no relationship here are omitted.

| Pattern | Status | Evidence |
|---|---|---|
| P114 | adopted | src/jwt.rs:41 (each decoder pins its expected algorithm in Validation: HS256 at src/jwt.rs:41, ES256 at src/jwt.rs:84, RS256 at src/jwt.rs:123; the token header never chooses the algorithm) |
| P115 | partial | src/jwt.rs:1 (three signature families sit behind one call shape, so a migration adds a decoder instead of rewriting one) |
| P64 | adopted | tests/proptest.rs:9 (PKCE roundtrip, mismatch, and method-refusal properties) |
