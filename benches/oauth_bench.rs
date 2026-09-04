use criterion::{Criterion, criterion_group, criterion_main};
use oauth_toolkit::crypto;
use oauth_toolkit::jwt;

fn bench_sha256_hex(c: &mut Criterion) {
    let data = "a".repeat(1024);
    c.bench_function("sha256_hex_1kb", |b| b.iter(|| crypto::sha256_hex(&data)));
}

fn bench_hmac_sign(c: &mut Criterion) {
    let key = "secret-key-for-hmac";
    let msg = "message-to-sign";
    c.bench_function("hmac_sign", |b| {
        b.iter(|| crypto::hmac_sha256_hex(key, msg))
    });
}

fn bench_jwt_roundtrip(c: &mut Criterion) {
    let secret = "a-very-long-secret-key-for-jwt-signing-ops";
    let claims = serde_json::json!({"sub": "user123", "exp": 9999999999i64, "iat": 1000});
    c.bench_function("jwt_roundtrip", |b| {
        b.iter(|| {
            let token = jwt::encode_hs256(&claims, secret).unwrap();
            let _decoded: serde_json::Value =
                jwt::decode_hs256(&token, secret, None, None).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_sha256_hex,
    bench_hmac_sign,
    bench_jwt_roundtrip
);
criterion_main!(benches);
