//! Redaction invariant: however the output is chunked, a secret never survives.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openvault::redact::Redactor;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (secret, rest) = data.split_at(4 + (data[0] as usize % 8).min(data.len() - 5));
    // The replacement text itself could spell the secret; exclude those bytes.
    if secret.len() < 4 || secret.iter().any(|b| b"[]REDACT:s".contains(b)) {
        return;
    }
    let (mut r, _) = Redactor::new(&[("s".to_string(), secret)]);
    let mut out = Vec::new();
    // Interleave the secret into the stream, chunked by bytes of `rest`.
    let mut stream = rest.to_vec();
    stream.extend_from_slice(secret);
    stream.extend_from_slice(rest);
    let mut i = 0;
    let mut k = 0;
    while i < stream.len() {
        let n = 1 + (rest.get(k).copied().unwrap_or(7) as usize % 13);
        let end = (i + n).min(stream.len());
        out.extend(r.push(&stream[i..end]));
        i = end;
        k += 1;
    }
    out.extend(r.finish());
    assert!(
        !out.windows(secret.len()).any(|w| w == secret),
        "secret survived redaction"
    );
});
