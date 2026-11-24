//! Streaming redaction of secret values from a child's output.
//!
//! Each secret is matched in several encodings — raw, base64 (standard and
//! URL-safe, at every byte alignment so it is caught inside longer blobs),
//! hex (lower/upper) and percent-encoding — and matches spanning read-chunk
//! boundaries are caught by holding back only the bytes that could still be the
//! start of a match. Ordinary output is never delayed.

use zeroize::Zeroize;

use crate::util;

/// Values shorter than this are not redacted (it would shred normal output).
pub const MIN_LEN: usize = 4;

pub struct Redactor {
    /// (pattern, replacement), longest pattern first.
    pats: Vec<(Vec<u8>, Vec<u8>)>,
    pending: Vec<u8>,
}

impl Drop for Redactor {
    fn drop(&mut self) {
        for (p, _) in &mut self.pats {
            p.zeroize();
        }
        self.pending.zeroize();
    }
}

/// All the encoded forms of `value` worth matching.
pub fn variants(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![value.to_vec()];
    if value.len() >= MIN_LEN {
        out.push(util::hex(value).into_bytes());
        out.push(util::hex(value).to_uppercase().into_bytes());
        let pct = percent_encode(value);
        if pct.as_slice() != value {
            out.push(pct);
        }
        for url_safe in [false, true] {
            // Whole-value encodings (incl. the trailing partial char and padding)...
            out.push(util::base64(value, url_safe, true).into_bytes());
            out.push(util::base64(value, url_safe, false).into_bytes());
            // ...and the alignment-independent core when embedded in a larger blob.
            for offset in 0..3usize {
                if let Some(v) = base64_core(value, offset, url_safe) {
                    out.push(v.into_bytes());
                }
            }
        }
    }
    out.retain(|v| v.len() >= MIN_LEN);
    out.sort();
    out.dedup();
    out
}

/// The base64 characters that depend only on `value` when it starts `offset`
/// bytes into a larger base64-encoded blob.
fn base64_core(value: &[u8], offset: usize, url_safe: bool) -> Option<String> {
    let mut buf = vec![0u8; offset];
    buf.extend_from_slice(value);
    let enc = util::base64(&buf, url_safe, false);
    let start_bit = offset * 8;
    let end_bit = (offset + value.len()) * 8;
    let first = start_bit.div_ceil(6);
    let last = end_bit / 6; // exclusive
    if last <= first + 3 {
        return None;
    }
    let s = enc.get(first..last)?;
    Some(s.to_string())
}

fn percent_encode(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

impl Redactor {
    /// `secrets`: (label, value). Returns the redactor and the labels skipped
    /// because their values are too short to redact safely.
    pub fn new(secrets: &[(String, &[u8])]) -> (Self, Vec<String>) {
        let mut pats = Vec::new();
        let mut skipped = Vec::new();
        for (label, value) in secrets {
            if value.len() < MIN_LEN {
                skipped.push(label.clone());
                continue;
            }
            let repl = format!("[REDACTED:{label}]").into_bytes();
            for v in variants(value) {
                pats.push((v, repl.clone()));
            }
        }
        pats.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        (
            Redactor {
                pats,
                pending: Vec::new(),
            },
            skipped,
        )
    }

    /// Feed a chunk; returns the bytes that are safe to emit now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    /// End of stream: emit everything that is left.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, eof: bool) -> Vec<u8> {
        let buf = std::mem::take(&mut self.pending);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'outer: while i < buf.len() {
            let rest = &buf[i..];
            if !eof {
                // Could a longer match still be completed by future bytes?
                for (p, _) in &self.pats {
                    if p.len() > rest.len() && p.starts_with(rest) {
                        self.pending = rest.to_vec();
                        break 'outer;
                    }
                }
            }
            for (p, r) in &self.pats {
                if rest.starts_with(p) {
                    out.extend_from_slice(r);
                    i += p.len();
                    continue 'outer;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        let mut buf = buf;
        buf.zeroize();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[(&str, &str)], chunks: &[&str]) -> String {
        let s: Vec<(String, &[u8])> = secrets
            .iter()
            .map(|(l, v)| (l.to_string(), v.as_bytes()))
            .collect();
        let (mut r, _) = Redactor::new(&s);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(r.push(c.as_bytes()));
        }
        out.extend(r.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn redacts_raw() {
        assert_eq!(
            run(&[("gh", "s3cr3tvalue")], &["token=s3cr3tvalue done"]),
            "token=[REDACTED:gh] done"
        );
    }

    #[test]
    fn redacts_across_chunk_boundaries_byte_by_byte() {
        let input = "a s3cr3tvalue b s3cr3tvalue";
        let chunks: Vec<String> = input.chars().map(|c| c.to_string()).collect();
        let refs: Vec<&str> = chunks.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            run(&[("gh", "s3cr3tvalue")], &refs),
            "a [REDACTED:gh] b [REDACTED:gh]"
        );
    }

    #[test]
    fn does_not_delay_unrelated_output() {
        let (mut r, _) = Redactor::new(&[("gh".into(), b"s3cr3tvalue".as_slice())]);
        assert_eq!(r.push(b"hello world\n"), b"hello world\n");
        // A possible prefix is held back...
        assert_eq!(r.push(b"x s3cr"), b"x ");
        // ...and released when it turns out not to be the secret.
        assert_eq!(r.push(b"ab\n"), b"s3crab\n");
    }

    #[test]
    fn redacts_encodings() {
        let secret = "p@ss w0rd/xyz";
        let b64 = util::base64(secret.as_bytes(), false, true);
        let b64url = util::base64(format!("ab{secret}").as_bytes(), true, false);
        let hex = util::hex(secret.as_bytes());
        let pct = "p%40ss%20w0rd%2Fxyz";
        for enc in [
            b64.as_str(),
            b64url.as_str(),
            hex.as_str(),
            &hex.to_uppercase(),
            pct,
        ] {
            let out = run(&[("pw", secret)], &[&format!("<<{enc}>>")]);
            assert!(out.contains("[REDACTED:pw]"), "{enc} not redacted: {out}");
            assert!(!out.contains(secret));
        }
    }

    #[test]
    fn base64_inside_larger_blob_any_alignment() {
        let secret = b"supersecretvalue";
        for pre in 0..3 {
            let mut blob = b"user:".to_vec();
            blob.extend(std::iter::repeat_n(b'x', pre));
            blob.extend_from_slice(secret);
            blob.extend_from_slice(b"@host");
            let enc = util::base64(&blob, false, true);
            let out = run(&[("s", "supersecretvalue")], &[&enc]);
            assert!(out.contains("[REDACTED:s]"), "offset {pre}: {out}");
        }
    }

    #[test]
    fn short_values_are_skipped_not_shredded() {
        let (_, skipped) = Redactor::new(&[("pin".into(), b"12".as_slice())]);
        assert_eq!(skipped, vec!["pin".to_string()]);
    }

    #[test]
    fn longest_match_wins() {
        assert_eq!(
            run(&[("a", "abcd"), ("b", "abcdefgh")], &["abcd", "efgh"]),
            "[REDACTED:b]"
        );
    }
}
