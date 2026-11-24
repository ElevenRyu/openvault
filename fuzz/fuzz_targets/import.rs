//! Every importer must survive arbitrary bytes without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openvault::import::{parse, to_records, Format};

const FORMATS: [Format; 6] = [
    Format::OnePux,
    Format::OnePasswordCsv,
    Format::Bitwarden,
    Format::AppleCsv,
    Format::LastPassCsv,
    Format::Dotenv,
];

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else { return };
    let f = FORMATS[*sel as usize % FORMATS.len()];
    if let Ok(items) = parse(f, body) {
        let _ = to_records(items, Some("fz"), f, "fuzz");
    }
});
