#![no_main]

use libfuzzer_sys::fuzz_target;

// The OOM restoration record. The first 20 bytes select the caller identity
// the record is checked against; the rest is the record text. Any input must
// validate to a record or a `Refused` message; a panic is a bug.
fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }
    let caller = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let pid = i64::from_le_bytes(data[4..12].try_into().unwrap());
    let start = i64::from_le_bytes(data[12..20].try_into().unwrap());
    if let Ok(text) = std::str::from_utf8(&data[20..]) {
        let _ = taema_attach::parse_oom_record(text, caller, pid, start);
    }
});
