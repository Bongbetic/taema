#![no_main]

use libfuzzer_sys::fuzz_target;

// The helper's rules file. Any input must parse to `Rules` or a `Refused`
// message; a panic, hang, or allocation blowup is a bug.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = taema_attach::parse_rules(text, "fuzz");
    }
});
