#![no_main]

use libfuzzer_sys::fuzz_target;
use taema_attach::parse_op;

// The privileged helper's argument vector. Any input must validate to an
// `Op` or a `Refused` message; a panic, hang, or allocation blowup is a bug.
// An empty pid word is accepted here and refused downstream ("bad pid"),
// exactly like the Python fallback: parse and execution stay split.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let argv: Vec<String> = text.split('\0').take(8).map(str::to_string).collect();
    let _ = parse_op(&argv);
});
