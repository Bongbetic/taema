//! taema-fast: the multi-call fast client for shell integration.
//
// ```text
// taema-fast done SHELLPID TAG STATUS [WORD]   a command line ended
// taema-fast kill SHELLPID [WORD]              a kill/taema line ended
// taema-fast ask SHELLPID                      show the pending question, read one key
// taema-fast prompt                            print the cached prompt segment
// ```
//
// Faithful port of `libexec/taema-hook` (done/kill/ask) and the `taema prompt`
// fast path: identical command lines, identical output, IPC v2. It never
// fails loudly: any error exits 0, exactly like the Python versions.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_millis(300);
const ASK_BUDGET: Duration = Duration::from_millis(1500);
const KEY_TIMEOUT: Duration = Duration::from_secs(15);
const COLS: usize = 80;
const KILL_WORDS: [&str; 4] = ["kill", "pkill", "killall", "taema"];

// ---- text -----------------------------------------------------------------

/// Printable text: control and bidi characters stripped, length capped at
/// `n` characters (mirrors the Python `clean`).
fn clean(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| {
            let v = *c as u32;
            !((0x00..=0x1f).contains(&v)
                || (0x7f..=0x9f).contains(&v)
                || (0x200b..=0x200f).contains(&v)
                || (0x2028..=0x202f).contains(&v)
                || (0x2066..=0x2069).contains(&v)
                || v == 0xfeff)
        })
        .take(n)
        .collect()
}

fn is_word_punct(c: char) -> bool {
    // [\w!"'&.,?] with \w as ASCII word chars (mirrors CPython's pattern
    // for the inputs the hook formats; see format tests).
    c.is_ascii_alphanumeric() || c == '_' || "!\"'&.,?".contains(c)
}

fn is_letter(c: char) -> bool {
    // [^\d\W]: a word char that is not a decimal digit.
    (c.is_alphabetic() || c == '_') && !c.is_numeric()
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

// ---- textwrap port --------------------------------------------------------
// Faithful port of CPython's textwrap for fill(width, initial="", subsequent,
// drop/expand/replace whitespace, break long words and hyphens, fix sentence
// endings). Only the option combination the hook uses is supported.

fn munge_whitespace(text: &str) -> String {
    // expand tabs to 8, then map every other whitespace char to a space.
    let mut out = String::with_capacity(text.len());
    let mut col = 0usize;
    for c in text.chars() {
        if c == '\t' {
            let next = (col / 8 + 1) * 8;
            for _ in col..next {
                out.push(' ');
            }
            col = next;
        } else if c == '\n' || c == '\r' || c == '\x0b' || c == '\x0c' || c == ' ' {
            out.push(' ');
            col += 1;
        } else {
            out.push(c);
            col += 1;
        }
    }
    out
}

fn is_em_dash_at(chars: &[char], i: usize) -> bool {
    // (?<=wp) -{2,} (?=\w): dashes at i with word punct before, word char after.
    if i == 0 || !is_word_punct(chars[i - 1]) {
        return false;
    }
    let mut j = i;
    while j < chars.len() && chars[j] == '-' {
        j += 1;
    }
    if j - i < 2 {
        return false;
    }
    matches!(chars.get(j), Some(c) if c.is_alphanumeric() || *c == '_')
}

fn hyphen_break_at(chars: &[char], i: usize) -> bool {
    // Break after the '-' at i iff the CPython wordsep conditions hold:
    // (letter,letter,'-') or (letter,'-',letter,'-') behind, letter ahead.
    if chars.get(i) != Some(&'-') {
        return false;
    }
    let behind_a = i >= 2 && is_letter(chars[i - 2]) && is_letter(chars[i - 1]);
    let behind_b =
        i >= 3 && is_letter(chars[i - 3]) && chars[i - 2] == '-' && is_letter(chars[i - 1]);
    if !(behind_a || behind_b) {
        return false;
    }
    let ahead = matches!(chars.get(i + 1), Some(c) if is_letter(*c));
    if !ahead {
        return false;
    }
    // (?= lt -? lt)
    if let Some(d) = chars.get(i + 2) {
        if *d == '-' {
            return matches!(chars.get(i + 3), Some(e) if is_letter(*e));
        }
    }
    true
}

fn split_chunks(text: &str) -> Vec<String> {
    // Equivalent of wordsep_re.split with break_on_hyphens=True, empties out.
    let chars: Vec<char> = text.chars().collect();
    let mut chunks: Vec<String> = Vec::new();
    let mut i = 0;
    let n = chars.len();
    while i < n {
        if is_space(chars[i]) {
            let mut j = i;
            while j < n && is_space(chars[j]) {
                j += 1;
            }
            chunks.push(chars[i..j].iter().collect());
            i = j;
            continue;
        }
        if chars[i] == '-' && is_em_dash_at(&chars, i) {
            let mut j = i;
            while j < n && chars[j] == '-' {
                j += 1;
            }
            chunks.push(chars[i..j].iter().collect());
            i = j;
            continue;
        }
        // a word: consume non-space chars, stopping at hyphen breaks,
        // whitespace, or an em-dash opening.
        let mut j = i;
        while j < n && !is_space(chars[j]) {
            if chars[j] == '-' && is_em_dash_at(&chars, j) {
                break;
            }
            j += 1;
            if chars.get(j.saturating_sub(1)) == Some(&'-') && hyphen_break_at(&chars, j - 1) {
                break;
            }
        }
        chunks.push(chars[i..j].iter().collect());
        i = j;
    }
    chunks.into_iter().filter(|c| !c.is_empty()).collect()
}

fn wrap_chunks(mut chunks: Vec<String>, width: usize, subsequent_indent: &str) -> Vec<String> {
    // Port of TextWrapper._wrap_chunks with the hook's options: initial
    // indent "", subsequent indent as given, drop whitespace, break long
    // words and hyphens, no sentence fixing, no max lines.
    let mut lines: Vec<String> = Vec::new();
    chunks.reverse();
    while !chunks.is_empty() {
        let indent = if lines.is_empty() {
            ""
        } else {
            subsequent_indent
        };
        let indent_len = indent.chars().count();
        let line_width = width.saturating_sub(indent_len);
        if let Some(last) = chunks.last() {
            if last.trim().is_empty() && !lines.is_empty() {
                chunks.pop();
            }
        }
        let mut cur_line: Vec<String> = Vec::new();
        let mut cur_len = 0usize;
        while let Some(last) = chunks.last() {
            let l = last.chars().count();
            if cur_len + l <= line_width {
                let c = chunks.pop().unwrap();
                cur_len += l;
                cur_line.push(c);
            } else {
                break;
            }
        }
        if let Some(last) = chunks.last() {
            if last.chars().count() > line_width {
                handle_long_word(&mut chunks, &mut cur_line, &mut cur_len, line_width);
            }
        }
        if let Some(last) = cur_line.last() {
            if last.trim().is_empty() {
                cur_line.pop();
            }
        }
        if !cur_line.is_empty() {
            let mut line = String::from(indent);
            for c in &cur_line {
                line.push_str(c);
            }
            lines.push(line);
        }
    }
    lines
}

fn handle_long_word(
    chunks: &mut Vec<String>,
    cur_line: &mut Vec<String>,
    cur_len: &mut usize,
    width: usize,
) {
    let space_left = if width < 1 {
        1
    } else {
        width.saturating_sub(*cur_len)
    };
    if space_left > 0 {
        let chunk = chunks.last().cloned().unwrap_or_default();
        let chars: Vec<char> = chunk.chars().collect();
        let mut end = space_left.min(chars.len());
        if chars.len() > space_left {
            // break after the last hyphen that fits, if non-hyphens precede it
            let lim = space_left.min(chars.len());
            if let Some(hyphen) = chars[..lim].iter().rposition(|c| *c == '-') {
                if hyphen > 0 && chars[..hyphen].iter().any(|c| *c != '-') {
                    end = hyphen + 1;
                }
            }
        }
        let head: String = chars[..end].iter().collect();
        let tail: String = chars[end..].iter().collect();
        cur_line.push(head.clone());
        *cur_len += head.chars().count();
        *chunks.last_mut().unwrap() = tail;
    } else if cur_line.is_empty() {
        let c = chunks.pop().unwrap();
        *cur_len += c.chars().count();
        cur_line.push(c);
    }
}

/// Equivalent of `textwrap.fill(text, width=COLS-2,
/// subsequent_indent=indent, break_long_words=True)`.
fn fill(text: &str, indent: &str) -> String {
    wrap_chunks(split_chunks(&munge_whitespace(text)), COLS - 2, indent).join("\n")
}

// ---- the question ---------------------------------------------------------
// Faithful port of the question rendering in `libexec/taema-hook`:
// format_question, map_key, menu_choice, confirmation.

/// Python str() of a JSON value: missing callers pass their own default.
fn pystr(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(b)) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => String::new(),
    }
}

fn pystr_key(obj: &Value, key: &str, default: &str) -> String {
    match obj.get(key) {
        None => default.to_string(),
        Some(v) => pystr(Some(v)),
    }
}

/// Python int() of a JSON number for counts: ints (and bools) only.
fn count_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        _ => None,
    }
}

/// Equivalent of `format_question(q)`: the question as wrapped text lines.
/// Deliberate deviation: malformed question shapes (missing keys, wrong
/// types) render with defaults instead of raising; the hook would exit 0
/// with a partial transcript. Well-formed daemon output is identical.
fn format_question(q: &Value) -> Vec<String> {
    let cands = q.get("candidates").and_then(|v| v.as_array());
    let empty: Vec<Value> = Vec::new();
    let cands = cands.unwrap_or(&empty);
    let left = q.get("leftovers").and_then(|v| v.as_array());
    let left = left.unwrap_or(&empty);
    let first = cands
        .first()
        .map(|c| clean(&pystr(Some(c.get("label").unwrap_or(&Value::Null))), 48))
        .unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    if q.get("kind").and_then(|v| v.as_str()) == Some("closed") {
        let comm = left
            .first()
            .map(|l| clean(&pystr_key(l, "comm", "?"), 48))
            .unwrap_or_else(|| "?".to_string());
        lines.push(format!(
            "tæma: `{comm}` was closed. Was it part of {}?",
            if first.is_empty() {
                "another app"
            } else {
                &first
            }
        ));
        lines.push(format!("  [1] yes: stop it when {first} closes"));
    } else {
        let mut total: i64 = 0;
        for l in left {
            if let Some(c) = count_int(l.get("count")) {
                total += c;
            }
        }
        let n: i64 = if total == 0 { left.len() as i64 } else { total };
        let names: Vec<String> = left
            .iter()
            .take(4)
            .map(|l| clean(&pystr_key(l, "key", "?"), 32))
            .collect();
        let more = if left.len() > 4 { ", ..." } else { "" };
        lines.push(format!(
            "tæma: `{}` left {n} process{} running ({}{more}).",
            clean(&pystr_key(q, "job", "?"), 32),
            if n == 1 { "" } else { "es" },
            names.join(", "),
        ));
        lines.push(format!("  [1] part of {first}: stop them when it closes"));
    }
    let rest = if cands.len() > 1 { &cands[1..] } else { &[] };
    if !rest.is_empty() {
        let mut desc: Vec<String> = Vec::new();
        for c in rest.iter().take(3) {
            let mut item = clean(&pystr_key(c, "label", ""), 32);
            if let Some(seen) = count_int(c.get("seen")) {
                item.push_str(&format!(" (seen {seen}x)"));
            }
            desc.push(item);
        }
        lines.push(format!("  [2] part of another app: {}", desc.join(", ")));
    }
    lines.push(
        "  [3] standalone app: give them their own scope, never stop with a parent".to_string(),
    );
    lines.push("  [4] never stop these survivors".to_string());
    lines.push("  [Enter] ask me later".to_string());
    lines
        .into_iter()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                fill(&l, "  ")
            } else {
                fill(&l, "      ")
            }
        })
        .collect()
}

enum Act {
    Answer {
        choice: String,
        owner: Option<String>,
    },
    Menu,
    Later,
}

/// Equivalent of `map_key(key, q)`.
fn map_key(key: &str, cands: &[Value]) -> Act {
    if key == "1" && !cands.is_empty() {
        return Act::Answer {
            choice: "stop".to_string(),
            owner: cands[0].get("key").map(|v| pystr(Some(v))),
        };
    }
    if key == "2" && cands.len() > 1 {
        if cands.len() > 2 {
            return Act::Menu;
        }
        return Act::Answer {
            choice: "stop".to_string(),
            owner: cands[1].get("key").map(|v| pystr(Some(v))),
        };
    }
    if key == "3" {
        return Act::Answer {
            choice: "standalone".to_string(),
            owner: None,
        };
    }
    if key == "4" {
        return Act::Answer {
            choice: "never".to_string(),
            owner: None,
        };
    }
    Act::Later
}

/// Equivalent of `menu_choice(key, q)`: owner key or None.
/// Deliberate deviation: a non-ASCII-digit key (which makes the hook's
/// int() raise and exit silently) falls through to None, i.e. ask-later.
fn menu_choice(key: &str, rest: &[Value]) -> Option<String> {
    let upto = rest.len().min(9);
    if !key.is_empty() && key.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = key.parse::<usize>() {
            if 1 <= n && n <= upto {
                return rest[n - 1].get("key").map(|v| pystr(Some(v)));
            }
        }
    }
    None
}

/// Equivalent of `confirmation(q, choice, owner, reply)`.
fn confirmation(q: &Value, choice: &str, owner: Option<&str>, reply: &Value) -> String {
    let left = q.get("leftovers").and_then(|v| v.as_array());
    let empty: Vec<Value> = Vec::new();
    let left = left.unwrap_or(&empty);
    let keys: Vec<String> = left
        .iter()
        .take(3)
        .map(|l| clean(&pystr_key(l, "key", "?"), 32))
        .collect();
    let keys = keys.join(", ");
    let keys = if keys.is_empty() {
        "them".to_string()
    } else {
        keys
    };
    if choice == "standalone" {
        return format!("tæma: noted, {keys} will have their own scope.");
    }
    let name = match reply.get("owner") {
        Some(v) => pystr(Some(v)),
        None => owner.unwrap_or("").to_string(),
    };
    format!(
        "tæma: noted, {keys} will stop when {} closes.",
        clean(&name, 48)
    )
}

// ---- IPC v2 ---------------------------------------------------------------
// Faithful port of `sock_paths` and `request`: one JSON line per socket,
// total time near budget, silent on every failure.

static REQUEST_ID: AtomicU64 = AtomicU64::new(0);

fn sock_paths_with(taema_socket: Option<String>, home: Option<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(env) = taema_socket {
        if !env.is_empty() {
            out.push(env);
        }
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        out.push(format!("/run/user/{uid}/taema.sock"));
    }
    if let Some(home) = home {
        if !home.is_empty() {
            out.push(format!("{home}/.local/state/taema/taema.sock"));
        }
    }
    out
}

fn sock_paths() -> Vec<String> {
    sock_paths_with(
        std::env::var("TAEMA_SOCKET").ok(),
        std::env::var("HOME").ok(),
    )
}

fn runtime_dir() -> String {
    let uid = unsafe { libc::getuid() };
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("/run/user/{uid}"))
}

/// Blocking Unix connect with a timeout, mirroring `settimeout` + `connect`.
fn connect_timeout(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let close = |fd: RawFd| unsafe {
        libc::close(fd);
    };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        close(fd);
        return Err(std::io::Error::last_os_error());
    }
    let bytes = std::ffi::OsStr::new(path).as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.len() >= addr.sun_path.len() {
        close(fd);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    #[allow(clippy::cast_possible_truncation)]
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            close(fd);
            return Err(err);
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        let ready = unsafe { libc::poll(&mut pfd, 1, ms) };
        if ready <= 0 {
            close(fd);
            return Err(if ready == 0 {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            } else {
                std::io::Error::last_os_error()
            });
        }
        let mut sock_err: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut sock_err as *mut libc::c_int as *mut libc::c_void,
                &mut opt_len,
            );
        }
        if sock_err != 0 {
            close(fd);
            return Err(std::io::Error::from_raw_os_error(sock_err));
        }
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } != 0 {
        close(fd);
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn request(
    cmd: &str,
    args: &serde_json::Map<String, Value>,
    budget: Duration,
    paths: &[String],
) -> Option<Value> {
    let id = REQUEST_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let mut env = serde_json::Map::new();
    env.insert("v".to_string(), json!(2));
    env.insert("id".to_string(), json!(id));
    env.insert("cmd".to_string(), Value::String(cmd.to_string()));
    env.insert("args".to_string(), Value::Object(args.clone()));
    let line = serde_json::to_string(&Value::Object(env)).ok()? + "\n";
    let end = Instant::now() + budget;
    for path in paths {
        let now = Instant::now();
        if now >= end {
            break;
        }
        let left = end - now;
        let mut stream = match connect_timeout(path, left) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_write_timeout(Some(left));
        if stream.write_all(line.as_bytes()).is_err() {
            continue;
        }
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 65536];
        let mut failed = false;
        while !buf.ends_with(b"\n") {
            let left = end.saturating_duration_since(Instant::now());
            let floor = Duration::from_millis(10);
            let _ = stream.set_read_timeout(Some(left.max(floor)));
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if failed || buf.is_empty() {
            continue;
        }
        let reply: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Value::Object(map) = &reply {
            if map.get("v") == Some(&json!(2)) {
                match map.get("id") {
                    Some(Value::Number(n)) if n.as_u64() == Some(id) => {}
                    _ => {
                        let mut err = serde_json::Map::new();
                        err.insert(
                            "error".to_string(),
                            Value::String("response id mismatch".to_string()),
                        );
                        return Some(Value::Object(err));
                    }
                }
                if map.get("ok") == Some(&Value::Bool(true)) {
                    return map.get("result").cloned();
                }
                match map.get("error") {
                    Some(Value::Object(e)) => {
                        let mut err = serde_json::Map::new();
                        err.insert(
                            "error".to_string(),
                            e.get("message")
                                .cloned()
                                .unwrap_or_else(|| Value::String("request failed".to_string())),
                        );
                        return Some(Value::Object(err));
                    }
                    _ => {
                        let mut err = serde_json::Map::new();
                        err.insert(
                            "error".to_string(),
                            Value::String("invalid error reply".to_string()),
                        );
                        return Some(Value::Object(err));
                    }
                }
            }
        }
        return Some(reply);
    }
    None
}

fn args_object(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for (k, v) in pairs {
        map.insert((*k).to_string(), v.clone());
    }
    map
}

// ---- terminal -------------------------------------------------------------
// Faithful port of `pending_input` and `read_key`: brief non-canonical
// type-ahead check, one raw key with the timeout, signals left on.

fn set_canonical(fd: RawFd, canonical: bool) -> Option<libc::termios> {
    unsafe {
        let mut old: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut old) != 0 {
            return None;
        }
        let mut new = old;
        if canonical {
            new.c_lflag |= libc::ICANON;
        } else {
            new.c_lflag &= !libc::ICANON;
        }
        if libc::tcsetattr(fd, libc::TCSANOW, &new) != 0 {
            return None;
        }
        Some(old)
    }
}

fn restore_termios(fd: RawFd, saved: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, saved);
    }
}

/// Equivalent of `pending_input(fd)`: bytes waiting on the tty. Unknown
/// (any termios/ioctl failure) counts as waiting.
fn pending_input(fd: RawFd) -> bool {
    let saved = match set_canonical(fd, false) {
        Some(s) => s,
        None => return true,
    };
    let result = unsafe {
        let mut waiting: libc::c_int = 0;
        if libc::ioctl(fd, libc::FIONREAD, &mut waiting) != 0 {
            true
        } else {
            waiting > 0
        }
    };
    restore_termios(fd, &saved);
    result
}

fn wait_readable(fd: RawFd, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let left = deadline - now;
        let mut fdset: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe {
            libc::FD_ZERO(&mut fdset);
            libc::FD_SET(fd, &mut fdset);
        }
        let mut tv = libc::timeval {
            tv_sec: left.as_secs() as libc::time_t,
            tv_usec: left.subsec_micros() as libc::suseconds_t,
        };
        let ready = unsafe {
            libc::select(
                fd + 1,
                &mut fdset,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            )
        };
        if ready > 0 {
            return true;
        }
        if ready == 0 {
            return false;
        }
        // EINTR: retry with the remaining budget (matches PEP 475 behavior).
        if unsafe { *libc::__errno_location() } != libc::EINTR {
            return false;
        }
    }
}

/// Equivalent of `read_key(fd, timeout)`: one key, "" on timeout, Esc, or error.
fn read_key(fd: RawFd, timeout: Duration) -> String {
    unsafe {
        let mut old: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut old) != 0 {
            return String::new();
        }
        let mut new = old;
        new.c_lflag &= !(libc::ICANON | libc::ECHO);
        new.c_cc[libc::VMIN] = 1;
        new.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(fd, libc::TCSADRAIN, &new) != 0 {
            return String::new();
        }
        let deadline = Instant::now() + timeout;
        let mut out = String::new();
        if wait_readable(fd, deadline) {
            let mut byte = [0u8; 1];
            if libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) == 1 && byte[0] != 0x1b {
                out.push(byte[0] as char);
            }
            libc::tcflush(fd, libc::TCIFLUSH);
        }
        libc::tcsetattr(fd, libc::TCSADRAIN, &old);
        out
    }
}

/// Equivalent of `say(fd, text)`: best-effort write of one line.
fn say(fd: RawFd, text: &str) -> bool {
    let mut line = text.as_bytes().to_vec();
    line.push(b'\n');
    let mut written = 0;
    while written < line.len() {
        let n = unsafe {
            libc::write(
                fd,
                line[written..].as_ptr() as *const libc::c_void,
                line.len() - written,
            )
        };
        if n <= 0 {
            return false;
        }
        written += n as usize;
    }
    true
}

/// Equivalent of `drop_pending(shell)`: remove the pending-question marker.
fn drop_pending_in(dir: &str, shell: i64) {
    let _ = std::fs::remove_file(format!("{dir}/taema/q.{shell}"));
}

// ---- commands -------------------------------------------------------------

fn cmd_done(shell: i64, tag: &str, status: i64, word: &str) {
    let args = args_object(&[
        ("shell_pid", json!(shell)),
        ("tag", Value::String(tag.to_string())),
        ("status", json!(status)),
        ("word", Value::String(word.to_string())),
    ]);
    let _ = request("job_done", &args, BUDGET, &sock_paths());
}

fn cmd_kill(shell: i64, word: &str) {
    if !KILL_WORDS.contains(&word) {
        return;
    }
    let args = args_object(&[
        ("shell_pid", json!(shell)),
        ("word", Value::String(word.to_string())),
    ]);
    let _ = request("kill_done", &args, BUDGET, &sock_paths());
}

/// The ask flow on an already-open tty fd. Returns the status string the
/// Python `ask` returns (used by tests); None means it died silently, which
/// the binary reports as exit 0 exactly like the hook.
fn ask_on_fd(shell: i64, fd: RawFd, paths: &[String]) -> Option<&'static str> {
    let rdir = runtime_dir();
    if pending_input(fd) {
        return Some("typeahead");
    }
    let args = args_object(&[("shell_pid", json!(shell))]);
    let reply = request("ask", &args, ASK_BUDGET, paths)?;
    let question = match &reply {
        Value::Object(map) => match map.get("question") {
            Some(Value::Object(_)) => map.get("question").unwrap().clone(),
            _ => {
                drop_pending_in(&rdir, shell);
                return Some("none");
            }
        },
        _ => return None,
    };
    if !say(fd, &format_question(&question).join("\n")) {
        return None;
    }
    let empty: Vec<Value> = Vec::new();
    let cands = question
        .get("candidates")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let act = match map_key(&read_key(fd, KEY_TIMEOUT), cands) {
        Act::Menu => {
            let rest = if cands.len() > 1 { &cands[1..] } else { &[] };
            let mut parts: Vec<String> = Vec::new();
            for (i, c) in rest.iter().take(9).enumerate() {
                parts.push(format!(
                    "[{}] {}",
                    i + 1,
                    clean(&pystr_key(c, "label", ""), 32)
                ));
            }
            if !say(fd, &format!("  which app?  {}", parts.join("  "))) {
                return None;
            }
            match menu_choice(&read_key(fd, KEY_TIMEOUT), rest) {
                Some(owner) => Act::Answer {
                    choice: "stop".to_string(),
                    owner: Some(owner),
                },
                None => Act::Later,
            }
        }
        other => other,
    };
    let (choice, owner) = match act {
        Act::Answer { choice, owner } => (choice, owner),
        Act::Menu => return None,
        Act::Later => {
            drop_pending_in(&rdir, shell);
            if !say(fd, "tæma: ok, I will ask later.") {
                return None;
            }
            return Some("later");
        }
    };
    if choice == "stop" && owner.is_none() {
        // mirrors the hook: a missing owner key raises, and the hook exits 0.
        return None;
    }
    let mut msg = args_object(&[
        ("nonce", Value::String(pystr_key(&question, "nonce", ""))),
        ("choice", Value::String(choice.clone())),
    ]);
    if let Some(o) = &owner {
        msg.insert("owner".to_string(), Value::String(o.clone()));
    }
    let reply = request("answer", &msg, ASK_BUDGET, paths);
    match reply {
        Some(Value::Object(map)) if map.get("ok") == Some(&Value::Bool(true)) => {
            let done = say(
                fd,
                &confirmation(&question, &choice, owner.as_deref(), &Value::Object(map)),
            );
            if !done {
                return None;
            }
            Some("answered")
        }
        Some(Value::Object(_)) => {
            if !say(fd, "tæma: could not save the answer.") {
                return None;
            }
            Some("failed")
        }
        _ => None,
    }
}

fn cmd_ask(shell: i64) {
    let fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        return;
    }
    let _ = ask_on_fd(shell, fd, &sock_paths());
    unsafe {
        libc::close(fd);
    }
}

/// Equivalent of the `taema prompt` fast path: the cached summary segment.
fn cmd_prompt_in(dir: &str) {
    let content = match std::fs::read(format!("{dir}/taema/summary")) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return,
        },
        Err(_) => return,
    };
    let first: String = content
        .split('\n')
        .next()
        .unwrap_or("")
        .chars()
        .take(2048)
        .collect();
    let summary = first.trim_end_matches(['\r', '\n']);
    if !summary.is_empty() {
        println!("{summary}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("prompt") {
        cmd_prompt_in(&runtime_dir());
        std::process::exit(0);
    }
    if args.len() < 3 {
        std::process::exit(0);
    }
    let cmd = args[1].as_str();
    let shell: i64 = match args[2].trim().parse() {
        Ok(n) => n,
        Err(_) => std::process::exit(0),
    };
    if shell <= 1 {
        std::process::exit(0);
    }
    match cmd {
        "done" => {
            if args.len() >= 5 {
                let status: i64 = match args[4].trim().parse() {
                    Ok(n) => n,
                    Err(_) => std::process::exit(0),
                };
                let word = args.get(5).map(|s| clean(s, 32)).unwrap_or_default();
                cmd_done(shell, &args[3], status, &word);
            }
        }
        "kill" => {
            let word = args.get(3).cloned().unwrap_or_default();
            cmd_kill(shell, &word);
        }
        "ask" => cmd_ask(shell),
        "prompt" => cmd_prompt_in(&runtime_dir()),
        _ => {}
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    // Unit tests for the pure port logic. The wrap and format_question
    // batteries are frozen outputs of CPython's textwrap.fill (width 78,
    // the hook's indents) and libexec/taema-hook computed 2026-10-28;
    // tests/test_fast_parity.py proves the same behavior live end to end.
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn wrap_matches_cpython() {
        let cases: &[(&str, &str, &str)] = &[
("", "  ", ""),
("", "      ", ""),
(" ", "  ", ""),
(" ", "      ", ""),
("hello", "  ", "hello"),
("hello", "      ", "hello"),
("hello world", "  ", "hello world"),
("hello world", "      ", "hello world"),
("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "  ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "      ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
("goof-ball", "  ", "goof-ball"),
("goof-ball", "      ", "goof-ball"),
("Look, goof-ball -- use the -b option!", "  ", "Look, goof-ball -- use the -b option!"),
("Look, goof-ball -- use the -b option!", "      ", "Look, goof-ball -- use the -b option!"),
("Hello there -- you goof-ball, use the -b option!", "  ", "Hello there -- you goof-ball, use the -b option!"),
("Hello there -- you goof-ball, use the -b option!", "      ", "Hello there -- you goof-ball, use the -b option!"),
("well-known well--known a-b-c -b -- -", "  ", "well-known well--known a-b-c -b -- -"),
("well-known well--known a-b-c -b -- -", "      ", "well-known well--known a-b-c -b -- -"),
("trailing hyphen-", "  ", "trailing hyphen-"),
("trailing hyphen-", "      ", "trailing hyphen-"),
("-leading hyphen", "  ", "-leading hyphen"),
("-leading hyphen", "      ", "-leading hyphen"),
("em---dash between---words", "  ", "em---dash between---words"),
("em---dash between---words", "      ", "em---dash between---words"),
("tab\there\tand\nnewline\rmix\u{b}\u{c}", "  ", "tab     here    and newline mix"),
("tab\there\tand\nnewline\rmix\u{b}\u{c}", "      ", "tab     here    and newline mix"),
("foo. Bar baz. Qux!", "  ", "foo. Bar baz. Qux!"),
("foo. Bar baz. Qux!", "      ", "foo. Bar baz. Qux!"),
("quoted \"end.\" next", "  ", "quoted \"end.\" next"),
("quoted \"end.\" next", "      ", "quoted \"end.\" next"),
("café naïve résumé wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd ", "  ", "café naïve résumé wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd\n  wörd wörd wörd wörd wörd wörd wörd wörd"),
("café naïve résumé wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd ", "      ", "café naïve résumé wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd wörd\n      wörd wörd wörd wörd wörd wörd wörd wörd"),
("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文", "  ", "中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文"),
("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文", "      ", "中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文"),
("emoji 😀 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "  ", "emoji 😀 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n  xxxxxxxxxxxxxxxxxxxx"),
("emoji 😀 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "      ", "emoji 😀 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n      xxxxxxxxxxxxxxxxxxxx"),
("a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z ", "  ", "a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m\n  n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y\n  z a b c d e f g h i j k l m n o p q r s t u v w x y z"),
("a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z ", "      ", "a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m\n      n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w\n      x y z a b c d e f g h i j k l m n o p q r s t u v w x y z"),
("supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious ", "  ", "supercalifragilisticexpialidocious supercalifragilisticexpialidocious\n  supercalifragilisticexpialidocious supercalifragilisticexpialidocious\n  supercalifragilisticexpialidocious"),
("supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious supercalifragilisticexpialidocious ", "      ", "supercalifragilisticexpialidocious supercalifragilisticexpialidocious\n      supercalifragilisticexpialidocious supercalifragilisticexpialidocious\n      supercalifragilisticexpialidocious"),
("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "  ", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n  yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n  y"),
("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "      ", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n      yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n      yyyyy"),
("word word word zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz tail here", "  ", "word word word zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n  zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz tail here"),
("word word word zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz tail here", "      ", "word word word zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n      zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz tail here"),
("  leading and trailing  ", "  ", "  leading and trailing"),
("  leading and trailing  ", "      ", "  leading and trailing"),
("hyphen-at-the-very-end-of-a-line-that-keeps-going-", "  ", "hyphen-at-the-very-end-of-a-line-that-keeps-going-"),
("hyphen-at-the-very-end-of-a-line-that-keeps-going-", "      ", "hyphen-at-the-very-end-of-a-line-that-keeps-going-"),
("multiple   spaces\t\tand\ttabs", "  ", "multiple   spaces               and     tabs"),
("multiple   spaces\t\tand\ttabs", "      ", "multiple   spaces               and     tabs"),
("\u{200b}zero\u{200c}width\u{200b}in\u{2066}here\u{feff}", "  ", "\u{200b}zero\u{200c}width\u{200b}in\u{2066}here\u{feff}"),
("\u{200b}zero\u{200c}width\u{200b}in\u{2066}here\u{feff}", "      ", "\u{200b}zero\u{200c}width\u{200b}in\u{2066}here\u{feff}"),
        ];
        for (text, indent, expected) in cases {
            assert_eq!(
                &fill(text, indent),
                expected,
                "input={text:?} indent={indent:?}"
            );
        }
    }

    #[test]
    fn format_question_matches_hook() {
        let cases: &[(&str, Vec<String>)] = &[
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"node\", \"count\": 1, \"key\": \"node:esbuild\"}, {\"comm\": \"node\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"closed\", \"leftovers\": [{\"comm\": \"vite\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `vite` was closed. Was it part of npm run dev?"), String::from("  [1] yes: stop it when npm run dev closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 0 processes running ()."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"node\", \"count\": 1, \"key\": \"node:esbuild\"}, {\"comm\": \"node\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite)."), String::from("  [1] part of : stop them when it closes"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"c\", \"count\": 2, \"key\": \"k0\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k1\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k2\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k3\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k4\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k5\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k6\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k7\"}, {\"comm\": \"c\", \"count\": 2, \"key\": \"k8\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 18 processes running (k0, k1, k2, k3, ...)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\", \"seen\": 3}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"node\", \"count\": 1, \"key\": \"node:esbuild\"}, {\"comm\": \"node\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 2 processes running (node:esbuild, node:vite)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code (seen 3x)"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\", \"kind\": \"job\", \"label\": \"llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"node\", \"count\": 1, \"key\": \"node:esbuild\"}, {\"comm\": \"node\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj` left 2 processes running\n  (node:esbuild, node:vite)."), String::from("  [1] part of llllllllllllllllllllllllllllllllllllllllllllllll: stop them when\n      it closes"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"evil\\u001b[2J\\u0007\\u200ex\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"node\", \"count\": 1, \"key\": \"node:esbuild\"}, {\"comm\": \"node\", \"count\": 1, \"key\": \"node:vite\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `evil[2Jx` left 2 processes running (node:esbuild, node:vite)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"a\", \"count\": 0, \"key\": \"a\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 1 process running (a)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
("{\"candidates\": [{\"id\": 1, \"key\": \"npm\", \"kind\": \"job\", \"label\": \"npm run dev\"}, {\"id\": 2, \"key\": \"code\", \"kind\": \"ancestor\", \"label\": \"code\"}], \"choices\": [\"stop\", \"keep\", \"standalone\", \"never\"], \"expires_in\": 60, \"id\": 1, \"job\": \"npm run dev\", \"kind\": \"job\", \"leftovers\": [{\"comm\": \"a\", \"key\": \"a\"}], \"nonce\": \"abc123\", \"shell_pid\": 20}", vec![String::from("tæma: `npm run dev` left 1 process running (a)."), String::from("  [1] part of npm run dev: stop them when it closes"), String::from("  [2] part of another app: code"), String::from("  [3] standalone app: give them their own scope, never stop with a parent"), String::from("  [4] never stop these survivors"), String::from("  [Enter] ask me later")]),
        ];
        for (qjson, expected) in cases {
            let q: Value = serde_json::from_str(qjson).unwrap();
            assert_eq!(&format_question(&q), expected, "q={qjson}");
        }
    }

    #[test]
    fn clean_strips_controls_and_caps() {
        assert_eq!(clean("a\x1b[2Jb\u{200e}c", 64), "a[2Jbc");
        assert_eq!(clean(&"x".repeat(100), 32).len(), 32);
        assert_eq!(clean("caf\u{e9}", 64), "caf\u{e9}");
    }

    #[test]
    fn key_mapping_matches_hook() {
        let q: Value = serde_json::from_str(
            r#"{"candidates": [{"key": "npm"}, {"key": "code"}, {"key": "idea"}]}"#,
        )
        .unwrap();
        let cands = q.get("candidates").and_then(|v| v.as_array()).unwrap();
        assert!(matches!(
            map_key("1", cands),
            Act::Answer { choice, owner }
            if choice == "stop" && owner.as_deref() == Some("npm")
        ));
        assert!(matches!(map_key("2", cands), Act::Menu));
        let two: Value =
            serde_json::from_str(r#"{"candidates": [{"key": "npm"}, {"key": "code"}]}"#).unwrap();
        let two = two.get("candidates").and_then(|v| v.as_array()).unwrap();
        assert!(matches!(
            map_key("2", two),
            Act::Answer { choice, owner }
            if choice == "stop" && owner.as_deref() == Some("code")
        ));
        assert!(matches!(
            map_key("3", cands),
            Act::Answer { choice, owner }
            if choice == "standalone" && owner.is_none()
        ));
        for key in ["", "x", "5", "0", "9"] {
            assert!(matches!(map_key(key, cands), Act::Later), "{key:?}");
        }
        let one: Value = serde_json::from_str(r#"{"candidates": [{"key": "npm"}]}"#).unwrap();
        let one = one.get("candidates").and_then(|v| v.as_array()).unwrap();
        assert!(matches!(map_key("2", one), Act::Later));
    }

    #[test]
    fn menu_choice_matches_hook() {
        let rest: Vec<Value> = ["code", "idea"]
            .iter()
            .map(|k| serde_json::json!({"key": k}))
            .collect();
        assert_eq!(menu_choice("1", &rest).as_deref(), Some("code"));
        assert_eq!(menu_choice("2", &rest).as_deref(), Some("idea"));
        assert_eq!(menu_choice("3", &rest), None);
        assert_eq!(menu_choice("0", &rest), None);
        assert_eq!(menu_choice("x", &rest), None);
        assert_eq!(menu_choice("", &rest), None);
    }

    #[test]
    fn confirmation_matches_hook() {
        let q: Value = serde_json::from_str(
            r#"{"leftovers": [{"key": "node:esbuild"}, {"key": "node:vite"}]}"#,
        )
        .unwrap();
        let reply: Value = serde_json::from_str(r#"{"ok": true, "owner": "npm"}"#).unwrap();
        assert_eq!(
            confirmation(&q, "stop", Some("code"), &reply),
            "t\u{e6}ma: noted, node:esbuild, node:vite will stop when npm closes."
        );
        assert_eq!(
            confirmation(&q, "standalone", None, &reply),
            "t\u{e6}ma: noted, node:esbuild, node:vite will have their own scope."
        );
        let empty: Value = serde_json::from_str(r#"{"leftovers": []}"#).unwrap();
        assert_eq!(
            confirmation(&empty, "never", None, &reply),
            "t\u{e6}ma: noted, them will stop when npm closes."
        );
    }

    #[test]
    fn sock_paths_honors_overrides() {
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            sock_paths_with(Some("/tmp/x.sock".to_string()), Some("/home/u".to_string())),
            vec![
                "/tmp/x.sock".to_string(),
                format!("/run/user/{uid}/taema.sock"),
                "/home/u/.local/state/taema/taema.sock".to_string(),
            ]
        );
        assert_eq!(
            sock_paths_with(None, None),
            vec![format!("/run/user/{uid}/taema.sock")]
        );
        assert_eq!(
            sock_paths_with(Some("".to_string()), Some("".to_string())),
            vec![format!("/run/user/{uid}/taema.sock")]
        );
    }

    // A scripted fake daemon: one thread, one reply per connection.
    struct FakeServer {
        dir: String,
        path: String,
        got: Arc<Mutex<Vec<String>>>,
    }

    static SERVE_SEQ: AtomicU64 = AtomicU64::new(0);

    fn serve(replies: Vec<String>) -> FakeServer {
        use std::os::unix::net::UnixListener;
        let seq = SERVE_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = format!(
            "{}/taema-fast-test-{}-{seq}",
            std::env::temp_dir().to_string_lossy(),
            std::process::id()
        );
        let _ = std::fs::create_dir_all(&dir);
        let path = format!("{dir}/t.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let got = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(replies));
        let got2 = Arc::clone(&got);
        let replies2 = Arc::clone(&replies);
        std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(20);
            while Instant::now() < end {
                let (mut conn, _) = match listener.accept() {
                    Ok(c) => c,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                };
                let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match std::io::Read::read(&mut conn, &mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.ends_with(b"\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&buf).trim_end().to_string();
                got2.lock().unwrap().push(text.clone());
                // echo the request id: the client counter is process-global.
                let id = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let reply = replies2.lock().unwrap().remove(0).replace("{ID}", &id);
                let _ = std::io::Write::write_all(&mut conn, reply.as_bytes());
                if replies2.lock().unwrap().is_empty() {
                    break;
                }
            }
        });
        FakeServer { dir, path, got }
    }

    fn envelope(id: &str, result: &str) -> String {
        format!("{{\"v\": 2, \"id\": {id}, \"ok\": true, \"result\": {result}}}\n")
    }

    #[test]
    fn request_returns_result_and_id() {
        let srv = serve(vec![envelope("{ID}", r#"{"question": {}}"#)]);
        let args = args_object(&[("shell_pid", serde_json::json!(20))]);
        let out = request("ask", &args, Duration::from_secs(5), &[srv.path.clone()]);
        assert_eq!(out, Some(serde_json::json!({"question": {}})));
        let got = srv.got.lock().unwrap();
        assert_eq!(got.len(), 1);
        let sent: Value = serde_json::from_str(&got[0]).unwrap();
        assert_eq!(sent.get("v"), Some(&serde_json::json!(2)));
        // the id is a process-global counter; the echo in `serve` proves
        // the reply id matched this request (else a mismatch error returns).
        assert!(sent.get("id").and_then(|v| v.as_u64()).unwrap_or(0) >= 1);
        assert_eq!(sent.get("cmd"), Some(&serde_json::json!("ask")));
        let _ = std::fs::remove_dir_all(&srv.dir);
    }

    #[test]
    fn request_down_is_none() {
        let args = args_object(&[]);
        let out = request(
            "ask",
            &args,
            Duration::from_millis(200),
            &["/nonexistent/taema-fast-test.sock".to_string()],
        );
        assert_eq!(out, None);
    }

    #[test]
    fn request_id_mismatch_and_error_shapes() {
        let bad_id = "{\"v\": 2, \"id\": 999999, \"ok\": true, \"result\": {}}\n".to_string();
        let srv = serve(vec![bad_id]);
        let args = args_object(&[]);
        let out = request("ask", &args, Duration::from_secs(5), &[srv.path.clone()]);
        assert_eq!(
            out,
            Some(serde_json::json!({"error": "response id mismatch"}))
        );
        let _ = std::fs::remove_dir_all(&srv.dir);

        let err = "{\"v\": 2, \"id\": {ID}, \"ok\": false, \"error\": {\"message\": \"nope\"}}\n"
            .to_string();
        let srv = serve(vec![err]);
        let out = request("ask", &args, Duration::from_secs(5), &[srv.path.clone()]);
        assert_eq!(out, Some(serde_json::json!({"error": "nope"})));
        let _ = std::fs::remove_dir_all(&srv.dir);

        let raw = "[1, 2]\n".to_string();
        let srv = serve(vec![raw]);
        let out = request("ask", &args, Duration::from_secs(5), &[srv.path.clone()]);
        assert_eq!(out, Some(serde_json::json!([1, 2])));
        let _ = std::fs::remove_dir_all(&srv.dir);
    }

    #[test]
    fn read_key_and_pending_on_non_tty() {
        let devnull = std::fs::File::open("/dev/null").unwrap();
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&devnull);
        assert_eq!(read_key(fd, Duration::from_millis(100)), "");
        assert!(pending_input(fd));
    }

    #[test]
    fn drop_pending_removes_marker() {
        let dir = format!(
            "{}/taema-fast-test-{}-drop",
            std::env::temp_dir().to_string_lossy(),
            std::process::id()
        );
        std::fs::create_dir_all(format!("{dir}/taema")).unwrap();
        std::fs::write(format!("{dir}/taema/q.20"), b"x").unwrap();
        drop_pending_in(&dir, 20);
        assert!(!std::path::Path::new(&format!("{dir}/taema/q.20")).exists());
        drop_pending_in(&dir, 20);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
