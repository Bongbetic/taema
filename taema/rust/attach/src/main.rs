//! taema-attach: the one privileged step of taema. Run as root through sudo.
//!
//! ```text
//! taema-attach attach PID NAME           move PID into /sys/fs/cgroup/user/<uid>/scope-NAME
//! taema-attach move RELPATH PID...       move PIDs into /sys/fs/cgroup/user/<uid>/RELPATH
//! taema-attach oom-record PID START ORIGINAL APPLIED
//! taema-attach oom-restore PID START ORIGINAL APPLIED restore one caller-owned process priority
//! ```
//!
//! Faithful port of `libexec/taema-attach` (Python): identical command line,
//! identical validation, identical messages. The only intentional differences
//! are inputs where the Python helper crashes with a traceback (non-ASCII
//! digits, out-of-range pids, mistyped root config): Rust refuses cleanly
//! with the same exit code instead.
//!
//! Test mode (`TAEMA_ATTACH_TEST=1`) is honored only when running unprivileged
//! (euid != 0), so the production path under sudo never consults the
//! environment: paths come from `TAEMA_ATTACH_CG/CONFIG/LOG/OOM_DIR`, the
//! caller defaults to the real uid, and root-ownership checks are relaxed.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, RawFd};

/// pidfd_open via the raw syscall: the libc wrapper is missing from musl
/// libc archives old enough to matter for static builds, while the
/// syscall number is stable on every kernel new enough to implement it
/// (5.3+); older kernels fail both spellings with ENOSYS.
fn pidfd_open_sys(pid: libc::pid_t, flags: libc::c_uint) -> libc::c_int {
    // SAFETY: a direct syscall with integer arguments has no memory effects.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            pid as libc::c_long,
            flags as libc::c_long,
        )
    };
    if ret < 0 {
        -1
    } else {
        ret as libc::c_int
    }
}
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const CG: &str = "/sys/fs/cgroup";
const CONFIG: &str = "/etc/taema/taema.toml";
const LOG: &str = "/var/log/taema/attach.log";
const LOG_MAX: u64 = 1 << 20;
const OOM_STATE_DIR: &str = "/run/taema-oom";
const OOM_RECORD_LIMIT: usize = 4096;
const OOM_STATE_MAX: usize = 4096;
const OOM_MIN: i64 = -1000;
const OOM_MAX: i64 = 1000;

/// A refusal: message printed as `taema-attach: {message}`, exit code 1.
type Refused = String;

fn refused(message: impl Into<String>) -> Refused {
    message.into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn strerror(errno: i32) -> String {
    // SAFETY: strerror returns a static string for any errno value.
    unsafe {
        let ptr = libc::strerror(errno);
        if ptr.is_null() {
            format!("Unknown error {}", errno)
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

/// What Python reports as `e.strerror`: no `(os error N)` suffix.
fn io_message(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(errno) => strerror(errno),
        None => error.to_string(),
    }
}

/// Paths and trust level. Test overrides apply only when unprivileged.
struct Layout {
    cg: String,
    config: String,
    log: String,
    oom_dir: String,
    test_mode: bool,
}

impl Layout {
    fn load() -> Layout {
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let test_mode = euid != 0 && std::env::var("TAEMA_ATTACH_TEST").as_deref() == Ok("1");
        let pick = |name: &str, fallback: &str| {
            if test_mode {
                std::env::var(name).unwrap_or_else(|_| fallback.to_string())
            } else {
                fallback.to_string()
            }
        };
        Layout {
            cg: pick("TAEMA_ATTACH_CG", CG),
            config: pick("TAEMA_ATTACH_CONFIG", CONFIG),
            log: pick("TAEMA_ATTACH_LOG", LOG),
            oom_dir: pick("TAEMA_ATTACH_OOM_DIR", OOM_STATE_DIR),
            test_mode,
        }
    }
}

fn is_rel_char(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'/' | b'-')
}

/// `[a-z0-9][a-z0-9_./-]{0,96}` plus the segment check from `valid_rel`.
fn valid_rel(rel: &str) -> bool {
    let bytes = rel.as_bytes();
    if bytes.is_empty() || bytes.len() > 97 {
        return false;
    }
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    if !bytes[1..].iter().all(|b| is_rel_char(*b)) {
        return false;
    }
    rel.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// `[a-z0-9][a-z0-9_-]{0,31}` full match.
fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// `/[0-9]+(/.*)?` full match: a login session cgroup.
fn is_session_cg(cg: &str) -> bool {
    let bytes = cg.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'/' {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 1 {
        return false;
    }
    i == bytes.len() || bytes[i] == b'/'
}

fn is_ascii_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// `-?[0-9]+` full match.
fn is_ascii_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `fnmatch.fnmatchcase`: `*`, `?`, `[...]`. Returns None where the running
/// Python would crash (an empty chunk index), so the caller refuses cleanly.
fn fnmatchcase(name: &str, pattern: &str) -> Option<bool> {
    fn helper(name: &[u8], pattern: &[u8]) -> Option<bool> {
        if pattern.is_empty() {
            return Some(name.is_empty());
        }
        match pattern[0] {
            b'*' => {
                let mut rest = pattern;
                while rest.first() == Some(&b'*') {
                    rest = &rest[1..];
                }
                if rest.is_empty() {
                    return Some(true);
                }
                // Trying every split matches the documented fullmatch
                // behavior of the atomic-group rewrite for boolean match.
                for i in 0..=name.len() {
                    if helper(&name[i..], rest)? {
                        return Some(true);
                    }
                }
                Some(false)
            }
            b'?' => {
                if name.is_empty() {
                    return Some(false);
                }
                helper(&name[1..], &pattern[1..])
            }
            b'[' => {
                let mut j = 1;
                if pattern.get(j) == Some(&b'!') {
                    j += 1;
                }
                if pattern.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < pattern.len() && pattern[j] != b']' {
                    j += 1;
                }
                if j >= pattern.len() {
                    if name.is_empty() || name[0] != b'[' {
                        return Some(false);
                    }
                    return helper(&name[1..], &pattern[1..]);
                }
                if name.is_empty() {
                    return Some(false);
                }
                let matched = class_match(&pattern[1..j], pattern[1] == b'!', name[0])?;
                if !matched {
                    return Some(false);
                }
                helper(&name[1..], &pattern[j + 1..])
            }
            _ => {
                if name.is_empty() || name[0] != pattern[0] {
                    return Some(false);
                }
                helper(&name[1..], &pattern[1..])
            }
        }
    }
    helper(name.as_bytes(), pattern.as_bytes())
}

/// One `[...]` class over the bytes between the brackets, following the
/// chunk split, empty-range removal, and escape rules of `fnmatch.translate`.
/// None marks the inputs where Python indexes an empty chunk and crashes.
fn class_match(inner: &[u8], bang: bool, ch: u8) -> Option<bool> {
    let chunks: Vec<Vec<u8>> = if !inner.contains(&b'-') {
        vec![inner.to_vec()]
    } else {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        // Rebase the index-based split loop onto `inner`.
        let mut i = 0;
        let mut k = if bang { 2 } else { 1 };
        loop {
            let mut found = None;
            let mut at = k;
            while at < inner.len() {
                if inner[at] == b'-' {
                    found = Some(at);
                    break;
                }
                at += 1;
            }
            let Some(position) = found else {
                break;
            };
            chunks.push(inner[i..position].to_vec());
            i = position + 1;
            k = position + 3;
        }
        if inner[i..].is_empty() {
            let mut last = chunks.pop()?;
            last.push(b'-');
            chunks.push(last);
        } else {
            chunks.push(inner[i..].to_vec());
        }
        // Empty-range removal, descending, exactly like the source loop over
        // a range fixed before the first merge.
        let mut index = chunks.len();
        while index > 1 {
            index -= 1;
            if index >= chunks.len() {
                return None;
            }
            let last = *chunks[index - 1].last()?;
            let first = *chunks[index].first()?;
            if last > first {
                let mut merged = chunks[index - 1][..chunks[index - 1].len() - 1].to_vec();
                merged.extend_from_slice(&chunks[index][1..]);
                chunks[index - 1] = merged;
                chunks.remove(index);
            }
        }
        chunks
    };
    // The joined `stuff` decides empty/negated handling; escapes do not move
    // the first byte, and set-operation escapes keep every byte literal.
    let joined: Vec<u8> = chunks.join(&b'-');
    if joined.is_empty() {
        return Some(false);
    }
    if joined == b"!" {
        return Some(true);
    }
    let negate = joined[0] == b'!';
    let mut matched = false;
    for (number, chunk) in chunks.iter().enumerate() {
        // Within a chunk every byte is literal: `fnmatch` doubles `\` and
        // escapes `-` before compiling.
        if chunk.contains(&ch) {
            matched = true;
        }
        // The joining `-` spans a range from the previous chunk's last byte
        // to this chunk's first byte; empty-range removal kept only valid
        // ones, and anything empty here crashed Python first.
        if number > 0 {
            let (Some(&low), Some(&high)) = (chunks[number - 1].last(), chunk.first()) else {
                return None;
            };
            if low <= ch && ch <= high {
                matched = true;
            }
        }
    }
    Some(matched != negate)
}

#[derive(Default)]
struct Rules {
    comm: Vec<String>,
    cgroup_prefix: Vec<String>,
    env_prefix: HashMap<String, Vec<String>>,
}

/// Fail closed: a missing, unreadable or untrusted system config refuses.
fn load_rules(layout: &Layout, path: Option<&str>) -> Result<Rules, Refused> {
    let path = path.unwrap_or(&layout.config);
    let meta = fs::metadata(path).map_err(|e| {
        refused(format!(
            "system config {} unavailable: {}",
            path,
            io_message(&e)
        ))
    })?;
    let mode = meta.mode();
    let trusted = meta.is_file() && mode & 0o022 == 0 && (layout.test_mode || meta.uid() == 0);
    if !trusted {
        return Err(refused(format!(
            "{} must be a regular file owned by root and not group/world writable",
            path
        )));
    }
    let bytes = fs::read(path).map_err(|e| {
        refused(format!(
            "system config {} unreadable: {}",
            path,
            io_message(&e)
        ))
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|e| refused(format!("system config {} unreadable: {}", path, e)))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| refused(format!("system config {} unreadable: {}", path, e)))?;
    let protected = table
        .get("protected")
        .cloned()
        .unwrap_or(toml::Table::new().into());
    let invalid = || {
        refused(format!(
            "system config {} has invalid protected rules",
            path
        ))
    };
    let table = protected.as_table().ok_or_else(invalid)?;
    let mut rules = Rules {
        comm: string_list(table.get("comm")).ok_or_else(invalid)?,
        cgroup_prefix: string_list(table.get("cgroup_prefix")).ok_or_else(invalid)?,
        ..Rules::default()
    };
    match table.get("env_prefix") {
        None => {}
        Some(toml::Value::Table(map)) => {
            for (key, value) in map {
                rules
                    .env_prefix
                    .insert(key.clone(), string_list(Some(value)).ok_or_else(invalid)?);
            }
        }
        Some(_) => return Err(invalid()),
    }
    Ok(rules)
}

/// A string list, or the characters of a bare string (mirroring Python's
/// iteration over a mistyped value); anything else is invalid.
fn string_list(value: Option<&toml::Value>) -> Option<Vec<String>> {
    match value {
        None => Some(Vec::new()),
        Some(toml::Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(item.as_str()?.to_string());
            }
            Some(out)
        }
        Some(toml::Value::String(text)) => Some(text.chars().map(|c| c.to_string()).collect()),
        Some(_) => None,
    }
}

fn read_proc(pid: i64, name: &str) -> std::io::Result<Vec<u8>> {
    fs::read(format!("/proc/{}/{}", pid, name))
}

/// Field 22 of /proc/PID/stat; the comm may hold spaces and parentheses.
fn starttime(pid: i64) -> std::io::Result<i64> {
    let raw = read_proc(pid, "stat")?;
    let text = String::from_utf8_lossy(&raw);
    let end = text
        .rfind(')')
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad stat"))?;
    let rest = text
        .get(end + 2..)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad stat"))?;
    rest.split_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad stat"))?
        .parse::<i64>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad stat"))
}

fn pid_uid(pid: i64) -> std::io::Result<u32> {
    Ok(fs::metadata(format!("/proc/{}", pid))?.uid())
}

fn proc_env(pid: i64) -> std::io::Result<HashMap<String, String>> {
    let raw = read_proc(pid, "environ")?;
    let mut out = HashMap::new();
    for item in raw.split(|b| *b == 0) {
        if let Some(eq) = item.iter().position(|b| *b == b'=') {
            let key = String::from_utf8_lossy(&item[..eq]).into_owned();
            let value = String::from_utf8_lossy(&item[eq + 1..]).into_owned();
            out.insert(key, value);
        }
    }
    Ok(out)
}

fn proc_cgroup(pid: i64) -> std::io::Result<String> {
    let raw = read_proc(pid, "cgroup")?;
    for line in String::from_utf8_lossy(&raw).lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.trim().to_string());
        }
    }
    Ok(String::new())
}

fn gone_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

/// A pidfd becomes readable once the process has exited.
fn pidfd_gone(fd: RawFd) -> bool {
    let mut item = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll with one valid struct and a zero timeout cannot block.
    let ready = unsafe { libc::poll(&mut item, 1, 0) };
    ready > 0 && item.revents & libc::POLLIN != 0
}

fn close_fd(fd: RawFd) {
    // SAFETY: fd is owned here and closed exactly once.
    unsafe {
        libc::close(fd);
    }
}

/// Raise unless pid may be moved for caller; None when the pid is gone.
fn check_pid(
    layout: &Layout,
    pid: i64,
    caller: u32,
    rules: &Rules,
) -> Result<Option<(String, String)>, Refused> {
    if pid <= 1 {
        return Err(refused(format!("bad pid {}", pid)));
    }
    let (owner, comm, cg, env) = match read_pid_facts(pid) {
        Ok(facts) => facts,
        Err(e) if gone_error(&e) => return Ok(None),
        // Python propagates anything else as an uncaught traceback; refuse
        // with the same exit code instead.
        Err(e) => {
            return Err(refused(format!(
                "could not inspect pid {}: {}",
                pid,
                io_message(&e)
            )));
        }
    };
    if owner != caller {
        return Err(refused(format!(
            "pid {} is not owned by uid {}",
            pid, caller
        )));
    }
    for pattern in &rules.comm {
        match fnmatchcase(&comm, pattern) {
            Some(true) => {
                return Err(refused(format!("pid {} ({}) is protected", pid, comm)));
            }
            Some(false) => {}
            // Python indexes an empty chunk and crashes here; same exit code.
            None => {
                return Err(refused(format!("invalid protected pattern {}", pattern)));
            }
        }
    }
    for pre in &rules.cgroup_prefix {
        let full = format!("{}{}", layout.cg, cg);
        if full == *pre || full.starts_with(&(pre.trim_end_matches('/').to_string() + "/")) {
            return Err(refused(format!(
                "pid {} is in protected cgroup {}",
                pid, pre
            )));
        }
    }
    for (var, prefixes) in &rules.env_prefix {
        if let Some(val) = env.get(var) {
            for pre in prefixes {
                if !val.is_empty()
                    && (val == pre
                        || val.starts_with(&(pre.trim_end_matches('/').to_string() + "/")))
                {
                    return Err(refused(format!(
                        "pid {} has protected {}={}",
                        pid, var, val
                    )));
                }
            }
        }
    }
    if !(is_session_cg(&cg) || cg.starts_with(&format!("/user/{}/", caller))) {
        return Err(refused(format!(
            "pid {} is in {}; only login-session and own scopes may be moved",
            pid, cg
        )));
    }
    Ok(Some((comm, cg)))
}

fn read_pid_facts(pid: i64) -> std::io::Result<(u32, String, String, HashMap<String, String>)> {
    let owner = pid_uid(pid)?;
    let comm = String::from_utf8_lossy(&read_proc(pid, "comm")?)
        .trim()
        .to_string();
    let cg = proc_cgroup(pid)?;
    let env = proc_env(pid)?;
    Ok((owner, comm, cg, env))
}

fn log_line(layout: &Layout, line: &str) {
    let _ = (|| -> std::io::Result<()> {
        if let Some(parent) = Path::new(&layout.log).parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::metadata(&layout.log) {
            Ok(meta) => {
                if meta.len() > LOG_MAX {
                    fs::rename(&layout.log, layout.log.clone() + ".1")?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&layout.log)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    })();
}

fn move_one(
    layout: &Layout,
    pid: i64,
    caller: u32,
    rel: &str,
    dest: &str,
    rules: &Rules,
) -> Result<(), Refused> {
    if pid > i32::MAX as i64 {
        // Python's pidfd_open raises OverflowError here: same exit code,
        // clean message instead of a traceback.
        return Err(refused(format!(
            "pidfd_open({}) failed: Numerical result out of range",
            pid
        )));
    }
    // SAFETY: pidfd_open with flags 0 either returns a fresh fd or -1.
    let fd = pidfd_open_sys(pid as libc::pid_t, 0);
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            eprintln!("taema-attach: pid {} gone, skipped", pid);
            return Ok(());
        }
        return Err(refused(format!(
            "pidfd_open({}) failed: {}",
            pid,
            strerror(errno)
        )));
    }
    let result = move_one_guarded(layout, pid, caller, rel, dest, rules, fd);
    close_fd(fd);
    result
}

fn move_one_guarded(
    layout: &Layout,
    pid: i64,
    caller: u32,
    rel: &str,
    dest: &str,
    rules: &Rules,
    fd: RawFd,
) -> Result<(), Refused> {
    let info = check_pid(layout, pid, caller, rules)?;
    let Some((comm, cg)) = info else {
        eprintln!("taema-attach: pid {} gone, skipped", pid);
        return Ok(());
    };
    let start = match starttime(pid).and_then(|start| {
        if pid_uid(pid)? != caller {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "changed owner",
            ));
        }
        Ok(start)
    }) {
        Ok(start) => start,
        Err(e) if gone_error(&e) => {
            eprintln!("taema-attach: pid {} gone, skipped", pid);
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(refused(format!("pid {} changed owner", pid)));
        }
        Err(e) => {
            return Err(refused(format!(
                "could not read process start for pid {}: {}",
                pid, e
            )));
        }
    };
    let src = format!("{}{}/cgroup.procs", layout.cg, cg);
    if let Err(e) = fs::write(format!("{}/cgroup.procs", dest), format!("{}\n", pid)) {
        eprintln!("taema-attach: pid {} not moved: {}", pid, io_message(&e));
        return Ok(());
    }
    let mut bad: Option<&str> = None;
    if pidfd_gone(fd) {
        bad = Some("exited");
    } else {
        match starttime(pid).and_then(|now| Ok((now, pid_uid(pid)?))) {
            Ok((now, owner)) => {
                if now != start || owner != caller {
                    bad = Some("was replaced");
                }
            }
            Err(e) if gone_error(&e) => bad = Some("exited"),
            Err(_) => {
                return Err(refused(format!(
                    "could not verify pid {} after the move",
                    pid
                )));
            }
        }
    }
    if let Some(how) = bad {
        if how == "was replaced" {
            let _ = fs::write(&src, format!("{}\n", pid));
        }
        log_line(
            layout,
            &format!(
                "{} uid={} pid={} REFUSED {} during move to /user/{}/{}",
                now_secs(),
                caller,
                pid,
                how,
                caller,
                rel
            ),
        );
        if how == "exited" {
            eprintln!("taema-attach: pid {} exited during move, skipped", pid);
            return Ok(());
        }
        return Err(refused(format!(
            "pid {} changed identity during the move (pid reuse); moved back",
            pid
        )));
    }
    log_line(
        layout,
        &format!(
            "{} uid={} pid={} comm={} from={} to=/user/{}/{}",
            now_secs(),
            caller,
            pid,
            comm,
            cg,
            caller,
            rel
        ),
    );
    Ok(())
}

/// Owned fd closed on drop, for the OOM paths with many exits.
struct FdGuard {
    fd: RawFd,
}

impl FdGuard {
    fn new(fd: RawFd) -> FdGuard {
        FdGuard { fd }
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

fn flock_ex(file: &fs::File) -> std::io::Result<()> {
    // SAFETY: flock on a live fd with LOCK_EX; EINTR retries.
    loop {
        let done = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if done == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

fn oom_identity_matches(pid: i64, caller: u32, expected_start: i64, pidfd: Option<RawFd>) -> bool {
    if pidfd.map(pidfd_gone).unwrap_or(false) {
        return false;
    }
    match pid_uid(pid).and_then(|owner| Ok((owner, starttime(pid)?))) {
        Ok((owner, start)) => owner == caller && start == expected_start,
        Err(_) => false,
    }
}

fn read_oom_score(pid: i64) -> Result<i64, Refused> {
    let raw = read_proc(pid, "oom_score_adj")
        .map_err(|_| refused("could not read OOM priority target"))?;
    let text =
        std::str::from_utf8(&raw).map_err(|_| refused("could not read OOM priority target"))?;
    let value: i64 = text
        .trim()
        .parse()
        .map_err(|_| refused("could not read OOM priority target"))?;
    if !(OOM_MIN..=OOM_MAX).contains(&value) {
        return Err(refused("OOM priority target is out of range"));
    }
    Ok(value)
}

/// Field order matches the Python record byte for byte.
#[derive(Debug, Clone, Copy)]
struct OomRecord {
    uid: u32,
    pid: i64,
    start: i64,
    original: i64,
    applied: i64,
    state: i64,
}

impl OomRecord {
    fn to_json(self) -> String {
        format!(
            "{{\"uid\":{},\"pid\":{},\"start\":{},\"original\":{},\"applied\":{},\"state\":{}}}",
            self.uid, self.pid, self.start, self.original, self.applied, self.state
        )
    }
}

fn oom_state_dir(layout: &Layout) -> Result<String, Refused> {
    let dir = &layout.oom_dir;
    let parent = Path::new(dir).parent().unwrap_or_else(|| Path::new("/"));
    let parent_meta = fs::metadata(parent).map_err(|e| {
        refused(format!(
            "OOM record directory unavailable: {}",
            io_message(&e)
        ))
    })?;
    if !parent_meta.is_dir()
        || parent_meta.mode() & 0o022 != 0
        || (!layout.test_mode && parent_meta.uid() != 0)
    {
        return Err(refused("OOM record parent is not a trusted root directory"));
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(refused(format!(
                "OOM record directory unavailable: {}",
                io_message(&e)
            )));
        }
    }
    let state = fs::symlink_metadata(dir).map_err(|e| {
        refused(format!(
            "OOM record directory unavailable: {}",
            io_message(&e)
        ))
    })?;
    if !state.is_dir() || (!layout.test_mode && state.uid() != 0) || state.mode() & 0o777 != 0o700 {
        return Err(refused(
            "OOM record directory must be root-owned and mode 0700",
        ));
    }
    Ok(dir.clone())
}

fn oom_record_path(directory: &str, caller: u32, pid: i64, expected_start: i64) -> String {
    format!("{}/{}-{}-{}.json", directory, caller, pid, expected_start)
}

fn validate_oom_record(file: &fs::File, layout: &Layout) -> Result<(), Refused> {
    let info = file
        .metadata()
        .map_err(|_| refused("OOM restoration record is not a private root-owned file"))?;
    if !info.is_file()
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
        || (!layout.test_mode && info.uid() != 0)
    {
        return Err(refused(
            "OOM restoration record is not a private root-owned file",
        ));
    }
    Ok(())
}

fn load_oom_record(
    layout: &Layout,
    path: &str,
    caller: u32,
    pid: i64,
    expected_start: i64,
) -> Result<Option<(fs::File, OomRecord)>, Refused> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(refused(format!(
                "could not open OOM restoration record: {}",
                io_message(&e)
            )));
        }
    };
    let result = (|| -> Result<OomRecord, Refused> {
        validate_oom_record(&file, layout)?;
        flock_ex(&file).map_err(|_| refused("could not read OOM restoration record"))?;
        let mut buf = vec![0u8; OOM_STATE_MAX + 1];
        let total = std::io::Read::read(&mut &file, &mut buf)
            .map_err(|_| refused("could not read OOM restoration record"))?;
        buf.truncate(total);
        if buf.len() > OOM_STATE_MAX {
            return Err(refused("OOM restoration record is too large"));
        }
        let text = std::str::from_utf8(&buf)
            .map_err(|_| refused("could not read OOM restoration record"))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| refused("could not read OOM restoration record"))?;
        let record = value
            .as_object()
            .ok_or_else(|| refused("OOM restoration record is invalid"))?;
        let field = |name: &str| -> Result<i64, Refused> {
            record
                .get(name)
                .and_then(|v| v.as_i64())
                .ok_or_else(|| refused("OOM restoration record identity is invalid"))
        };
        // as_i64 rejects bools, floats, and out-of-range numbers, as the
        // Python isinstance checks do.
        if field("uid")? != caller as i64
            || field("pid")? != pid
            || field("start")? != expected_start
        {
            return Err(refused("OOM restoration record identity is invalid"));
        }
        let original = record
            .get("original")
            .and_then(|v| v.as_i64())
            .unwrap_or(OOM_MIN - 1);
        let applied = record
            .get("applied")
            .and_then(|v| v.as_i64())
            .unwrap_or(OOM_MIN - 1);
        let state = record.get("state").and_then(|v| v.as_i64()).unwrap_or(-1);
        if !(OOM_MIN..=OOM_MAX).contains(&original)
            || !(OOM_MIN..=OOM_MAX).contains(&applied)
            || applied < original
            || (state != 0 && state != 1)
            || record.get("original").and_then(|v| v.as_i64()).is_none()
            || record.get("applied").and_then(|v| v.as_i64()).is_none()
            || record.get("state").and_then(|v| v.as_i64()).is_none()
        {
            return Err(refused("OOM restoration record values are invalid"));
        }
        Ok(OomRecord {
            uid: caller,
            pid,
            start: expected_start,
            original,
            applied,
            state,
        })
    })();
    match result {
        Ok(record) => Ok(Some((file, record))),
        Err(e) => Err(e),
    }
}

/// What `_write_oom_record` raises: an OSError the caller maps, or a Refused
/// that propagates unchanged.
enum WriteError {
    Io(std::io::Error),
    Refused(Refused),
}

impl From<Refused> for WriteError {
    fn from(error: Refused) -> WriteError {
        WriteError::Refused(error)
    }
}

fn write_oom_record(file: &fs::File, record: &OomRecord) -> Result<(), WriteError> {
    flock_ex(file).map_err(WriteError::Io)?;
    let data = record.to_json().into_bytes();
    use std::io::{Seek, SeekFrom};
    let mut handle = file;
    handle
        .seek(SeekFrom::Start(0))
        .map_err(|_| refused("could not write complete OOM restoration record"))?;
    let mut written = 0;
    while written < data.len() {
        match handle.write(&data[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(_) => return Err(refused("could not write complete OOM restoration record").into()),
        }
    }
    if written != data.len() {
        return Err(refused("could not write complete OOM restoration record").into());
    }
    handle
        .set_len(data.len() as u64)
        .map_err(|_| refused("could not write complete OOM restoration record"))?;
    handle
        .sync_all()
        .map_err(|_| refused("could not write complete OOM restoration record"))?;
    Ok(())
}

fn update_record(file: &fs::File, record: &OomRecord) -> Result<(), Refused> {
    write_oom_record(file, record).map_err(|error| match error {
        WriteError::Refused(message) => message,
        WriteError::Io(e) => refused(format!(
            "could not update OOM restoration record: {}",
            io_message(&e)
        )),
    })
}

fn prune_oom_records(layout: &Layout, directory: &str, caller: u32) -> Result<usize, Refused> {
    let prefix = format!("{}-", caller);
    let entries = fs::read_dir(directory)
        .map_err(|e| refused(format!("could not record OOM priority: {}", io_message(&e))))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|e| refused(format!("could not record OOM priority: {}", io_message(&e))))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    let mut count = 0;
    for name in names {
        if !name.starts_with(&prefix) || !name.ends_with(".json") {
            continue;
        }
        let parts: Vec<&str> = name[..name.len() - 5].split('-').collect();
        if parts.len() != 3 || !parts.iter().all(|p| is_ascii_digits(p)) {
            continue;
        }
        let uid: u32 = parts[0].parse().unwrap_or(u32::MAX);
        let pid: i64 = parts[1].parse().unwrap_or(-1);
        let start: i64 = parts[2].parse().unwrap_or(-1);
        if uid != caller {
            continue;
        }
        let path = format!("{}/{}", directory, name);
        let info = match fs::symlink_metadata(&path) {
            Ok(info) => info,
            Err(_) => {
                let _ = fs::remove_file(&path);
                continue;
            }
        };
        if !info.is_file()
            || info.mode() & 0o077 != 0
            || info.nlink() != 1
            || (!layout.test_mode && info.uid() != 0)
        {
            return Err(refused(
                "OOM restoration record is not a private root-owned file",
            ));
        }
        let stale = match starttime(pid).and_then(|actual| Ok((actual, pid_uid(pid)?))) {
            Ok((actual, owner)) => actual != start || owner != caller,
            Err(_) => true,
        };
        if stale {
            let _ = fs::remove_file(&path);
            continue;
        }
        count += 1;
    }
    Ok(count)
}

fn pidfd_or_refused(pid: i64) -> Result<FdGuard, Refused> {
    if pid > i32::MAX as i64 {
        return Err(refused(format!(
            "pidfd_open({}) failed: Numerical result out of range",
            pid
        )));
    }
    // SAFETY: pidfd_open with flags 0 either returns a fresh fd or -1.
    let fd = pidfd_open_sys(pid as libc::pid_t, 0);
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return Err(refused("OOM priority target is gone"));
        }
        return Err(refused(format!(
            "pidfd_open({}) failed: {}",
            pid,
            strerror(errno)
        )));
    }
    Ok(FdGuard::new(fd))
}

fn restore_oom(
    layout: &Layout,
    pid: i64,
    caller: u32,
    expected_start: i64,
    value: i64,
    applied: i64,
) -> Result<(), Refused> {
    if pid <= 1
        || caller == 0
        || expected_start <= 0
        || !(OOM_MIN..=OOM_MAX).contains(&value)
        || !(value..=OOM_MAX).contains(&applied)
    {
        return Err(refused("invalid OOM priority restore target"));
    }
    let pidfd = pidfd_or_refused(pid)?;
    if !oom_identity_matches(pid, caller, expected_start, None) {
        return Err(refused("OOM priority target changed identity"));
    }
    let record_path =
        oom_state_dir(layout).map(|dir| oom_record_path(&dir, caller, pid, expected_start))?;
    let (record_file, mut record) =
        match load_oom_record(layout, &record_path, caller, pid, expected_start)? {
            Some(pair) => pair,
            None => return Err(refused("OOM priority restore was not recorded")),
        };
    if value != record.original {
        return Err(refused("OOM priority value was not recorded"));
    }
    if applied != record.applied {
        return Err(refused("applied OOM priority was not recorded"));
    }
    if applied < record.original {
        return Err(refused(
            "OOM priority restore would lower the original value",
        ));
    }
    let target = match fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(format!("/proc/{}/oom_score_adj", pid))
    {
        Ok(file) => file,
        Err(e) if gone_error(&e) => return Err(refused("OOM priority target is gone")),
        Err(e) => {
            return Err(refused(format!(
                "could not open OOM priority target: {}",
                io_message(&e)
            )));
        }
    };
    if !oom_identity_matches(pid, caller, expected_start, Some(pidfd.fd)) {
        return Err(refused("OOM priority target changed identity"));
    }
    let current = read_oom_score(pid)?;
    if current == record.original {
        if record.state == 0 {
            record.state = 1;
            update_record(&record_file, &record)?;
        }
        return Ok(());
    }
    if record.state == 1 {
        return Err(refused("OOM priority restoration was already completed"));
    }
    if current != record.applied {
        return Err(refused("current OOM priority is not the recorded value"));
    }
    {
        let mut handle = &target;
        let data = format!("{}\n", value).into_bytes();
        let mut written = 0;
        while written < data.len() {
            match handle.write(&data[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) if gone_error(&e) => {
                    return Err(refused("OOM priority target is gone"));
                }
                Err(e) => {
                    return Err(refused(format!(
                        "could not restore OOM priority: {}",
                        io_message(&e)
                    )));
                }
            }
        }
        if written != data.len() {
            return Err(refused("could not restore complete OOM priority value"));
        }
    }
    record.state = 1;
    update_record(&record_file, &record)?;
    log_line(
        layout,
        &format!(
            "{} uid={} pid={} oom_score_adj={} RESTORED",
            now_secs(),
            caller,
            pid,
            value
        ),
    );
    Ok(())
}

fn record_oom(
    layout: &Layout,
    pid: i64,
    caller: u32,
    expected_start: i64,
    original: i64,
    applied: i64,
) -> Result<(), Refused> {
    if pid <= 1
        || caller == 0
        || expected_start <= 0
        || !(OOM_MIN..=OOM_MAX).contains(&original)
        || applied <= original
        || applied > OOM_MAX
    {
        return Err(refused("invalid OOM priority record"));
    }
    let pidfd = pidfd_or_refused(pid)?;
    if !oom_identity_matches(pid, caller, expected_start, Some(pidfd.fd)) {
        return Err(refused("OOM priority target changed identity"));
    }
    let directory = oom_state_dir(layout)?;
    let count = prune_oom_records(layout, &directory, caller)?;
    let path = oom_record_path(&directory, caller, pid, expected_start);
    let current = read_oom_score(pid)?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => {
            let result = (|| -> Result<(), Refused> {
                flock_ex(&file).map_err(|e| {
                    refused(format!("could not record OOM priority: {}", io_message(&e)))
                })?;
                validate_oom_record(&file, layout)?;
                if count >= OOM_RECORD_LIMIT {
                    return Err(refused("too many outstanding OOM priority records"));
                }
                if current != original {
                    return Err(refused(
                        "OOM priority original does not match the live value",
                    ));
                }
                let record = OomRecord {
                    uid: caller,
                    pid,
                    start: expected_start,
                    original,
                    applied,
                    state: 0,
                };
                let data = record.to_json().into_bytes();
                let mut handle = &file;
                let mut written = 0;
                while written < data.len() {
                    match std::io::Write::write(&mut handle, &data[written..]) {
                        Ok(0) => break,
                        Ok(n) => written += n,
                        Err(_) => {
                            return Err(refused("could not write complete OOM priority record"));
                        }
                    }
                }
                if written != data.len() {
                    return Err(refused("could not write complete OOM priority record"));
                }
                handle
                    .sync_all()
                    .map_err(|_| refused("could not write complete OOM priority record"))?;
                Ok(())
            })();
            drop(file);
            if result.is_err() {
                let _ = fs::remove_file(&path);
            }
            result?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let (existing_file, mut existing) =
                match load_oom_record(layout, &path, caller, pid, expected_start)? {
                    Some(pair) => pair,
                    None => return Err(refused("conflicting OOM priority record exists")),
                };
            if existing.original != original {
                return Err(refused("conflicting OOM priority record exists"));
            }
            if current == original {
                existing.applied = applied;
                existing.state = 0;
                write_oom_record(&existing_file, &existing).map_err(|error| match error {
                    WriteError::Refused(message) => message,
                    WriteError::Io(e) => {
                        refused(format!("could not record OOM priority: {}", io_message(&e)))
                    }
                })?;
                return Ok(());
            }
            if current == applied && existing.applied == applied && existing.state == 0 {
                return Ok(());
            }
            return Err(refused(
                "OOM priority original does not match the live value",
            ));
        }
        Err(e) => {
            return Err(refused(format!(
                "could not create OOM priority record: {}",
                io_message(&e)
            )));
        }
    }
    if !oom_identity_matches(pid, caller, expected_start, Some(pidfd.fd)) {
        let _ = fs::remove_file(&path);
        return Err(refused("OOM priority target changed identity"));
    }
    log_line(
        layout,
        &format!(
            "{} uid={} pid={} oom_score_adj={}->{} RECORDED",
            now_secs(),
            caller,
            pid,
            original,
            applied
        ),
    );
    Ok(())
}

fn parse_saturating(text: &str) -> i64 {
    // Python ints are unbounded; saturate so the range checks below produce
    // the same refusal the unbounded value would.
    text.parse::<i64>().unwrap_or_else(|_| {
        if text.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        }
    })
}

fn run(argv: &[String], layout: &Layout) -> Result<(), Refused> {
    // SAFETY: geteuid/getuid take no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let sudo_uid = std::env::var("SUDO_UID").unwrap_or_default();
    let caller: u32 = if layout.test_mode {
        if sudo_uid.is_empty() {
            unsafe { libc::getuid() }
        } else if !is_ascii_digits(&sudo_uid) {
            return Err(refused("run through sudo"));
        } else {
            sudo_uid.parse::<u32>().unwrap_or(u32::MAX)
        }
    } else {
        if euid != 0 || !is_ascii_digits(&sudo_uid) {
            return Err(refused("run through sudo"));
        }
        sudo_uid.parse::<u32>().unwrap_or(u32::MAX)
    };
    if caller == 0 {
        return Err(refused("refusing uid 0"));
    }
    if argv.len() == 5 && argv[0] == "oom-restore" {
        if !is_ascii_digits(&argv[1]) || !is_ascii_digits(&argv[2]) {
            return Err(refused("bad OOM priority target"));
        }
        if !is_ascii_int(&argv[3]) {
            return Err(refused("bad OOM priority value"));
        }
        if !is_ascii_int(&argv[4]) {
            return Err(refused("bad applied OOM priority value"));
        }
        let pid = parse_saturating(&argv[1]);
        let expected_start = parse_saturating(&argv[2]);
        let value = parse_saturating(&argv[3]);
        let applied = parse_saturating(&argv[4]);
        if pid <= 1 || expected_start <= 0 || !(OOM_MIN..=OOM_MAX).contains(&value) {
            return Err(refused("bad OOM priority target or value"));
        }
        if !(value..=OOM_MAX).contains(&applied) {
            return Err(refused("bad applied OOM priority value"));
        }
        restore_oom(layout, pid, caller, expected_start, value, applied)?;
        return Ok(());
    }
    if argv.len() == 5 && argv[0] == "oom-record" {
        if !is_ascii_digits(&argv[1]) || !is_ascii_digits(&argv[2]) {
            return Err(refused("bad OOM priority record target"));
        }
        if !is_ascii_int(&argv[3]) || !is_ascii_int(&argv[4]) {
            return Err(refused("bad OOM priority record value"));
        }
        let pid = parse_saturating(&argv[1]);
        let expected_start = parse_saturating(&argv[2]);
        let original = parse_saturating(&argv[3]);
        let applied = parse_saturating(&argv[4]);
        if pid <= 1
            || expected_start <= 0
            || !(OOM_MIN..=OOM_MAX).contains(&original)
            || applied <= original
            || applied > OOM_MAX
        {
            return Err(refused("bad OOM priority record target or values"));
        }
        record_oom(layout, pid, caller, expected_start, original, applied)?;
        return Ok(());
    }
    let (rel, pids): (String, &[String]) = if argv.len() == 3 && argv[0] == "attach" {
        if !valid_name(&argv[2]) {
            return Err(refused("bad name"));
        }
        (format!("scope-{}", argv[2]), &argv[1..2])
    } else if argv.len() >= 3 && argv[0] == "move" {
        (argv[1].clone(), &argv[2..])
    } else {
        return Err(refused(
            "usage: taema-attach attach PID NAME | move RELPATH PID... | \
             oom-record PID START ORIGINAL APPLIED | \
             oom-restore PID START ORIGINAL APPLIED",
        ));
    };
    if !valid_rel(&rel) {
        return Err(refused("bad path"));
    }
    let dest = format!("{}/user/{}/{}", layout.cg, caller, rel);
    let meta = match fs::metadata(&dest) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused(format!("no such scope: {}", rel)));
        }
        Err(e) => {
            return Err(refused(format!(
                "cannot inspect scope {}: {}",
                rel,
                io_message(&e)
            )));
        }
    };
    let is_link = fs::symlink_metadata(&dest)
        .map(|m| m.is_symlink())
        .unwrap_or(false);
    if meta.uid() != caller || is_link {
        return Err(refused(format!("scope not owned by uid {}", caller)));
    }
    let rules = load_rules(layout, None)?;
    for pid_text in pids {
        if !is_ascii_digits(pid_text) {
            return Err(refused("bad pid"));
        }
        move_one(
            layout,
            parse_saturating(pid_text),
            caller,
            &rel,
            &dest,
            &rules,
        )?;
    }
    Ok(())
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let layout = Layout::load();
    match run(&argv, &layout) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("taema-attach: {}", message);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_validation_matches() {
        assert!(valid_rel("scope-x"));
        assert!(valid_rel("a"));
        assert!(valid_rel(&"a".repeat(97)));
        assert!(valid_rel("shared/x-1.2_3"));
        assert!(!valid_rel(""));
        assert!(!valid_rel(&"a".repeat(98)));
        assert!(!valid_rel("UPPER"));
        assert!(!valid_rel("../x"));
        assert!(!valid_rel("a//b"));
        assert!(!valid_rel("/a"));
        assert!(!valid_rel("a/"));
        assert!(!valid_rel("a/./b"));
        assert!(!valid_rel("a/../b"));
        assert!(!valid_rel("-a"));
        assert!(!valid_rel("a b"));
        assert!(!valid_rel("é"));
    }

    #[test]
    fn name_validation_matches() {
        assert!(valid_name("x"));
        assert!(valid_name("abc-123_xyz"));
        assert!(valid_name(&"a".repeat(32)));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(33)));
        assert!(!valid_name("Upper"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name("a.b"));
        assert!(!valid_name("-a"));
    }

    #[test]
    fn session_cgroup_matches() {
        assert!(is_session_cg("/2"));
        assert!(is_session_cg("/123/x.slice/y"));
        assert!(is_session_cg("/2/"));
        assert!(!is_session_cg("/"));
        assert!(!is_session_cg("2"));
        assert!(!is_session_cg("/user/1000/x"));
        assert!(!is_session_cg(""));
        assert!(!is_session_cg("/x"));
    }

    #[test]
    fn int_shapes_match() {
        assert!(is_ascii_digits("0"));
        assert!(is_ascii_digits("007"));
        assert!(!is_ascii_digits(""));
        assert!(!is_ascii_digits("-1"));
        assert!(!is_ascii_digits("1 "));
        assert!(!is_ascii_digits("²"));
        assert!(is_ascii_int("0"));
        assert!(is_ascii_int("-0"));
        assert!(is_ascii_int("-1000"));
        assert!(!is_ascii_int(""));
        assert!(!is_ascii_int("-"));
        assert!(!is_ascii_int("--1"));
        assert!(!is_ascii_int("1-"));
    }

    #[test]
    fn glob_matches_fnmatch() {
        let cases = [
            ("python3", "python*", true),
            ("python3", "python?", true),
            ("python3", "python??", false),
            ("ab", "a?b", false),
            ("axb", "a?b", true),
            ("anything", "*", true),
            ("", "*", true),
            ("", "?", false),
            ("abc", "a*c", true),
            ("ac", "a*c", true),
            ("axyc", "a*c", true),
            ("axyd", "a*c", false),
            ("a", "[abc]", true),
            ("d", "[abc]", false),
            ("d", "[!abc]", true),
            ("a", "[!abc]", false),
            ("m", "[a-z]", true),
            ("5", "[a-z]", false),
            ("5", "[0-9]", true),
            ("]", "[]]", true),
            ("[", "[", true),
            ("x", "[", false),
            ("a[b", "a[b", true),
            ("a", "[z-a]", false),
            ("-", "[z-a]", false),
            ("z", "[z-a]", false),
            ("\\", "[\\\\]", true),
            ("d", "[\\d]", true),
            ("5", "[\\d]", false),
            ("-", "[a-b-c]", true),
            ("c", "[a-b-c]", true),
            ("d", "[a-b-c]", false),
            ("b", "[a\\-z]", true),
            ("-", "[a\\-z]", false),
            ("-", "[--0]", true),
            ("0", "[--0]", true),
            ("a", "[--0]", false),
            ("x", "[!b-a]", true),
            ("[unclosed", "[unclosed", true),
            ("[", "[unclosed", false),
        ];
        for (name, pattern, expected) in cases {
            assert_eq!(
                fnmatchcase(name, pattern),
                Some(expected),
                "{:?} {:?}",
                name,
                pattern
            );
        }
    }

    #[test]
    fn record_json_is_compact_and_ordered() {
        let record = OomRecord {
            uid: 1000,
            pid: 42,
            start: 987,
            original: -200,
            applied: 500,
            state: 0,
        };
        assert_eq!(
            record.to_json(),
            "{\"uid\":1000,\"pid\":42,\"start\":987,\"original\":-200,\"applied\":500,\"state\":0}"
        );
    }

    #[test]
    fn string_list_mirrors_typing() {
        assert_eq!(string_list(None), Some(Vec::new()));
        let array = toml::Value::Array(vec!["a".into(), "b".into()]);
        assert_eq!(
            string_list(Some(&array)),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        let text: toml::Value = "ab".into();
        assert_eq!(
            string_list(Some(&text)),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        let number: toml::Value = 5.into();
        assert_eq!(string_list(Some(&number)), None);
        let mixed = toml::Value::Array(vec!["a".into(), 5.into()]);
        assert_eq!(string_list(Some(&mixed)), None);
    }
}
