//! EDR userland service — console app.
//!
//! Receives sensor event batches, feeds them to the detection engine, prints the
//! per-event ALLOW/DENY decision (plus the backend-reconstructed chain on a block),
//! and returns the batch's block decision to the sensor.
//!
//!   edr-endpoint-service                 # built-in LSASS-dump demo (works with no driver)
//!   edr-endpoint-service --file dump.bin # replay batches captured from the driver
//!   edr-endpoint-service --stdin         # read batches from stdin
//!   edr-endpoint-service --port \SnsDrvPort   # (Windows) live minifilter connection
//!   edr-endpoint-service --rules r.rules ...  # override the rule set
//!   edr-endpoint-service --backend 127.0.0.1:7171  # ship events to the backend service
//!                                         # (storylines render on its console)

use edr_endpoint_service::{sensor, source, Service, SERVICE_RULES};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use source::{EventSource, ReaderSource, VecSource};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut rules_path: Option<String> = None;
    let mut backend_addr: Option<String> = None;
    let mut mode = Mode::Demo;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rules" => {
                i += 1;
                rules_path = args.get(i).cloned();
            }
            "--backend" => {
                i += 1;
                backend_addr = args.get(i).cloned();
                if backend_addr.is_none() {
                    eprintln!("--backend cần địa chỉ, ví dụ --backend 127.0.0.1:7171");
                    return ExitCode::from(2);
                }
            }
            "--file" => {
                i += 1;
                mode = Mode::File(args.get(i).cloned().unwrap_or_default());
            }
            "--stdin" => mode = Mode::Stdin,
            "--port" => {
                let name = args.get(i + 1).filter(|s| !s.starts_with("--")).cloned();
                if name.is_some() {
                    i += 1;
                }
                mode = Mode::Port(name.unwrap_or_else(|| "\\SnsDrvPort".to_string()));
            }
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown arg '{}'", other);
                print_help();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let rules = match &rules_path {
        Some(p) => match fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read rules {}: {}", p, e);
                return ExitCode::from(2);
            }
        },
        None => SERVICE_RULES.to_string(),
    };

    let mut svc = match Service::with_rules(&rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rule error: {}", e);
            return ExitCode::from(2);
        }
    };

    // Banner FIRST — before any (possibly slow or failing) connect — and flushed,
    // so a stall/failure in the port or backend connect can never look like a silent
    // early exit with no output at all.
    println!(
        "edr-endpoint-service · mode = {} · rules = {} · backend = {}",
        mode_label(&mode),
        rules_path.as_deref().unwrap_or("<mặc định + lsass>"),
        backend_addr.as_deref().unwrap_or("<in-process>")
    );
    let _ = io::stdout().flush();

    // Uplink to the backend service (connect BEFORE opening the sensor port, and with
    // a bounded timeout, so an unreachable/absent backend fails fast and loud instead
    // of hanging silently). When attached, every outbox record (telemetry + BlockReport
    // alerts) is shipped there and the storyline renders on ITS console.
    let mut uplink: Option<Uplink> = None;
    if let Some(addr) = &backend_addr {
        print!("  → connecting backend {} ... ", addr);
        let _ = io::stdout().flush();
        match connect_backend(addr) {
            Ok(s) => {
                println!("ok");
                svc.remote = true;
                uplink = Some(Uplink::new(addr.clone(), s));
            }
            Err(e) => {
                println!("FAILED");
                eprintln!("cannot connect backend {}: {} — hãy chạy edr-backend-service trước.", addr, e);
                return ExitCode::from(2);
            }
        }
    }

    print!("  → opening source ... ");
    let _ = io::stdout().flush();
    let mut src: Box<dyn EventSource> = match build_source(mode) {
        Ok(s) => {
            println!("{}", s.name());
            s
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("source error: {}", e);
            return ExitCode::from(2);
        }
    };
    println!("  ⌛ chờ event từ sensor (Ctrl+C để dừng) ...\n");
    let _ = io::stdout().flush();

    let mut batches = 0u64;
    loop {
        let payload = match src.next_batch() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) => {
                eprintln!("read error: {}", e);
                return ExitCode::from(1);
            }
        };
        batches += 1;
        let out = match svc.process_batch(&payload) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("decode error: {}", e);
                continue;
            }
        };
        println!(
            "[frame {}] {} event → engine (+{} state-only):",
            batches,
            out.outcomes.len(),
            out.state_only
        );
        for o in &out.outcomes {
            println!("{}", o.line);
        }
        for c in &out.chains {
            println!("\n{}", edr_engine::render_chain(c));
        }
        // Reply to the sensor FIRST — before the backend ship below. On the
        // synchronous enforcement path the driver blocks the filtered operation
        // waiting for this verdict under a short timeout; it must not sit behind a
        // backend TCP round-trip (that overran the timeout → "send timeout" on the
        // sensor and a fail-open). Async telemetry frames expect no reply.
        if sensor::expects_reply(&payload) {
            println!("  ⇒ verdict gửi sensor (sync enforce): {}", if out.deny { "BLOCK" } else { "ALLOW" });
            if let Err(e) = src.reply(out.deny) {
                eprintln!("reply error: {}", e);
            }
        } else if out.deny {
            println!("  ⇒ (async) đã DENY — báo cáo, sự kiện không chặn inline");
        }
        // Push the arm deltas down to the sensor so only these identities enforce inline.
        for a in &out.arms {
            match a {
                edr_engine::ArmCmd::Arm { actor, op } => {
                    println!("  ⇄ ARM    → sensor: {:?} {:?} (từ giờ chặn đồng bộ)", actor, op)
                }
                edr_engine::ArmCmd::Disarm { actor } => {
                    println!("  ⇄ DISARM → sensor: {:?} (trả về async)", actor)
                }
            }
        }
        if !out.arms.is_empty() {
            let frame = edr_endpoint_service::control::encode_frame(&out.arms);
            if let Err(e) = src.push_control(&frame) {
                eprintln!("push control error: {}", e);
            }
        }
        // Ship the outbox to the backend service LAST (off the enforcement path).
        // The uplink reconnects on its own if the backend drops; frames that can't
        // be shipped right now are silently dropped (never buffered unboundedly),
        // and shipping resumes when the backend is back.
        if let Some(up) = uplink.as_mut() {
            let mut sent = 0usize;
            let mut alerts = 0usize;
            for w in &out.wire {
                if matches!(w, edr_engine::wire::Wire::Block(_)) {
                    alerts += 1;
                }
                if up.ship(&edr_proto::encode_frame(w)) {
                    sent += 1;
                }
            }
            if sent > 0 {
                println!(
                    "  ⇡ ship {} record → backend{}",
                    sent,
                    if alerts > 0 {
                        format!(" (kèm {} ALERT — chuỗi hiển thị bên console backend)", alerts)
                    } else {
                        String::new()
                    }
                );
            }
        }
        println!();
    }

    println!(
        "--- tổng kết: {} frame · {} event vào engine · {} DENY ---",
        batches, svc.events_seen, svc.denies
    );
    ExitCode::SUCCESS
}

enum Mode {
    Demo,
    File(String),
    Stdin,
    Port(String),
}

fn mode_label(m: &Mode) -> String {
    match m {
        Mode::Demo => "demo".to_string(),
        Mode::Stdin => "stdin".to_string(),
        Mode::File(p) => format!("file:{}", p),
        Mode::Port(n) => format!("port:{}", n),
    }
}

/// Connect to the backend with a bounded timeout so an absent/filtered backend
/// fails in seconds with a clear error instead of hanging (or looking like a
/// silent exit). Resolves host:port and tries each address.
fn connect_backend(addr: &str) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last = io::Error::new(io::ErrorKind::Other, "no address resolved");
    for sa in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
            Ok(s) => {
                // Bound each write so a truly stuck backend can never wedge the event
                // loop, but keep it generous (10s) so a brief backend hiccup — e.g. a
                // slow console write — does not trigger a spurious drop/reconnect. On
                // a write error we drop and reconnect (below).
                let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Resilient uplink to the backend service: ships frames, and on any write error
/// (drop, reset, or write-timeout) it abandons the socket and reconnects on its own
/// — throttled — so a flaky/slow backend never wedges or permanently detaches the
/// endpoint. Telemetry produced while disconnected is dropped (bounded: we never
/// block the event loop or buffer unboundedly); shipping resumes on reconnect.
struct Uplink {
    addr: String,
    stream: Option<TcpStream>,
    next_retry: Instant,
    down_since_logged: bool,
}

impl Uplink {
    fn new(addr: String, stream: TcpStream) -> Uplink {
        Uplink { addr, stream: Some(stream), next_retry: Instant::now(), down_since_logged: false }
    }

    /// Ship one framed message. Returns true if it went out. On failure the socket
    /// is dropped and a (throttled) reconnect is attempted on subsequent calls.
    fn ship(&mut self, bytes: &[u8]) -> bool {
        if self.stream.is_none() {
            self.try_reconnect();
        }
        if let Some(s) = self.stream.as_mut() {
            if s.write_all(bytes).is_err() {
                // Abandon the (possibly half-written) socket; a fresh connection
                // starts the backend cleanly with no frame desync.
                self.stream = None;
                self.next_retry = Instant::now() + Duration::from_secs(2);
                if !self.down_since_logged {
                    eprintln!("  ⚠ mất kết nối backend {} — sẽ tự nối lại, telemetry tạm bỏ", self.addr);
                    self.down_since_logged = true;
                }
                return false;
            }
            return true;
        }
        false
    }

    fn try_reconnect(&mut self) {
        if self.stream.is_some() || Instant::now() < self.next_retry {
            return;
        }
        self.next_retry = Instant::now() + Duration::from_secs(2);
        if let Ok(s) = connect_backend(&self.addr) {
            println!("  ⇡ backend {} đã nối lại", self.addr);
            self.stream = Some(s);
            self.down_since_logged = false;
        }
    }
}

fn build_source(mode: Mode) -> io::Result<Box<dyn EventSource>> {
    match mode {
        Mode::Demo => Ok(Box::new(VecSource::new(demo_batches()))),
        Mode::Stdin => Ok(Box::new(ReaderSource::new(io::stdin(), "stdin"))),
        Mode::File(p) => {
            let f = fs::File::open(&p)?;
            Ok(Box::new(ReaderSource::new(f, p)))
        }
        Mode::Port(name) => connect_port(name),
    }
}

#[cfg(windows)]
fn connect_port(name: String) -> io::Result<Box<dyn EventSource>> {
    Ok(Box::new(edr_endpoint_service::winport::WinPortSource::connect(&name)?))
}

#[cfg(not(windows))]
fn connect_port(_name: String) -> io::Result<Box<dyn EventSource>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "--port chỉ hỗ trợ trên Windows (kết nối minifilter). Dùng --demo/--file/--stdin để thử.",
    ))
}

/// Built-in LSASS credential-dump scenario, using the sensor's real event types.
/// Sequence: enumerate lsass (state-only) → exec mimikatz → mimikatz opens lsass
/// with VM_READ. Mirrors the live driver: one frame per event, sent as it occurs
/// (no batching); every record carries identity + target image inline.
fn demo_batches() -> Vec<Vec<u8>> {
    vec![
        // Startup enumeration (informational only under v2).
        sensor::build_batch(&[sensor::enc_process_exist(
            10_000_000,
            50,
            9_000_000,
            r"C:\Windows\System32\lsass.exe",
        )]),
        // The attack: exec mimikatz...
        sensor::build_batch(&[sensor::enc_process_create(
            20_000_000,
            800,
            100,
            5_000_000, // parent (pid 100) create time
            r"C:\Tools\mimikatz.exe",
            "sekurlsa::logonpasswords",
        )]),
        // ...then read LSASS memory. The driver sends an lsass open on the
        // synchronous enforcement path (reply expected), so the service replies a
        // BLOCK verdict inline — exactly what the real driver waits on.
        sensor::build_frame(
            &[sensor::enc_process_open(
                21_000_000,
                800,
                20_000_000, // mimikatz create time (== its exec ts)
                50,
                9_000_000, // lsass create time
                0x0010,    /* PROCESS_VM_READ */
                r"C:\Windows\System32\lsass.exe",
            )],
            true,
        ),
    ]
}

fn print_help() {
    println!(
        "edr-endpoint-service — cầu nối sensor(kernel) ↔ engine, trả quyết định chặn.\n\
         \n  --demo            (mặc định) kịch bản LSASS-dump dựng sẵn, chạy không cần driver\
         \n  --file <path>     đọc batch nhị phân đã bắt từ driver\
         \n  --stdin           đọc batch từ stdin\
         \n  --port [\\SnsDrvPort]  (Windows) kết nối minifilter trực tiếp\
         \n  --rules <file>    nạp bộ rule khác (mặc định: builtin + lsass)\
         \n  --backend <addr>  ship event + alert lên backend service (edr-backend-service);\
         \n                    storyline sẽ hiển thị trên console của backend\
         "
    );
}
