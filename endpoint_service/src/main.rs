//! EDR userland service — console app.
//!
//! Receives sensor event batches, feeds them to the detection engine, prints the
//! per-event ALLOW/DENY decision (plus the backend-reconstructed chain on a block),
//! and returns the batch's block decision to the sensor.
//!
//! By default it connects to the live sensor `--com-port` (\SnsDrvPort) and ships
//! telemetry + alerts to the backend at `--remote-addr` (127.0.0.1:7171). Override
//! the source with `--file`/`--stdin`/`--demo`, or keep the backend in-process with
//! `--in-process`. See `--help`.

use clap::Parser;
use edr_endpoint_service::{sensor, source, Service, SERVICE_RULES};
use std::fs;
use std::io::{self, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use edr_engine::wire::Wire;
use log::{debug, error, info, warn};
use source::{EventSource, ReaderSource, VecSource};

/// Bounded backend-ship queue. Full ⇒ the backend is behind/down and we drop
/// (telemetry is best-effort) rather than block or back-pressure the event loop.
const SHIP_QUEUE_CAP: usize = 8192;

/// Init the `log` backend (env_logger). Level filter comes from `RUST_LOG`
/// (default `info`), so per-event **debug** (no automaton matched) is hidden unless
/// asked for, while **info** (matched) / **warn** (chain completed) show by default.
fn init_logger() {
    use std::io::Write as _;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "[{} {:<5}] {}", ts_now(), record.level(), record.args()))
        .init();
}

/// EDR endpoint service — bridges the kernel sensor to the detection engine and
/// ships telemetry + alerts to the backend.
#[derive(Parser, Debug)]
#[command(name = "edr-endpoint-service", version, about, long_about = None)]
struct Args {
    /// Sensor communication port (Windows minifilter) — the default live source.
    #[arg(long, default_value = r"\SnsDrvPort")]
    com_port: String,

    /// Sensor transport. `ring` (default) takes telemetry from a shared-memory ring
    /// the driver maps into us and never enters the kernel on the hot path; `port`
    /// is the older one-message-per-event path, kept as a fallback for a driver that
    /// predates the ring. Both use the same port for control and verdicts.
    #[arg(long, value_enum, default_value_t = Transport::Ring)]
    transport: Transport,

    /// Backend service address to ship telemetry + alerts to.
    #[arg(long, default_value = "127.0.0.1:7171")]
    remote_addr: String,

    /// Run the backend in-process instead of shipping to `--remote-addr`.
    #[arg(long)]
    in_process: bool,

    /// Override the rule set (path to a .rules file; default: builtin + lsass).
    #[arg(long, value_name = "FILE")]
    rules: Option<String>,

    /// Replace the live source: replay a binary batch dump captured from the driver.
    #[arg(long, value_name = "FILE", group = "source")]
    file: Option<String>,

    /// Replace the live source: read batches from stdin.
    #[arg(long, group = "source")]
    stdin: bool,

    /// Replace the live source: built-in LSASS-dump demo (runs with no driver).
    #[arg(long, group = "source")]
    demo: bool,

    /// Replace the live source: generate N synthetic events and ship them (no driver).
    /// A loopback stress test to isolate transport issues from the sensor path.
    #[arg(long, value_name = "N", group = "source")]
    stress: Option<u64>,
}

fn main() -> ExitCode {
    init_logger();
    let args = Args::parse();

    // Source: an explicit override wins, else the live sensor com-port (default).
    let mode = if let Some(f) = args.file {
        Mode::File(f)
    } else if args.stdin {
        Mode::Stdin
    } else if args.demo {
        Mode::Demo
    } else if let Some(n) = args.stress {
        Mode::Stress(n)
    } else {
        Mode::Port(args.com_port, args.transport)
    };
    // Backend: remote by default, in-process on request.
    let backend_addr = if args.in_process { None } else { Some(args.remote_addr) };
    let rules_path = args.rules;

    let rules = match &rules_path {
        Some(p) => match fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot read rules {}: {}", p, e);
                return ExitCode::from(2);
            }
        },
        None => SERVICE_RULES.to_string(),
    };

    let mut svc = match Service::with_rules(&rules) {
        Ok(s) => s,
        Err(e) => {
            error!("rule error: {}", e);
            return ExitCode::from(2);
        }
    };

    info!(
        "edr-endpoint-service · mode = {} · rules = {} · backend = {}",
        mode_label(&mode),
        rules_path.as_deref().unwrap_or("<mặc định + lsass>"),
        backend_addr.as_deref().unwrap_or("<in-process>")
    );

    // The backend uplink runs on its OWN thread. The sensor event loop (thread 1)
    // only feeds the engine and *enqueues* frames into a bounded channel; the shipper
    // (thread 2) drains it, writes to the backend, and reconnects on its own. So a
    // slow/flaky/down backend can never block or back-pressure the enforcement path.
    // Connect BEFORE opening the sensor port and with a bounded timeout, so an absent
    // backend fails fast and loud instead of hanging.
    let mut ship_tx: Option<SyncSender<Wire>> = None;
    let mut ship_handle: Option<thread::JoinHandle<()>> = None;
    if let Some(addr) = &backend_addr {
        info!("connecting backend {} ...", addr);
        match connect_backend(addr) {
            Ok(s) => {
                info!("backend {} connected (shipper thread)", addr);
                svc.remote = true;
                let (tx, rx) = sync_channel::<Wire>(SHIP_QUEUE_CAP);
                let uplink = Uplink::new(addr.clone(), s);
                ship_handle = Some(thread::spawn(move || shipper_loop(uplink, rx)));
                ship_tx = Some(tx);
            }
            Err(e) => {
                error!("cannot connect backend {}: {} — hãy chạy edr-backend-service trước.", addr, err_detail(&e));
                return ExitCode::from(2);
            }
        }
    }

    let mut src: Box<dyn EventSource> = match build_source(mode) {
        Ok(s) => {
            info!("source mở: {}", s.name());
            s
        }
        Err(e) => {
            error!("source error: {}", e);
            return ExitCode::from(2);
        }
    };
    info!("chờ event từ sensor (Ctrl+C để dừng) ...");

    let mut batches = 0u64;
    loop {
        let payload = match src.next_batch() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) => {
                error!("read error: {}", err_detail(&e));
                return ExitCode::from(1);
            }
        };
        batches += 1;
        let out = match svc.process_batch(&payload) {
            Ok(o) => o,
            Err(e) => {
                error!("decode error: {}", e);
                continue;
            }
        };
        debug!("[frame {}] {} event → engine (+{} state-only)", batches, out.outcomes.len(), out.state_only);
        // Per-event log level by the event's relation to the detection automata:
        //   completed a chain → warn · matched/advanced an automaton → info · no match → debug
        for o in &out.outcomes {
            let line = o.line.trim_start();
            if o.completed || o.deny {
                warn!("{}", line);
            } else if o.advanced {
                info!("{}", line);
            } else {
                debug!("{}", line);
            }
        }
        for c in &out.chains {
            warn!("chuỗi dựng lại:\n{}", edr_engine::render_chain(c));
        }
        // Reply to the sensor FIRST — before the backend ship below. On the
        // synchronous enforcement path the driver blocks the filtered operation
        // waiting for this verdict under a short timeout; it must not sit behind a
        // backend TCP round-trip (that overran the timeout → "send timeout" on the
        // sensor and a fail-open). Async telemetry frames expect no reply.
        if sensor::expects_reply(&payload) {
            if out.deny {
                warn!("verdict → sensor (sync enforce): BLOCK");
            } else {
                info!("verdict → sensor (sync enforce): ALLOW");
            }
            if let Err(e) = src.reply(out.deny) {
                error!("reply error: {}", err_detail(&e));
            }
        } else if out.deny {
            warn!("(async) đã DENY — báo cáo, sự kiện không chặn inline");
        }
        // Push the arm deltas down to the sensor so only these identities enforce inline.
        for a in &out.arms {
            match a {
                edr_engine::ArmCmd::Arm { actor, op } => {
                    info!("ARM    → sensor: {:?} {:?} (từ giờ chặn đồng bộ)", actor, op)
                }
                edr_engine::ArmCmd::Disarm { actor } => {
                    info!("DISARM → sensor: {:?} (trả về async)", actor)
                }
            }
        }
        if !out.arms.is_empty() {
            let frame = edr_endpoint_service::control::encode_frame(&out.arms);
            if let Err(e) = src.push_control(&frame) {
                error!("push control error: {}", err_detail(&e));
            }
        }
        // Hand the outbox to the shipper thread — NON-blocking. This is the whole
        // point of the split: the event loop never waits on the backend TCP. A full
        // queue means the backend is behind/down, so we drop (best-effort telemetry)
        // instead of blocking; shipping + reconnect happen entirely on thread 2.
        if let Some(tx) = ship_tx.as_ref() {
            let mut queued = 0usize;
            let mut dropped = 0usize;
            let mut alerts = 0usize;
            for w in out.wire {
                let is_block = matches!(&w, Wire::Block(_));
                match tx.try_send(w) {
                    Ok(()) => {
                        queued += 1;
                        if is_block {
                            alerts += 1;
                        }
                    }
                    Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => dropped += 1,
                }
            }
            if queued > 0 {
                if alerts > 0 {
                    info!("queued {} record → backend (kèm {} ALERT)", queued, alerts);
                } else {
                    debug!("queued {} record → backend", queued);
                }
            }
            if dropped > 0 {
                warn!("{} record bỏ (hàng đợi backend đầy)", dropped);
            }
        }
    }

    // Clean-exit modes (file/stdin/demo): drop the sender so the shipper drains the
    // remaining queue and exits, then wait for it. (In --port live mode the loop
    // above never returns; the shipper just dies with the process on Ctrl+C.)
    drop(ship_tx);
    if let Some(h) = ship_handle {
        let _ = h.join();
    }

    info!("tổng kết: {} frame · {} event vào engine · {} DENY", batches, svc.events_seen, svc.denies);
    ExitCode::SUCCESS
}

enum Mode {
    Demo,
    File(String),
    Stdin,
    Port(String, Transport),
    Stress(u64),
}

/// How telemetry gets out of the sensor. Control (arm/disarm) and verdicts go over
/// the minifilter port either way — only the event firehose differs.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Transport {
    /// Shared-memory ring: the driver maps a non-paged pool region into us and
    /// publishes into it; no kernel transition per event.
    Ring,
    /// One `FltSendMessage` per event. Kept for a driver that predates the ring.
    Port,
}

fn mode_label(m: &Mode) -> String {
    match m {
        Mode::Demo => "demo".to_string(),
        Mode::Stdin => "stdin".to_string(),
        Mode::File(p) => format!("file:{}", p),
        Mode::Port(n, Transport::Ring) => format!("ring:{}", n),
        Mode::Port(n, Transport::Port) => format!("port:{}", n),
        Mode::Stress(n) => format!("stress:{}", n),
    }
}

/// Synthetic source for `--stress N`: N one-event batches (a file write) generated on
/// the fly. Same engine + shipper + loopback path as live, but no sensor driver — so
/// running it with the driver loaded vs unloaded isolates transport issues from the
/// sensor.
struct StressSource {
    remaining: u64,
    total: u64,
}

impl StressSource {
    fn new(n: u64) -> StressSource {
        StressSource { remaining: n, total: n }
    }
}

impl EventSource for StressSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let i = self.total - self.remaining;
        self.remaining -= 1;
        let rec = sensor::enc_file_write(1_000_000 + i as i64, 4321, 5_000_000, &format!(r"C:\stress\f{}.tmp", i));
        Ok(Some(sensor::build_batch(&[rec])))
    }
    fn name(&self) -> &str {
        "stress"
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

/// Wall-clock HH:MM:SS.mmm (UTC) so endpoint and backend logs can be lined up.
fn ts_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}.{:03}", (s / 3600) % 24, (s / 60) % 60, s % 60, d.subsec_millis())
}

/// Full detail of an I/O error: message + kind + raw OS code (e.g. 10053/10054),
/// which is what actually distinguishes the disconnect causes.
fn err_detail(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{} [kind={:?}, os={}]", e, e.kind(), code),
        None => format!("{} [kind={:?}]", e, e.kind()),
    }
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
            if let Err(e) = s.write_all(bytes) {
                // Log the FULL write error (kind + OS code) at the moment of the drop
                // so it can be correlated with the backend's read error, then abandon
                // the (possibly half-written) socket; a fresh connection starts the
                // backend cleanly with no frame desync.
                warn!(
                    "MẤT KẾT NỐI backend {} khi ghi {} byte: {} — sẽ tự nối lại",
                    self.addr,
                    bytes.len(),
                    err_detail(&e),
                );
                self.stream = None;
                self.next_retry = Instant::now() + Duration::from_millis(500);
                self.down_since_logged = false;
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
        self.next_retry = Instant::now() + Duration::from_millis(500);
        match connect_backend(&self.addr) {
            Ok(s) => {
                info!("backend {} ĐÃ NỐI LẠI", self.addr);
                self.stream = Some(s);
                self.down_since_logged = false;
            }
            Err(e) => {
                if !self.down_since_logged {
                    warn!("nối lại backend {} THẤT BẠI: {} — sẽ thử lại mỗi 500ms", self.addr, err_detail(&e));
                    self.down_since_logged = true;
                }
            }
        }
    }

    /// Idle maintenance: if currently down, attempt a (throttled) reconnect so the
    /// link is back before the next event rather than on it.
    fn tick(&mut self) {
        if self.stream.is_none() {
            self.try_reconnect();
        }
    }
}

/// Thread 2: drain the ship queue and write frames to the backend, reconnecting on
/// its own. Fully decoupled from the sensor event loop (thread 1) so a slow/down
/// backend never blocks or back-pressures enforcement. Exits when the sender is
/// dropped and the queue is drained (clean shutdown of file/stdin/demo modes).
fn shipper_loop(mut up: Uplink, rx: Receiver<Wire>) {
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(w) => {
                up.ship(&edr_proto::encode_frame(&w));
            }
            // Idle: no new frames — try a throttled reconnect if we're down.
            Err(RecvTimeoutError::Timeout) => up.tick(),
            // Sender dropped and queue drained → done.
            Err(RecvTimeoutError::Disconnected) => break,
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
        Mode::Port(name, t) => connect_port(name, t),
        Mode::Stress(n) => Ok(Box::new(StressSource::new(n))),
    }
}

#[cfg(windows)]
fn connect_port(name: String, transport: Transport) -> io::Result<Box<dyn EventSource>> {
    match transport {
        Transport::Ring => Ok(Box::new(edr_endpoint_service::ring::RingSource::connect(&name)?)),
        Transport::Port => {
            Ok(Box::new(edr_endpoint_service::winport::WinPortSource::connect(&name)?))
        }
    }
}

#[cfg(not(windows))]
fn connect_port(_name: String, _transport: Transport) -> io::Result<Box<dyn EventSource>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "--com-port (live sensor) chỉ hỗ trợ trên Windows. Dùng --demo/--file/--stdin để thử.",
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
