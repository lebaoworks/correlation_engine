//! EDR backend service — console app.
//!
//! Receives the endpoint service's wire stream, builds the full provenance graph,
//! prints every ingested event, and on a block alert reconstructs and displays
//! the whole storyline.
//!
//!   edr-backend-service                      # listen on 127.0.0.1:7171
//!   edr-backend-service --listen 0.0.0.0:7171
//!   edr-backend-service --file wire.bin      # replay a captured wire stream
//!   edr-backend-service --stdin              # read the wire stream from stdin

use edr_backend_service::{Ingestor, Output};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Duration;

const DEFAULT_ADDR: &str = "127.0.0.1:7171";

/// Bounded print queue between the receiver thread and the printer thread. Full ⇒
/// the console can't keep up with the ingest rate; we drop console lines (the graph
/// still ingested every event) rather than let the receiver block on the console and
/// stall the socket read — which is exactly what fills the OS buffer and resets the
/// loopback connection.
const PRINT_QUEUE_CAP: usize = 65536;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut mode = Mode::Listen(DEFAULT_ADDR.to_string());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                let addr = args.get(i + 1).filter(|s| !s.starts_with("--")).cloned();
                if addr.is_some() {
                    i += 1;
                }
                mode = Mode::Listen(addr.unwrap_or_else(|| DEFAULT_ADDR.to_string()));
            }
            "--file" => {
                i += 1;
                mode = Mode::File(args.get(i).cloned().unwrap_or_default());
            }
            "--stdin" => mode = Mode::Stdin,
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

    match mode {
        Mode::Listen(addr) => listen(&addr),
        Mode::File(path) => {
            let data = match fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cannot read {}: {}", path, e);
                    return ExitCode::from(2);
                }
            };
            let mut ing = Ingestor::new();
            eprintln!("edr-backend-service · nguồn = {}", path);
            let mut out = io::BufWriter::new(io::stdout());
            if let Err(e) = feed(&mut ing, &data, &mut out) {
                let _ = out.flush();
                eprintln!("decode error: {}", e);
                return ExitCode::from(1);
            }
            let _ = out.flush();
            summary(&ing);
            ExitCode::SUCCESS
        }
        Mode::Stdin => {
            let mut ing = Ingestor::new();
            eprintln!("edr-backend-service · nguồn = stdin");
            let mut chunk = [0u8; 64 * 1024];
            let mut stdin = io::stdin();
            let mut out = io::BufWriter::with_capacity(256 * 1024, io::stdout());
            loop {
                match stdin.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = feed(&mut ing, &chunk[..n], &mut out) {
                            let _ = out.flush();
                            eprintln!("decode error: {}", e);
                            return ExitCode::from(1);
                        }
                        let _ = out.flush();
                    }
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        return ExitCode::from(1);
                    }
                }
            }
            let _ = out.flush();
            summary(&ing);
            ExitCode::SUCCESS
        }
    }
}

enum Mode {
    Listen(String),
    File(String),
    Stdin,
}

fn listen(addr: &str) -> ExitCode {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {}: {}", addr, e);
            return ExitCode::from(2);
        }
    };
    eprintln!("edr-backend-service · lắng nghe {} (chờ endpoint service kết nối, Ctrl+C để dừng)", addr);

    // Two threads: THIS one (receiver) accepts, reads the socket, ingests into the
    // graph, and enqueues printable output; the PRINTER thread drains the queue and
    // writes stdout. The receiver never waits on the (slow) console, so console I/O
    // can't stall the read loop and let the OS buffer fill → loopback reset. stdout
    // carries only event data (printer thread); status/errors go to stderr here.
    let (tx, rx) = sync_channel::<Output>(PRINT_QUEUE_CAP);
    let printer = thread::spawn(move || printer_loop(rx));

    // The graph outlives connections: an endpoint may reconnect and keep shipping
    // into the same forensic history.
    let mut ing = Ingestor::new();
    let mut conns = 0u64;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                conns += 1;
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".to_string());
                eprintln!("── [{}] kết nối #{} từ {} ─────────────", ts_now(), conns, peer);
                let _ = drain_conn(&mut ing, s, &tx);
                eprintln!("── kết nối #{} đóng ──", conns);
                summary(&ing);
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    drop(tx); // let the printer drain and exit
    let _ = printer.join();
    ExitCode::SUCCESS
}

/// Receiver side (thread 1): read the socket as fast as possible, ingest into the
/// graph, and hand printable output to the printer thread. Enqueue is NON-blocking —
/// a full queue drops *console* lines (the graph still ingested every event), never
/// blocking the read. Connection status/errors go to stderr.
fn drain_conn(ing: &mut Ingestor, mut s: TcpStream, tx: &SyncSender<Output>) -> io::Result<()> {
    let mut chunk = [0u8; 64 * 1024];
    let mut dropped = 0u64;
    loop {
        let n = match s.read(&mut chunk) {
            Ok(n) => n,
            Err(e) => {
                // Full detail (kind + OS code, e.g. 10054) at the moment of the drop,
                // to correlate with the endpoint's write error on the other console.
                eprintln!("  ⚠ [{}] LỖI ĐỌC socket từ endpoint: {} — đóng kết nối", ts_now(), err_detail(&e));
                report_dropped(dropped);
                return Err(e);
            }
        };
        if n == 0 {
            eprintln!("  [{}] endpoint đóng kết nối (EOF sạch)", ts_now());
            if ing.pending_bytes() != 0 {
                eprintln!("  ⚠ {} byte lửng chưa thành frame khi kết nối đóng", ing.pending_bytes());
            }
            report_dropped(dropped);
            return Ok(());
        }
        match ing.push_bytes(&chunk[..n]) {
            Ok(outs) => {
                for out in outs {
                    // try_send: if the printer is behind, drop this console line rather
                    // than block the read loop (the event is already in the graph).
                    if tx.try_send(out).is_err() {
                        dropped += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⚠ [{}] LỖI GIẢI MÃ stream: {} — đóng kết nối", ts_now(), e);
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
    }
}

fn report_dropped(dropped: u64) {
    if dropped > 0 {
        eprintln!("  ⚠ {} dòng console bị bỏ (console không theo kịp; graph vẫn ingest đủ)", dropped);
    }
}

/// Printer side (thread 2): drain the queue and write to a buffered stdout, batching
/// (one flush per burst) so console I/O never back-pressures the receiver. Exits when
/// the sender is dropped and the queue is drained.
fn printer_loop(rx: Receiver<Output>) {
    let mut w = io::BufWriter::with_capacity(256 * 1024, io::stdout());
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(first) => {
                write_output(&mut w, &first);
                while let Ok(next) = rx.try_recv() {
                    write_output(&mut w, &next);
                }
                let _ = w.flush();
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = w.flush();
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = w.flush();
                break;
            }
        }
    }
}

fn write_output<W: Write>(w: &mut W, out: &Output) {
    let _ = match out {
        Output::Event(line) => writeln!(w, "{}", line),
        Output::Alert { header, chain } => writeln!(w, "\n{}\n{}", header, chain),
    };
}

/// Decode + ingest, writing output to `w` (a buffered writer, NOT locking+flushing
/// stdout per line — that per-line console cost is what stalls the socket read loop
/// under a flood and lets the loopback connection reset).
fn feed<W: Write>(ing: &mut Ingestor, data: &[u8], w: &mut W) -> Result<(), String> {
    for out in ing.push_bytes(data)? {
        let r = match out {
            Output::Event(line) => writeln!(w, "{}", line),
            Output::Alert { header, chain } => writeln!(w, "\n{}\n{}", header, chain),
        };
        r.map_err(|e| format!("write stdout: {}", e))?;
    }
    Ok(())
}

fn summary(ing: &Ingestor) {
    // Status → stderr so stdout stays a clean event-only stream (single writer).
    eprintln!(
        "--- graph: {} event ingest · {} alert · {} chuỗi đã dựng · {} frame lỗi bỏ qua ---",
        ing.events,
        ing.alerts,
        ing.backend.chains.len(),
        ing.bad_frames
    );
}

/// Wall-clock HH:MM:SS.mmm (UTC) so backend and endpoint logs can be lined up.
fn ts_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}.{:03}", (s / 3600) % 24, (s / 60) % 60, s % 60, d.subsec_millis())
}

/// Full detail of an I/O error: message + kind + raw OS code (e.g. 10053/10054).
fn err_detail(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{} [kind={:?}, os={}]", e, e.kind(), code),
        None => format!("{} [kind={:?}]", e, e.kind()),
    }
}

fn print_help() {
    println!(
        "edr-backend-service — nhận wire stream từ endpoint service, giữ full provenance graph,\n\
         hiển thị toàn bộ storyline khi endpoint bắn alert (BlockReport).\n\
         \n  --listen [addr]   lắng nghe TCP (mặc định {})\
         \n  --file <path>     replay wire stream đã bắt ra file\
         \n  --stdin           đọc wire stream từ stdin\
         ",
        DEFAULT_ADDR
    );
}
