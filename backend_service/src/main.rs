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
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

const DEFAULT_ADDR: &str = "127.0.0.1:7171";

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
            println!("edr-backend-service · nguồn = {}\n", path);
            if let Err(e) = feed(&mut ing, &data) {
                eprintln!("decode error: {}", e);
                return ExitCode::from(1);
            }
            summary(&ing);
            ExitCode::SUCCESS
        }
        Mode::Stdin => {
            let mut ing = Ingestor::new();
            println!("edr-backend-service · nguồn = stdin\n");
            let mut chunk = [0u8; 64 * 1024];
            let mut stdin = io::stdin();
            loop {
                match stdin.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = feed(&mut ing, &chunk[..n]) {
                            eprintln!("decode error: {}", e);
                            return ExitCode::from(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        return ExitCode::from(1);
                    }
                }
            }
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
    println!("edr-backend-service · lắng nghe {} (chờ endpoint service kết nối, Ctrl+C để dừng)\n", addr);

    // The graph outlives connections: an endpoint may reconnect and keep shipping
    // into the same forensic history.
    let mut ing = Ingestor::new();
    let mut conns = 0u64;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                conns += 1;
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".to_string());
                println!("── kết nối #{} từ {} ─────────────────────────────", conns, peer);
                if let Err(e) = drain_conn(&mut ing, s) {
                    eprintln!("connection error: {}", e);
                }
                println!("── kết nối #{} đóng ──", conns);
                summary(&ing);
                println!();
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    ExitCode::SUCCESS
}

fn drain_conn(ing: &mut Ingestor, mut s: TcpStream) -> io::Result<()> {
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            if ing.pending_bytes() != 0 {
                eprintln!("warning: {} byte lửng chưa thành frame khi kết nối đóng", ing.pending_bytes());
            }
            return Ok(());
        }
        if let Err(e) = feed(ing, &chunk[..n]) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
    }
}

fn feed(ing: &mut Ingestor, data: &[u8]) -> Result<(), String> {
    for out in ing.push_bytes(data)? {
        match out {
            Output::Event(line) => println!("{}", line),
            Output::Alert { header, chain } => {
                println!("\n{}", header);
                println!("{}", chain);
            }
        }
    }
    Ok(())
}

fn summary(ing: &Ingestor) {
    println!(
        "--- graph: {} event ingest · {} alert · {} chuỗi đã dựng · {} frame lỗi bỏ qua ---",
        ing.events,
        ing.alerts,
        ing.backend.chains.len(),
        ing.bad_frames
    );
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
