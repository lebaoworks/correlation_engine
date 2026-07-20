//! FFI C-ABI để driver kernel (C++ WDK) dùng engine_core như static lib chạy
//! **inline** trong callback (`sensor/windows_driver/SnsDrv`).
//!
//! Các hàm `extern "C"` luôn được biên dịch (test host phủ đúng ABI). Runtime
//! kernel — global allocator + panic handler — chỉ bật khi `--features kernel`
//! (và không phải build test), vì `#[global_allocator]`/`#[panic_handler]` là
//! singleton, không được có mặt khi engine_core bị link vào crate std (engine_rules,
//! engine_replay). Header C: `engine_core/include/engine.h`.
//!
//! ABI khớp header từng byte — sửa một bên phải sửa bên kia.

use alloc::boxed::Box;
use core::{ptr, slice};

use crate::{Engine, Event, Key, Kind, Op, Ttp, Verdict};

/// Event dạng C (`#[repr(C)]`, khớp `EngineEvent` trong header). Key 128-bit
/// tách thành hai u64 vì C/MSVC không có kiểu 128-bit gốc.
#[repr(C)]
pub struct CEvent {
    pub ts: u64,
    /// [`Op`] theo chỉ số 0..8 (xem [`op_from_index`]).
    pub op: u32,
    pub actor_lo: u64,
    pub actor_hi: u64,
    /// [`Kind`] theo chỉ số 0..4.
    pub actor_kind: u32,
    pub object_lo: u64,
    pub object_hi: u64,
    pub object_kind: u32,
}

fn make_key(lo: u64, hi: u64) -> Key {
    Key(((hi as u128) << 64) | (lo as u128))
}

/// Chỉ số op trong header (`EngineOp`) → [`Op`]. Ngoài dải ⇒ `None` (bỏ event).
fn op_from_index(i: u32) -> Option<Op> {
    Some(match i {
        0 => Op::Exec,
        1 => Op::Create,
        2 => Op::Write,
        3 => Op::Read,
        4 => Op::Open,
        5 => Op::Connect,
        6 => Op::Inject,
        7 => Op::Dup,
        _ => return None,
    })
}

/// Chỉ số kind trong header (`EngineKind`) → [`Kind`]. Ngoài dải ⇒ `Other`.
fn kind_from_index(i: u32) -> Kind {
    match i {
        0 => Kind::Process,
        1 => Kind::File,
        2 => Kind::Socket,
        _ => Kind::Other,
    }
}

impl CEvent {
    fn to_event(&self) -> Option<Event> {
        Some(Event {
            ts: self.ts,
            op: op_from_index(self.op)?,
            actor: make_key(self.actor_lo, self.actor_hi),
            actor_kind: kind_from_index(self.actor_kind),
            object: make_key(self.object_lo, self.object_hi),
            object_kind: kind_from_index(self.object_kind),
        })
    }
}

/// Dựng engine từ wire ruleset DAG (`ERD1`) do `engine_rules` encode. Trả handle
/// mờ (`*mut Engine`); `NULL` nếu bytes không hợp lệ. Giải phóng bằng
/// [`engine_destroy`].
///
/// # Safety
/// `rules` phải trỏ tới `len` byte đọc được (hoặc `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn engine_create(rules: *const u8, len: usize) -> *mut Engine {
    if rules.is_null() && len != 0 {
        return ptr::null_mut();
    }
    let bytes = if len == 0 { &[][..] } else { slice::from_raw_parts(rules, len) };
    // try_new fallible: kernel cấp State cố định có thể thất bại → trả NULL, KHÔNG panic.
    match crate::wire::decode_dag(bytes).ok().and_then(Engine::try_new) {
        Some(engine) => Box::into_raw(Box::new(engine)),
        None => ptr::null_mut(),
    }
}

/// Chạy một event qua engine. Trả `EngineVerdict` (`0=ignore 1=inspect 2=block
/// 3=disarm`). Handle/event rỗng hoặc `op` ngoài dải ⇒ `0` an toàn.
///
/// # Safety
/// `engine` là handle từ [`engine_create`] chưa destroy; `ev` trỏ tới một
/// `CEvent` hợp lệ; `ttps` trỏ tới `ttps_len` phần tử `u32` (hoặc `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn engine_on_event(
    engine: *mut Engine,
    ev: *const CEvent,
    ttps: *const u32,
    ttps_len: usize,
) -> u32 {
    if engine.is_null() || ev.is_null() {
        return Verdict::Ignore as u32;
    }
    let engine = &mut *engine;
    let event = match (*ev).to_event() {
        Some(e) => e,
        None => return Verdict::Ignore as u32,
    };
    // Ttp là repr(transparent) trên u32 → cast thẳng, không copy, không alloc.
    let ttps: &[Ttp] = if ttps.is_null() || ttps_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ttps as *const Ttp, ttps_len)
    };
    engine.on_event(&event, ttps) as u32
}

/// Ghi tập TTP (đã sắp xếp, không trùng) mà ruleset đang nạp tham chiếu vào
/// `out` (tối đa `cap`), trả **tổng** số TTP. Gọi `out == NULL`/`cap == 0` để
/// lấy tổng trước; trả về `> cap` ⇒ buffer bị cắt. Driver dùng để bật đúng tagger.
///
/// # Safety
/// `engine` là handle từ [`engine_create`]; `out` trỏ tới `cap` phần tử `u32`
/// ghi được (hoặc `NULL` khi `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn engine_referenced_ttps(
    engine: *const Engine,
    out: *mut u32,
    cap: usize,
) -> usize {
    if engine.is_null() {
        return 0;
    }
    let ttps = (*engine).referenced_ttps();
    if !out.is_null() {
        let n = core::cmp::min(cap, ttps.len());
        for (i, t) in ttps.iter().take(n).enumerate() {
            *out.add(i) = t.0;
        }
    }
    ttps.len()
}

/// Giải phóng engine do [`engine_create`] trả về. `NULL` là no-op.
///
/// # Safety
/// `engine` phải là handle từ [`engine_create`], destroy đúng một lần.
#[no_mangle]
pub unsafe extern "C" fn engine_destroy(engine: *mut Engine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

// ---- Runtime kernel: global allocator + panic handler chuyển tiếp xuống driver.
//      Chỉ có khi build `--features kernel` (và không phải test): singleton này
//      không được xuất hiện khi engine_core bị link vào crate std.
//
//      RÀNG BUỘC (kernel không được abort/panic — chạy trong mọi điều kiện):
//      `engine_panic` là LỐI THOÁT CUỐI phải KHÔNG BAO GIỜ tới. Panic ở đây chỉ
//      xảy ra khi (a) hết pool (collection cấp phát thất bại) hoặc (b) vi phạm bất
//      biến nội bộ. `panic=abort` ở dòng build KHÔNG phải "chiến lược abort" — nó
//      là yêu cầu bắt buộc của crate-type staticlib (không unwind được); mục tiêu
//      là panic KHÔNG xảy ra. Để bảo đảm (a) không xảy ra, đường per-event phải
//      KHÔNG cấp phát động thất bại được — tức bản engine dùng ở kernel phải là
//      biến thể **fixed-capacity, no-alloc** (bounded working-set). Bản v0.0.2
//      hiện tại (BTreeMap/Vec) CHƯA đạt điều đó — xem `todo.md` bước 5.
#[cfg(all(feature = "kernel", not(test)))]
mod kernel_rt {
    use core::alloc::{GlobalAlloc, Layout};
    use core::panic::PanicInfo;

    extern "C" {
        /// Driver cấp: cấp phát non-paged pool, an toàn ở IRQL của callback.
        fn engine_alloc(size: usize, align: usize) -> *mut u8;
        /// Driver cấp: giải phóng vùng do `engine_alloc` trả.
        fn engine_free(ptr: *mut u8, size: usize, align: usize);
        /// Driver cấp: xử lý panic (KeBugCheckEx/log). Không trở về.
        fn engine_panic() -> !;
    }

    struct KernelAlloc;

    unsafe impl GlobalAlloc for KernelAlloc {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            engine_alloc(l.size(), l.align())
        }
        unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
            engine_free(ptr, l.size(), l.align());
        }
    }

    #[global_allocator]
    static ALLOC: KernelAlloc = KernelAlloc;

    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        // SAFETY: driver bảo đảm engine_panic không trở về.
        unsafe { engine_panic() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    use crate::{Action, DagPattern, DagRuleSet, DagStep, OpSet, StepMatch};
    use alloc::string::ToString;
    use alloc::vec;

    // 0=exec 1=create 2=write 3=read 4=open 5=connect 6=inject 7=dup
    const EXEC: u32 = 0;
    const WRITE: u32 = 2;
    const READ: u32 = 3;

    fn cevent(ts: u64, op: u32, actor: u64, object: u64) -> CEvent {
        CEvent {
            ts,
            op,
            actor_lo: actor,
            actor_hi: 0,
            actor_kind: 0, // process
            object_lo: object,
            object_hi: 0,
            object_kind: 1, // file
        }
    }

    fn step(bit: u8, op: Op, ttp: u32, prereq: u64, action: Option<Action>) -> DagStep {
        DagStep {
            matcher: StepMatch { ops: OpSet::single(op), ttps: vec![Ttp(ttp)] },
            bit,
            prereq_mask: prereq,
            action,
        }
    }

    // ransomware_dag: bit0 gốc; bit1,2 cần {0}; bit3 cần {1,2}, disarm(write,exec).
    fn dag_bytes() -> alloc::vec::Vec<u8> {
        let rs = DagRuleSet {
            patterns: vec![DagPattern {
                name: "ransomware_dag".to_string(),
                steps: vec![
                    step(0, Op::Exec, 1059, 0, None),
                    step(1, Op::Read, 1083, 0b1, None),
                    step(2, Op::Exec, 1490, 0b1, None),
                    step(3, Op::Write, 1486, 0b110,
                         Some(Action::Disarm(OpSet::single(Op::Write).union(OpSet::single(Op::Exec))))),
                ],
            }],
        };
        wire::encode_dag(&rs)
    }

    unsafe fn on(eng: *mut Engine, ev: &CEvent, ttps: &[u32]) -> u32 {
        engine_on_event(eng, ev, ttps.as_ptr(), ttps.len())
    }

    #[test]
    fn ffi_roundtrip_reordered_chain() {
        let bytes = dag_bytes();
        unsafe {
            let eng = engine_create(bytes.as_ptr(), bytes.len());
            assert!(!eng.is_null());
            // chuỗi ĐẢO thứ tự: bit 2 (T1490) trước bit 1 (T1083)
            assert_eq!(on(eng, &cevent(1, EXEC, 10, 11), &[1059]), 1); // inspect
            assert_eq!(on(eng, &cevent(2, EXEC, 10, 12), &[1490]), 1); // inspect (bit2 trước)
            assert_eq!(on(eng, &cevent(3, READ, 10, 13), &[1083]), 1); // inspect (bit1)
            assert_eq!(on(eng, &cevent(4, WRITE, 10, 14), &[1486]), 3); // disarm (bit3)
            assert_eq!(on(eng, &cevent(5, WRITE, 10, 15), &[]), 2); // block (DISARMED)
            engine_destroy(eng);
        }
    }

    #[test]
    fn null_and_bad_inputs_are_safe() {
        unsafe {
            assert!(engine_create(b"XXXX".as_ptr(), 4).is_null());
            let ev = cevent(1, EXEC, 10, 11);
            assert_eq!(engine_on_event(ptr::null_mut(), &ev, ptr::null(), 0), 0);
            engine_destroy(ptr::null_mut());
            let bytes = dag_bytes();
            let eng = engine_create(bytes.as_ptr(), bytes.len());
            let bad = cevent(1, 99, 10, 11);
            assert_eq!(engine_on_event(eng, &bad, ptr::null(), 0), 0);
            engine_destroy(eng);
        }
    }

    #[test]
    fn referenced_ttps_drives_tagger_selection() {
        let bytes = dag_bytes();
        unsafe {
            let eng = engine_create(bytes.as_ptr(), bytes.len());
            assert_eq!(engine_referenced_ttps(eng, ptr::null_mut(), 0), 4);
            let mut buf = [0u32; 8];
            let n = engine_referenced_ttps(eng, buf.as_mut_ptr(), buf.len());
            assert_eq!(n, 4);
            assert_eq!(&buf[..4], &[1059, 1083, 1486, 1490]);
            let mut small = [0u32; 2];
            assert_eq!(engine_referenced_ttps(eng, small.as_mut_ptr(), small.len()), 4);
            assert_eq!(small, [1059, 1083]);
            engine_destroy(eng);
        }
    }

    #[test]
    fn empty_ruleset_roundtrips() {
        let empty = wire::encode_dag(&DagRuleSet::default());
        unsafe {
            let eng = engine_create(empty.as_ptr(), empty.len());
            assert!(!eng.is_null());
            assert_eq!(on(eng, &cevent(1, EXEC, 10, 11), &[1059]), 0);
            engine_destroy(eng);
        }
    }
}
