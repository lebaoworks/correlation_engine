//! Lock-free MPSC ring shared with the kernel sensor — layout + cursor math.
//!
//! This module is deliberately **platform-independent**: it does the pointer
//! arithmetic over a raw `*mut u8` and nothing else, so the protocol can be tested
//! on any host (the driver half only exists on Windows). It is the executable spec
//! of the layout `sensor/windows_driver/SnsDrv/Ring.cpp` must match byte for byte.
//!
//! # Layout
//!
//! ```text
//! 0    magic:u32 ++ abi:u16 ++ pad:u16 ++ data_size:u32 ++ pad:u32
//! 64   head_mirror:u64 ++ dropped:u64          <- producer writes (own cacheline)
//! 128  tail:u64 ++ consumer_state:u32          <- consumer writes (own cacheline)
//! 4096 data[data_size]                         <- data_size is a power of two
//! ```
//!
//! head/tail sit on separate cachelines: they are written by different CPUs on
//! every event, and sharing a line would trade a syscall for a cacheline ping-pong.
//!
//! # What lives where, and why
//!
//! The region is non-paged pool **mapped into the service**, so the service can
//! write anywhere in it. The authoritative `head` and `mask` therefore live in
//! driver-private memory *outside* this region; `head_mirror` here is a read-only
//! copy for the consumer. Every kernel write offset is computed as
//! `head_private & mask` — both operands out of the service's reach — so a
//! compromised service can corrupt its own telemetry but can never steer a kernel
//! write out of bounds. `tail` is user-written and therefore **untrusted**: it is
//! only ever used for the free-space check, and `head - tail > data_size` (only
//! reachable by tampering) is clamped to "full" → drop.
//!
//! # Commit protocol
//!
//! Frames are the existing 8-byte `sensor` frame header + one record, so
//! `sensor::parse_batch` consumes them unchanged. The frame's first field is
//! `TotalSize:u32`, which doubles as the ring's commit flag:
//!
//! * Producer writes the body first and `TotalSize` **last** (release).
//! * `TotalSize == 0` at `tail` means *reserved but not yet committed* → the
//!   consumer waits rather than reading a torn frame.
//! * The consumer **zeroes `TotalSize` before advancing `tail`**, which is what
//!   keeps "0 == uncommitted" true once the ring wraps onto old bytes.
//!
//! A reservation that would straddle the end takes the tail remainder too and
//! fills it with a **pad frame** (`Version == 0`, an otherwise invalid value) for
//! the consumer to skip.

use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

/// `"SRNG"` little-endian. Guards against a stale/foreign mapping.
pub const RING_MAGIC: u32 = 0x474e_5253;
/// Layout revision. Bump on any change to the offsets below.
pub const RING_ABI: u16 = 1;

// Control block offsets.
const O_MAGIC: usize = 0;
const O_ABI: usize = 4;
const O_DATA_SIZE: usize = 8;
const O_HEAD_MIRROR: usize = 64;
const O_DROPPED: usize = 72;
const O_TAIL: usize = 128;
const O_CONSUMER_STATE: usize = 136;
/// Data starts here; the control block occupies the first page on its own.
pub const DATA_OFFSET: usize = 4096;

/// Frame header size (mirrors `sensor::BATCH_HEADER`).
const FRAME_HEADER: usize = 8;
/// `Version` of a pad frame. 0 is not a valid wire version, so a reader that
/// ignored the pad convention would reject it rather than mis-parse it.
const PAD_VERSION: u16 = 0;

/// `consumer_state`: consumer is spinning and will notice a publish on its own.
pub const CONSUMER_RUNNING: u32 = 0;
/// `consumer_state`: consumer is about to block / is blocked — ring the doorbell.
pub const CONSUMER_SLEEPING: u32 = 1;

/// Telemetry stops at 7/8 so a burst can never starve the enforcement path, which
/// may use the whole ring. A dropped telemetry record costs visibility; a dropped
/// enforce record stalls a thread that is blocked in the kernel waiting for it.
const TELEMETRY_BUDGET_NUM: u64 = 7;
const TELEMETRY_BUDGET_DEN: u64 = 8;

/// Which budget a publish may draw on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// Async telemetry — capped at 7/8 of the ring.
    Telemetry,
    /// Synchronous enforcement — may use the full ring.
    Enforce,
}

pub fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// A committed frame's position within the data region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Offset into the data region (already masked).
    pub off: usize,
    /// Total frame bytes, always a multiple of 8.
    pub len: usize,
}

/// Both halves of the mapped ring. `Ring` itself is just a typed view over the
/// mapping — it owns nothing and frees nothing.
pub struct Ring {
    base: *mut u8,
    data_size: usize,
    mask: u64,
}

// The mapping is shared with the kernel by design; all access below is atomic.
unsafe impl Send for Ring {}

impl Ring {
    /// View an already-mapped region. `len` is the whole mapping (control + data).
    ///
    /// # Safety
    /// `base` must point to at least `len` readable+writable bytes that stay mapped
    /// for the lifetime of the returned `Ring`.
    pub unsafe fn from_raw(base: *mut u8, len: usize) -> Result<Ring, String> {
        if len <= DATA_OFFSET {
            return Err(format!("ring mapping too small: {} bytes", len));
        }
        let magic = AtomicU32::from_ptr(base.add(O_MAGIC) as *mut u32).load(Ordering::Acquire);
        if magic != RING_MAGIC {
            return Err(format!("bad ring magic 0x{:08x} (want 0x{:08x})", magic, RING_MAGIC));
        }
        let abi = AtomicU32::from_ptr(base.add(O_ABI) as *mut u32).load(Ordering::Acquire) as u16;
        if abi != RING_ABI {
            return Err(format!("ring ABI {} (want {})", abi, RING_ABI));
        }
        let data_size =
            AtomicU32::from_ptr(base.add(O_DATA_SIZE) as *mut u32).load(Ordering::Acquire) as usize;
        if !data_size.is_power_of_two() {
            return Err(format!("ring data_size {} is not a power of two", data_size));
        }
        if DATA_OFFSET + data_size > len {
            return Err(format!("ring data_size {} overruns the {}-byte mapping", data_size, len));
        }
        Ok(Ring { base, data_size, mask: (data_size - 1) as u64 })
    }

    /// Initialize a fresh region. In production the **driver** does this; this exists
    /// so the layout has one definition and the tests can build a real ring.
    ///
    /// # Safety
    /// As `from_raw`, and the region must be zeroed or otherwise unused.
    pub unsafe fn init(base: *mut u8, len: usize, data_size: usize) -> Result<Ring, String> {
        if !data_size.is_power_of_two() || data_size < FRAME_HEADER {
            return Err(format!("bad data_size {}", data_size));
        }
        if DATA_OFFSET + data_size > len {
            return Err(format!("data_size {} overruns the {}-byte mapping", data_size, len));
        }
        std::ptr::write_bytes(base, 0, len);
        AtomicU32::from_ptr(base.add(O_DATA_SIZE) as *mut u32)
            .store(data_size as u32, Ordering::Release);
        AtomicU32::from_ptr(base.add(O_ABI) as *mut u32).store(RING_ABI as u32, Ordering::Release);
        // Magic last: it is what makes the rest of the block valid to a reader.
        AtomicU32::from_ptr(base.add(O_MAGIC) as *mut u32).store(RING_MAGIC, Ordering::Release);
        Ok(Ring { base, data_size, mask: (data_size - 1) as u64 })
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    fn at_u32(&self, off: usize) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.base.add(off) as *mut u32) }
    }
    fn at_u64(&self, off: usize) -> &AtomicU64 {
        unsafe { AtomicU64::from_ptr(self.base.add(off) as *mut u64) }
    }
    fn data(&self) -> *mut u8 {
        unsafe { self.base.add(DATA_OFFSET) }
    }

    pub fn head_mirror(&self) -> u64 {
        self.at_u64(O_HEAD_MIRROR).load(Ordering::Acquire)
    }
    pub fn tail(&self) -> u64 {
        self.at_u64(O_TAIL).load(Ordering::Acquire)
    }
    pub fn dropped(&self) -> u64 {
        self.at_u64(O_DROPPED).load(Ordering::Acquire)
    }
    pub fn consumer_state(&self) -> u32 {
        self.at_u32(O_CONSUMER_STATE).load(Ordering::Acquire)
    }

    /// `TotalSize` of the frame at data offset `off` — also the commit flag.
    fn total_size_at(&self, off: usize) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.data().add(off) as *mut u32) }
    }
}

// ---- consumer ---------------------------------------------------------------

/// The single reader. Owns `tail`: it keeps a private copy and only publishes it,
/// so it never re-reads its own store through the shared line.
pub struct Consumer {
    ring: Ring,
    tail: u64,
}

/// Why `next` returned nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Empty {
    /// Nothing reserved past `tail`.
    NoData,
    /// A producer has reserved the slot at `tail` but has not committed it yet.
    /// Retrying shortly will succeed — do **not** sleep on this.
    Uncommitted,
}

impl Consumer {
    pub fn new(ring: Ring) -> Consumer {
        let tail = ring.tail();
        Consumer { ring, tail }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Next committed frame, skipping pad frames. Returns its position only — call
    /// [`Consumer::bytes`] to read it and [`Consumer::advance`] when done with it.
    pub fn next(&mut self) -> Result<Frame, Empty> {
        loop {
            let head = self.ring.head_mirror();
            if self.tail == head {
                return Err(Empty::NoData);
            }
            let off = (self.tail & self.ring.mask) as usize;
            // Acquire: pairs with the producer's release store of TotalSize, so the
            // frame body it wrote before that store is visible to us after it.
            let total = self.ring.total_size_at(off).load(Ordering::Acquire) as usize;
            if total == 0 {
                return Err(Empty::Uncommitted);
            }
            let version = unsafe {
                let p = self.ring.data().add(off + 4) as *const u16;
                std::ptr::read_unaligned(p)
            };
            if version == PAD_VERSION {
                self.advance(Frame { off, len: total });
                continue; // pad to the wrap point; the real frame is at 0
            }
            return Ok(Frame { off, len: total });
        }
    }

    /// The frame's bytes, ready for `sensor::parse_batch`. Valid until `advance`.
    pub fn bytes(&self, f: Frame) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ring.data().add(f.off), f.len) }
    }

    /// Release the frame's bytes back to producers.
    ///
    /// Zeroing `TotalSize` **before** publishing `tail` is what preserves
    /// "0 == uncommitted" across a wrap: until `tail` moves, no producer may
    /// reserve these bytes, so the zero is guaranteed to land first.
    pub fn advance(&mut self, f: Frame) {
        self.ring.total_size_at(f.off).store(0, Ordering::Release);
        self.tail = self.tail.wrapping_add(f.len as u64);
        self.ring.at_u64(O_TAIL).store(self.tail, Ordering::Release);
    }

    /// Announce that we are about to block. See [`Consumer::should_sleep`].
    fn set_state(&self, s: u32) {
        self.ring.at_u32(O_CONSUMER_STATE).store(s, Ordering::Relaxed);
    }

    /// Publish `SLEEPING`, then re-check the ring; `true` means it is safe to block
    /// on the doorbell.
    ///
    /// The `SeqCst` fence is load-bearing and is **not** replaceable by
    /// release/acquire. This and the producer's `if consumer_state == SLEEPING`
    /// form a Dekker pattern: each side stores to one location then loads another.
    /// Store→load is the single reordering x86-TSO permits (the store sits in the
    /// store buffer), and on x86 a release store and an acquire load are both plain
    /// `MOV` — neither drains it. Without a full fence on **both** sides:
    /// consumer's `SLEEPING` is still buffered → producer publishes, reads
    /// `RUNNING`, skips the doorbell → consumer's re-check is hoisted above its own
    /// store → sees empty → blocks forever on a non-empty ring.
    pub fn should_sleep(&mut self) -> bool {
        self.set_state(CONSUMER_SLEEPING);
        fence(Ordering::SeqCst);
        match self.next() {
            Err(Empty::NoData) => true,
            _ => {
                self.set_state(CONSUMER_RUNNING);
                false
            }
        }
    }

    /// Call after waking from the doorbell.
    pub fn awake(&mut self) {
        self.set_state(CONSUMER_RUNNING);
    }
}

// ---- producer ---------------------------------------------------------------

/// Reference producer. The real one is the **driver** (`Ring.cpp`); this mirrors it
/// so the protocol is testable off-Windows and so the two halves have one spec.
///
/// Multi-producer: `publish` takes `&self` and reserves with a CAS loop, because in
/// the driver several callbacks publish concurrently from arbitrary threads. The
/// driver's equivalent is `InterlockedCompareExchange64`.
///
/// `head` is private on purpose — in the driver it lives in non-paged pool outside
/// the mapped region, and only its mirror is published. See the module docs.
pub struct Producer {
    ring: Ring,
    head: AtomicU64,
}

// Publishing takes &self and is internally synchronised; the driver publishes from
// arbitrary callback threads.
unsafe impl Sync for Producer {}

impl Producer {
    pub fn new(ring: Ring) -> Producer {
        let head = AtomicU64::new(ring.head_mirror());
        Producer { ring, head }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    fn bump_dropped(&self) {
        self.ring.at_u64(O_DROPPED).fetch_add(1, Ordering::Relaxed);
    }

    /// Bytes a `prio` publish may occupy.
    fn budget(&self, prio: Priority) -> u64 {
        match prio {
            Priority::Enforce => self.ring.data_size as u64,
            Priority::Telemetry => {
                self.ring.data_size as u64 * TELEMETRY_BUDGET_NUM / TELEMETRY_BUDGET_DEN
            }
        }
    }

    /// Copy `frame` in and commit it. `frame` must be a whole wire frame (header
    /// included) whose length is a multiple of 8. Returns `false` if it was dropped
    /// for lack of room — publishing must never block a syscall path.
    pub fn publish(&self, frame: &[u8], prio: Priority) -> bool {
        let len = frame.len();
        debug_assert_eq!(len % 8, 0, "frames are 8-aligned by construction");
        if len < FRAME_HEADER || len > self.ring.data_size {
            self.bump_dropped();
            return false;
        }

        // Reserve: CAS a range out of the private head. Losing the race just means
        // another producer got in first, so re-read and retry.
        let (write_off, pad, new_head) = loop {
            let head = self.head.load(Ordering::Acquire);

            // `tail` is written by the service and is therefore untrusted. It only
            // feeds the free-space check, and `used > data_size` — unreachable
            // without tampering — is clamped to "full". A hostile tail can make us
            // drop our own telemetry; it can never move a write out of the data
            // region, because the offset below comes from `head & mask`, both of
            // which are driver-private.
            let tail = self.ring.tail();
            let used = head.wrapping_sub(tail);
            if used > self.ring.data_size as u64 {
                self.bump_dropped();
                return false;
            }
            let avail = self.budget(prio).saturating_sub(used);

            let off = (head & self.ring.mask) as usize;
            let remainder = self.ring.data_size - off;
            // Straddles the end: take the remainder as a pad frame in the same
            // reservation so the real frame lands at 0 contiguously.
            let wraps = remainder < len;
            let need = if wraps { remainder + len } else { len };
            if need as u64 > avail {
                self.bump_dropped();
                return false;
            }
            let new_head = head.wrapping_add(need as u64);
            if self
                .head
                .compare_exchange_weak(head, new_head, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let pad = if wraps { Some((off, remainder)) } else { None };
                break (if wraps { 0usize } else { off }, pad, new_head);
            }
        };

        // Publish the reservation before filling it. The consumer will see head move
        // and read TotalSize == 0 → `Empty::Uncommitted` → it waits instead of
        // reading a torn frame. `fetch_max` because two producers can reach here out
        // of reservation order and the mirror must never go backwards.
        self.ring.at_u64(O_HEAD_MIRROR).fetch_max(new_head, Ordering::Release);

        if let Some((off, remainder)) = pad {
            self.write_pad(off, remainder);
        }
        unsafe {
            // Body first, TotalSize last — see `commit`.
            std::ptr::copy_nonoverlapping(
                frame.as_ptr().add(4),
                self.ring.data().add(write_off + 4),
                len - 4,
            );
        }
        self.commit(write_off, len as u32);
        true
    }

    /// Fill `[off, off+len)` with a frame the consumer will skip.
    fn write_pad(&self, off: usize, len: usize) {
        debug_assert!(len >= FRAME_HEADER);
        unsafe {
            let p = self.ring.data().add(off);
            std::ptr::write_unaligned(p.add(4) as *mut u16, PAD_VERSION);
            std::ptr::write_unaligned(p.add(6) as *mut u16, 0u16);
        }
        self.commit(off, len as u32);
    }

    /// Publish `TotalSize` — the release store that makes the frame visible. Every
    /// byte written before it is ordered ahead of it, so the consumer's acquire load
    /// of a non-zero `TotalSize` guarantees a complete frame.
    fn commit(&self, off: usize, total: u32) {
        self.ring.total_size_at(off).store(total, Ordering::Release);
    }

    /// `true` if the consumer is blocked and must be woken.
    ///
    /// The `SeqCst` fence is the producer half of the Dekker pattern documented on
    /// [`Consumer::should_sleep`]; dropping it loses wakeups under load.
    pub fn needs_doorbell(&self) -> bool {
        fence(Ordering::SeqCst);
        self.ring.consumer_state() == CONSUMER_SLEEPING
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DS: usize = 256; // small on purpose: wraps arrive fast
    const MAP: usize = DATA_OFFSET + DS;

    /// A backing buffer plus the two halves viewing it.
    struct Pair {
        _buf: Vec<u8>,
        p: Producer,
        c: Consumer,
    }

    fn pair(data_size: usize) -> Pair {
        let mut buf = vec![0u8; DATA_OFFSET + data_size];
        let base = buf.as_mut_ptr();
        unsafe { Ring::init(base, DATA_OFFSET + data_size, data_size).unwrap() };
        let p = Producer::new(unsafe { Ring::from_raw(base, DATA_OFFSET + data_size).unwrap() });
        let c = Consumer::new(unsafe { Ring::from_raw(base, DATA_OFFSET + data_size).unwrap() });
        Pair { _buf: buf, p, c }
    }

    /// A well-formed frame of `len` bytes tagged with `id` (in the Count field) so
    /// tests can assert ordering.
    fn frame(len: usize, id: u16) -> Vec<u8> {
        assert!(len >= 8 && len % 8 == 0);
        let mut v = vec![0u8; len];
        v[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        v[4..6].copy_from_slice(&1u16.to_le_bytes()); // Version = 1 (not a pad)
        v[6..8].copy_from_slice(&id.to_le_bytes());
        v
    }

    fn id_of(b: &[u8]) -> u16 {
        u16::from_le_bytes(b[6..8].try_into().unwrap())
    }

    fn drain(c: &mut Consumer) -> Vec<u16> {
        let mut got = Vec::new();
        while let Ok(f) = c.next() {
            got.push(id_of(c.bytes(f)));
            c.advance(f);
        }
        got
    }

    #[test]
    fn init_then_view_roundtrips() {
        let mut buf = vec![0u8; MAP];
        let base = buf.as_mut_ptr();
        unsafe { Ring::init(base, MAP, DS).unwrap() };
        let r = unsafe { Ring::from_raw(base, MAP).unwrap() };
        assert_eq!(r.data_size(), DS);
        assert_eq!(r.head_mirror(), 0);
        assert_eq!(r.tail(), 0);
    }

    #[test]
    fn rejects_a_foreign_or_stale_mapping() {
        let mut buf = vec![0u8; MAP];
        // All zeroes: magic is wrong, which is exactly the stale-mapping case.
        assert!(unsafe { Ring::from_raw(buf.as_mut_ptr(), MAP) }.is_err());
    }

    #[test]
    fn empty_ring_yields_nodata() {
        let mut t = pair(DS);
        assert_eq!(t.c.next(), Err(Empty::NoData));
    }

    #[test]
    fn single_frame_roundtrips() {
        let mut t = pair(DS);
        assert!(t.p.publish(&frame(32, 7), Priority::Telemetry));
        let f = t.c.next().expect("committed frame is readable");
        assert_eq!(f.len, 32);
        assert_eq!(id_of(t.c.bytes(f)), 7);
        t.c.advance(f);
        assert_eq!(t.c.next(), Err(Empty::NoData));
    }

    #[test]
    fn frames_come_out_in_publish_order() {
        let mut t = pair(DS);
        for i in 0..4u16 {
            assert!(t.p.publish(&frame(16, i), Priority::Telemetry));
        }
        assert_eq!(drain(&mut t.c), vec![0, 1, 2, 3]);
    }

    #[test]
    fn wrap_inserts_a_pad_the_consumer_skips() {
        let mut t = pair(DS);
        // Walk head to 240 of 256, leaving a 16-byte remainder. Drain as we go so
        // this stays a test about wrapping, not about the 7/8 telemetry cap.
        for i in 0..15u16 {
            assert!(t.p.publish(&frame(16, i), Priority::Telemetry));
            assert_eq!(drain(&mut t.c), vec![i]);
        }
        assert_eq!(t.p.ring().head_mirror(), 240);

        // 32 bytes will not fit in the 16-byte tail → pad(16) + frame at 0.
        assert!(t.p.publish(&frame(32, 99), Priority::Telemetry));
        assert_eq!(t.p.ring().head_mirror(), 240 + 16 + 32, "pad is reserved with the frame");

        let f = t.c.next().expect("pad is skipped, real frame is found");
        assert_eq!(f.off, 0, "frame landed at the start, not straddling the end");
        assert_eq!(id_of(t.c.bytes(f)), 99);
        t.c.advance(f);
        assert_eq!(t.c.next(), Err(Empty::NoData));
    }

    #[test]
    fn wrapped_ring_keeps_flowing() {
        let mut t = pair(DS);
        // Several laps, draining as we go — exercises the zero-on-advance invariant
        // against bytes that already held a committed frame.
        for i in 0..64u16 {
            assert!(t.p.publish(&frame(24, i), Priority::Telemetry), "lap {}", i);
            let f = t.c.next().expect("frame after wrap");
            assert_eq!(id_of(t.c.bytes(f)), i);
            t.c.advance(f);
        }
    }

    #[test]
    fn stale_bytes_never_read_as_committed_after_wrap() {
        let mut t = pair(DS);
        // Walk one full lap so every byte holds a stale committed frame. Drained per
        // frame to keep the 7/8 telemetry cap out of this test.
        for i in 0..16u16 {
            assert!(t.p.publish(&frame(16, i), Priority::Telemetry));
            assert_eq!(drain(&mut t.c), vec![i]);
        }
        // head == tail == 256: ring is empty even though the bytes are non-zero.
        assert_eq!(t.p.ring().head_mirror(), 256);
        assert_eq!(
            t.c.next(),
            Err(Empty::NoData),
            "advance() zeroed each TotalSize, so no stale frame is resurrected"
        );
    }

    #[test]
    fn uncommitted_slot_is_distinguished_from_empty() {
        let mut t = pair(DS);
        // Reserve without committing, the way a producer preempted mid-publish looks.
        t.p.ring().at_u64(O_HEAD_MIRROR).store(16, Ordering::Release);
        assert_eq!(
            t.c.next(),
            Err(Empty::Uncommitted),
            "head moved but TotalSize is still 0 → wait, do not sleep and do not read"
        );
    }

    #[test]
    fn telemetry_drops_at_seven_eighths_leaving_room_to_enforce() {
        let t = pair(DS);
        // 7/8 of 256 = 224 bytes = 14 frames of 16.
        for i in 0..14u16 {
            assert!(t.p.publish(&frame(16, i), Priority::Telemetry), "frame {}", i);
        }
        assert!(!t.p.publish(&frame(16, 14), Priority::Telemetry), "telemetry is capped at 7/8");
        assert_eq!(t.p.ring().dropped(), 1);
        assert!(t.p.publish(&frame(16, 15), Priority::Enforce), "enforce may use the last eighth");
    }

    #[test]
    fn enforce_drops_only_when_genuinely_full() {
        let mut t = pair(DS);
        for i in 0..16u16 {
            assert!(t.p.publish(&frame(16, i), Priority::Enforce), "frame {}", i);
        }
        assert!(!t.p.publish(&frame(16, 16), Priority::Enforce), "ring is full");
        assert_eq!(t.p.ring().dropped(), 1);
        // Draining one frame makes room again.
        let f = t.c.next().unwrap();
        t.c.advance(f);
        assert!(t.p.publish(&frame(16, 17), Priority::Enforce));
    }

    #[test]
    fn oversized_frame_is_dropped_not_wrapped_forever() {
        let t = pair(DS);
        assert!(!t.p.publish(&frame(DS + 8, 1), Priority::Enforce));
        assert_eq!(t.p.ring().dropped(), 1);
    }

    #[test]
    fn hostile_tail_cannot_steer_a_write_out_of_bounds() {
        let t = pair(DS);
        // A compromised service scribbles a wild tail. `used` goes absurd, which we
        // clamp to "full" → drop. The point is that nothing is written OOB and the
        // driver stays up; the service only starves itself.
        t.p.ring().at_u64(O_TAIL).store(u64::MAX - 4096, Ordering::Release);
        assert!(!t.p.publish(&frame(16, 1), Priority::Telemetry));
        assert!(t.p.ring().dropped() >= 1);
        assert_eq!(t.p.ring().head_mirror(), 0, "head never moved");
    }

    /// The MPSC part: several producers reserving concurrently against one consumer.
    ///
    /// The ring is deliberately far smaller than the traffic, so it wraps constantly
    /// and producers *do* hit the 7/8 cap and drop — that is the designed behaviour
    /// (a publish must never block a syscall path). So the invariant under test is
    /// not "everything arrives", it is **exactly the frames that reported success
    /// arrive, each exactly once, intact**.
    #[test]
    fn concurrent_producers_never_tear_or_duplicate_a_frame() {
        const PRODUCERS: u16 = 4;
        const PER: u16 = 500;
        const DZ: usize = 1024;
        const MAP_SZ: usize = DATA_OFFSET + DZ;

        let mut buf = vec![0u8; MAP_SZ];
        let base = buf.as_mut_ptr();
        unsafe { Ring::init(base, MAP_SZ, DZ).unwrap() };
        let prod = Producer::new(unsafe { Ring::from_raw(base, MAP_SZ).unwrap() });
        let mut cons = Consumer::new(unsafe { Ring::from_raw(base, MAP_SZ).unwrap() });

        let sent = std::sync::Mutex::new(Vec::<u16>::new());
        let live = AtomicU32::new(PRODUCERS as u32);
        let mut seen: Vec<u16> = Vec::new();

        std::thread::scope(|s| {
            for t in 0..PRODUCERS {
                let (prod, sent, live) = (&prod, &sent, &live);
                s.spawn(move || {
                    let mut mine = Vec::new();
                    for i in 0..PER {
                        // Unique id per (thread, i); varying sizes move where the
                        // wraps land from lap to lap.
                        let id = t * PER + i;
                        let len = 16 + ((i as usize % 3) * 8);
                        if prod.publish(&frame(len, id), Priority::Telemetry) {
                            mine.push(id);
                        }
                    }
                    sent.lock().unwrap().extend(mine);
                    live.fetch_sub(1, Ordering::Release);
                });
            }

            // Drain on this thread until every producer has exited and the ring is dry.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                match cons.next() {
                    Ok(f) => {
                        let b = cons.bytes(f);
                        // A torn frame shows up here: TotalSize is written last, so a
                        // frame the consumer accepted must agree with its own header.
                        assert_eq!(
                            u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize,
                            f.len,
                            "frame TotalSize disagrees with the consumed length → torn write"
                        );
                        seen.push(id_of(b));
                        cons.advance(f);
                    }
                    Err(Empty::Uncommitted) => std::hint::spin_loop(),
                    Err(Empty::NoData) => {
                        if live.load(Ordering::Acquire) == 0 {
                            break; // producers done and nothing left staged
                        }
                        assert!(std::time::Instant::now() < deadline, "consumer stalled");
                        std::hint::spin_loop();
                    }
                }
            }
        });

        let mut sent = sent.into_inner().unwrap();
        assert!(!sent.is_empty(), "the test is pointless if nothing got through");
        sent.sort_unstable();
        seen.sort_unstable();

        let mut uniq = seen.clone();
        uniq.dedup();
        assert_eq!(uniq.len(), seen.len(), "a duplicated id means two producers shared a slot");
        assert_eq!(seen, sent, "exactly the frames that reported success must come out");

        // Drops are expected here and are not a failure — record what actually
        // happened so the assertion above is read in context.
        let dropped = prod.ring().dropped();
        assert_eq!(
            dropped as usize + sent.len(),
            (PRODUCERS * PER) as usize,
            "every publish either lands or is counted as a drop; none may vanish"
        );
    }

    #[test]
    fn doorbell_is_rung_only_while_the_consumer_sleeps() {
        let mut t = pair(DS);
        assert!(!t.p.needs_doorbell(), "a running consumer needs no wakeup");

        assert!(t.c.should_sleep(), "empty ring → safe to block");
        assert!(t.p.needs_doorbell(), "sleeping consumer must be woken");

        t.c.awake();
        assert!(!t.p.needs_doorbell());
    }

    #[test]
    fn should_sleep_rechecks_and_refuses_to_block_on_a_pending_frame() {
        let mut t = pair(DS);
        assert!(t.p.publish(&frame(16, 1), Priority::Telemetry));
        assert!(
            !t.c.should_sleep(),
            "the re-check after publishing SLEEPING is what closes the lost-wakeup window"
        );
        assert_eq!(
            t.c.ring().consumer_state(),
            CONSUMER_RUNNING,
            "and it must undo SLEEPING, or the producer rings a doorbell nobody waits on"
        );
    }
}
