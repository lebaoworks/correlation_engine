/*
 * engine.h — C ABI cho engine_core (static lib) dùng trong driver kernel.
 *
 * Khớp TỪNG BYTE với engine_core/src/ffi.rs. Sửa một bên phải sửa bên kia.
 *
 * Luồng:
 *   endpoint_service (usermode) --engine_rules::compile_dag_to_bytes--> wire (ERD1)
 *     --control port--> driver --engine_create--> handle
 *   callback --dựng EngineEvent + tag TTP--> engine_on_event --> verdict --> ArmTable/deny
 */
#pragma once

/*
 * Kiểu số: trong kernel KHÔNG include <stdint.h>/<stddef.h> — chúng kéo vcruntime.h,
 * vỡ cấu hình warning của kernel (C4083/C4005). Dùng type intrinsic MSVC; size_t đã
 * có sẵn từ header WDK (ntdef/basetsd) mà driver include trước file này.
 */
#if defined(_KERNEL_MODE)
typedef unsigned char    uint8_t;
typedef unsigned int     uint32_t;
typedef unsigned __int64 uint64_t;
/* size_t: do WDK định nghĩa sẵn. */
#else
#include <stdint.h>
#include <stddef.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* op — khớp thứ tự engine_core::Op (chỉ số, KHÔNG phải bitmask). */
typedef enum {
    ENGINE_OP_EXEC    = 0,
    ENGINE_OP_CREATE  = 1,
    ENGINE_OP_WRITE   = 2,
    ENGINE_OP_READ    = 3,
    ENGINE_OP_OPEN    = 4,
    ENGINE_OP_CONNECT = 5,
    ENGINE_OP_INJECT  = 6,
    ENGINE_OP_DUP     = 7
} EngineOp;

/* kind — khớp engine_core::Kind. Ngoài dải ⇒ OTHER. */
typedef enum {
    ENGINE_KIND_PROCESS = 0,
    ENGINE_KIND_FILE    = 1,
    ENGINE_KIND_SOCKET  = 2,
    ENGINE_KIND_OTHER   = 3
} EngineKind;

/* verdict trả về — khớp engine_core::Verdict (repr u32). */
typedef enum {
    ENGINE_VERDICT_IGNORE  = 0,
    ENGINE_VERDICT_INSPECT = 1,
    ENGINE_VERDICT_BLOCK   = 2,
    ENGINE_VERDICT_DISARM  = 3
} EngineVerdict;

/*
 * Một event. Layout = #[repr(C)] CEvent. Key 128-bit tách thành lo/hi vì C/MSVC
 * không có kiểu 128-bit gốc: key = (hi << 64) | lo.
 *   - process: (pid, start_ts) đóng gói thành 128-bit định danh ổn định.
 *   - file:    FileId.
 */
typedef struct {
    uint64_t ts;           /* mốc thời gian đơn điệu (ms) */
    uint32_t op;           /* EngineOp */
    uint64_t actor_lo;
    uint64_t actor_hi;
    uint32_t actor_kind;   /* EngineKind */
    uint64_t object_lo;
    uint64_t object_hi;
    uint32_t object_kind;  /* EngineKind */
} EngineEvent;

/* Handle mờ tới engine. */
typedef void* EngineHandle;

/* ---- engine_ffi CUNG CẤP (Rust) ---- */

/*
 * Dựng engine từ wire ruleset DAG (magic "ERD1") do engine_rules encode.
 * Trả NULL nếu bytes không hợp lệ. Giải phóng bằng engine_destroy.
 * rules có thể NULL khi len == 0 (ruleset rỗng, mọi verdict = IGNORE).
 */
EngineHandle engine_create(const uint8_t* rules, size_t len);

/*
 * Chạy một event. Trả EngineVerdict. handle/ev NULL hoặc op ngoài dải ⇒ IGNORE.
 * ttps: mảng u32 (mã technique, vd 1059 cho T1059) do tagger của driver gán;
 * ttps_len == 0 (ttps có thể NULL) là hợp lệ.
 *
 * BLOCK/DISARM ⇒ driver chặn hành vi hiện tại; DISARM còn tước quyền op của
 * actor vĩnh viễn (engine đã ghi nội bộ — driver chỉ cần enforce chặn).
 */
uint32_t engine_on_event(EngineHandle engine, const EngineEvent* ev,
                         const uint32_t* ttps, size_t ttps_len);

/*
 * Ghi tập TTP (đã sắp xếp, không trùng) mà ruleset đang nạp tham chiếu vào out
 * (tối đa cap phần tử), trả TỔNG số TTP. Gọi out=NULL/cap=0 để lấy tổng trước.
 * Trả về > cap ⇒ buffer bị cắt.
 *
 * Dùng để chọn tagger: driver chỉ bật tagger có TTP nằm trong tập này, rồi
 * dispatch theo op (bảng tagger_by_op[op]) — "bắt op X thì chạy tagger cho op X".
 */
size_t engine_referenced_ttps(EngineHandle engine, uint32_t* out, size_t cap);

/* Giải phóng engine. NULL là no-op. */
void engine_destroy(EngineHandle engine);

/* ---- Driver PHẢI CUNG CẤP (chỉ build kernel; Rust global-alloc/panic gọi xuống) ----
 *
 * void* engine_alloc(size_t size, size_t align);   // non-paged pool, an toàn ở IRQL callback
 * void  engine_free (void* ptr, size_t size, size_t align);
 * void  engine_panic(void);                         // KeBugCheckEx/log — KHÔNG trở về
 *
 * (Khai báo ở phía driver, vd EngineRt.cpp. Không định nghĩa trong header này.)
 */

#ifdef __cplusplus
} /* extern "C" */
#endif
