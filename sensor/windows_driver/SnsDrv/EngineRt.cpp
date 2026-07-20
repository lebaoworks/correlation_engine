/*
 * EngineRt.cpp — runtime kernel mà engine_core (Rust static lib, feature "kernel")
 * gọi xuống: global allocator + panic handler. Xem engine_core/src/ffi.rs và
 * engine_core/include/engine.h.
 *
 * engine_core dùng alloc (BTreeMap/Vec) trên hot path của on_event; engine_alloc
 * phải là non-paged pool, an toàn ở IRQL của callback (≤ DISPATCH_LEVEL).
 */

#include <ntddk.h>

// Pool tag 'Egne' (hiện 'engE' đảo do little-endian trong !pool).
static constexpr ULONG ENGINE_POOL_TAG = 'engE';

extern "C" {

void* engine_alloc(size_t size, size_t /*align*/)
{
    if (size == 0)
        size = 1;
    // ExAllocatePool2 (Win10 2004+) zero-init; alignment pool mặc định (16) đủ cho
    // mọi kiểu trong engine_core (không có SIMD/over-aligned type).
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, ENGINE_POOL_TAG);
}

void engine_free(void* ptr, size_t /*size*/, size_t /*align*/)
{
    if (ptr)
        ExFreePoolWithTag(ptr, ENGINE_POOL_TAG);
}

__declspec(noreturn) void engine_panic()
{
    // engine_core panic = bất biến nội bộ bị vi phạm (không nên xảy ra). Dừng cứng
    // để lộ lỗi thay vì chạy tiếp với trạng thái hỏng.
    KeBugCheckEx(0xE9E90001, 0, 0, 0, 0);
}

// core/alloc dựng sẵn (target windows-msvc) biên dịch với panic=unwind nên tham
// chiếu EH personality của MSVC (__CxxFrameHandler3) và _fltused. engine_core ta
// panic=abort (engine_panic → bugcheck) nên KHÔNG bao giờ unwind — cấp symbol cho
// linker; nếu chẳng may bị gọi thì bugcheck để lộ lỗi.
// (Cách sạch hơn: build-std với panic_immediate_abort — xem engine_core/README.)
int _fltused = 0;

// Không bao giờ được gọi (panic=abort không unwind); chỉ để linker giải quyết symbol.
int __CxxFrameHandler3()
{
    return 0;
}

} // extern "C"
