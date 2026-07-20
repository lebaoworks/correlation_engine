#pragma once

/********************
*     Includes      *
********************/

#include <krn.hpp>
#include "Event.hpp"

// C ABI của engine_core (Rust static lib). include path: ../../../engine_core/include
extern "C" {
#include "engine.h"
}

/*
 * Engine — bọc C++ quanh engine_core (chạy inline trong kernel).
 *
 * Vòng đời:
 *   - Load(bytes,len): nhận wire ruleset DAG ("ERD1") do endpoint_service gửi
 *     xuống qua control port, dựng engine mới (engine_create), đổi handle, và
 *     dựng lại registry tagger theo tập TTP mà rule tham chiếu (engine_referenced_ttps).
 *   - Feed(evt, *deny): map event driver → EngineEvent, chạy tagger theo op,
 *     gọi engine_on_event, đặt *deny = (verdict >= BLOCK). Khớp chữ ký
 *     Event::SyncEnforceCallback nên cắm thẳng làm đường enforce.
 *
 * engine_core tự giữ DISARMED nội bộ: op đã bị disarm ở event trước thì event
 * sau mang op đó tự trả BLOCK — driver không cần mirror sang ArmTable.
 */
namespace Engine
{
    // Một tagger: gắn với đúng một op, phát một ttp khi predicate đúng.
    // Predicate đọc tín hiệu kernel từ event (image/access-mask/…).
    struct Tagger
    {
        EngineOp op;
        UINT32   ttp;
        bool (*match)(const Event::Event& evt);
    };

    class Instance : public krn::failable, public krn::tag<'EVT0'>
    {
    private:
        EngineHandle _handle = nullptr;
        EX_PUSH_LOCK _lock;         // bảo vệ swap handle giữa Load và Feed

        // Registry tagger đã lọc theo rule, index theo op (0..8).
        static constexpr ULONG NUM_OPS = 8;
        static constexpr ULONG MAX_PER_OP = 8;
        static constexpr ULONG MAX_TTPS = 16; // TTP tối đa gán cho một event
        const Tagger* _by_op[NUM_OPS][MAX_PER_OP] = {};
        ULONG _count[NUM_OPS] = {};

        void RebuildTaggers_(); // gọi trong Load, dưới _lock (exclusive)

    public:
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        Instance() noexcept;

        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        ~Instance();

        /// @brief Nạp ruleset mới (wire DAG). Trả STATUS_SUCCESS nếu bytes hợp lệ.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS Load(_In_reads_bytes_(len) const void* bytes, _In_ size_t len) noexcept;

        /// @brief Feed một event, đặt *deny = verdict cần chặn. Chữ ký khớp
        ///        Event::SyncEnforceCallback. Không có ruleset ⇒ *deny=false.
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS Feed(_In_ const Event::Event& evt, _Out_ bool* deny) noexcept;
    };
}
