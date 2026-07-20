/********************
*     Includes      *
********************/

#include "krn.hpp"
#include "Engine.hpp"

/*********************
*   Local helpers    *
*********************/
namespace
{
    // Case-insensitive UTF-16 substring (ASCII fold — image/cmdline are ASCII).
    bool ContainsCi(const Event::String& s, PCWSTR needle)
    {
        if (!s.Buffer || s.Length == 0)
            return false;
        const SIZE_T slen = s.Length / sizeof(WCHAR);
        SIZE_T nlen = 0;
        while (needle[nlen]) nlen++;
        if (nlen == 0 || nlen > slen)
            return false;

        auto lower = [](WCHAR c) -> WCHAR { return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + 32) : c; };
        for (SIZE_T i = 0; i + nlen <= slen; i++)
        {
            SIZE_T j = 0;
            for (; j < nlen; j++)
                if (lower(s.Buffer[i + j]) != lower(needle[j]))
                    break;
            if (j == nlen)
                return true;
        }
        return false;
    }

    // Process identity → 128-bit engine Key: lo = pid, hi = create time (chống pid-reuse).
    void PackProc(ULONG pid, LONGLONG createTime, UINT64* lo, UINT64* hi)
    {
        *lo = (UINT64)pid;
        *hi = (UINT64)createTime;
    }

    // File identity → 128-bit: FNV-1a 64 hai lần (lo/hi) trên tên UTF-16.
    // (Lý tưởng là NTFS FileId; tạm hash tên đã chuẩn hoá — collision 128-bit ~ 0.)
    void PackFile(const Event::String& s, UINT64* lo, UINT64* hi)
    {
        UINT64 h1 = 1469598103934665603ULL;
        UINT64 h2 = 1099511628211ULL;
        const BYTE* p = (const BYTE*)s.Buffer;
        for (ULONG i = 0; i < s.Length; i++)
        {
            h1 = (h1 ^ p[i]) * 1099511628211ULL;
            h2 = (h2 ^ p[i]) * 1469598103934665603ULL;
        }
        *lo = h1;
        *hi = h2;
    }

    // Map một event driver → EngineEvent. Trả false nếu loại event không có op engine.
    bool MapEvent(const Event::Event& e, EngineEvent* out)
    {
        RtlZeroMemory(out, sizeof(*out));
        out->ts = (UINT64)e.TimeStamp.QuadPart;
        // actor = tiến trình đang hành động (parent với ProcessCreate — theo Event.hpp).
        PackProc(e.ProcessId, e.ProcessCreateTime.QuadPart, &out->actor_lo, &out->actor_hi);
        out->actor_kind = ENGINE_KIND_PROCESS;

        switch (e.Type)
        {
        case Event::ProcessCreate:
        {
            auto& p = static_cast<const Event::ProcessCreateEvent&>(e);
            out->op = ENGINE_OP_EXEC;
            PackProc(p.ChildProcessId, p.ChildCreateTime.QuadPart, &out->object_lo, &out->object_hi);
            out->object_kind = ENGINE_KIND_PROCESS;
            return true;
        }
        case Event::ProcessOpen:
        {
            auto& p = static_cast<const Event::ProcessOpenEvent&>(e);
            out->op = ENGINE_OP_OPEN;
            PackProc(p.TargetProcessId, p.TargetCreateTime.QuadPart, &out->object_lo, &out->object_hi);
            out->object_kind = ENGINE_KIND_PROCESS;
            return true;
        }
        case Event::RemoteThreadCreate:
        {
            auto& p = static_cast<const Event::RemoteThreadCreateEvent&>(e);
            out->op = ENGINE_OP_INJECT;
            PackProc(p.TargetProcessId, p.TargetCreateTime.QuadPart, &out->object_lo, &out->object_hi);
            out->object_kind = ENGINE_KIND_PROCESS;
            return true;
        }
        case Event::FileWrite:
        {
            auto& p = static_cast<const Event::FileWriteEvent&>(e);
            out->op = ENGINE_OP_WRITE;
            PackFile(p.FileName, &out->object_lo, &out->object_hi);
            out->object_kind = ENGINE_KIND_FILE;
            return true;
        }
        case Event::FileRead:
        {
            auto& p = static_cast<const Event::FileReadEvent&>(e);
            out->op = ENGINE_OP_READ;
            PackFile(p.FileName, &out->object_lo, &out->object_hi); // thư mục bị liệt kê
            out->object_kind = ENGINE_KIND_FILE;
            return true;
        }
        default:
            // ProcessExit / FileOpen / Invalid — engine v0.0.2 chưa có op tương ứng.
            return false;
        }
    }

    // ---- Predicate tagger (đọc tín hiệu kernel). Mỗi cái chỉ chạy cho đúng op nó gắn. ----
    bool IsLolbinExec(const Event::Event& e)
    {
        auto& p = static_cast<const Event::ProcessCreateEvent&>(e);
        return ContainsCi(p.ImageName, L"powershell") || ContainsCi(p.ImageName, L"cmd.exe")
            || ContainsCi(p.ImageName, L"wscript") || ContainsCi(p.ImageName, L"cscript")
            || ContainsCi(p.ImageName, L"mshta");
    }
    bool IsVssadminDelete(const Event::Event& e)
    {
        auto& p = static_cast<const Event::ProcessCreateEvent&>(e);
        return ContainsCi(p.ImageName, L"vssadmin")
            && ContainsCi(p.CommandLine, L"delete") && ContainsCi(p.CommandLine, L"shadow");
    }
    bool IsLsassRead(const Event::Event& e)
    {
        auto& p = static_cast<const Event::ProcessOpenEvent&>(e);
        return (p.DesiredAccess & 0x0010 /*PROCESS_VM_READ*/) != 0 && ContainsCi(p.TargetImage, L"lsass");
    }
    bool IsHighEntropyWrite(const Event::Event& e)
    {
        return static_cast<const Event::FileWriteEvent&>(e).HighEntropy; // T1486
    }
    bool IsDirEnum(const Event::Event& e)
    {
        return static_cast<const Event::FileReadEvent&>(e).DirEnum; // T1083
    }
    bool Always(const Event::Event&) { return true; }

    // Catalogue driver biết cách tính. WHICH cái bật do rule quyết định (RebuildTaggers_).
    const Engine::Tagger CATALOGUE[] = {
        { ENGINE_OP_EXEC,   1059, IsLolbinExec },
        { ENGINE_OP_EXEC,   1490, IsVssadminDelete },
        { ENGINE_OP_OPEN,   1003, IsLsassRead },
        { ENGINE_OP_WRITE,  1486, IsHighEntropyWrite },
        { ENGINE_OP_READ,   1083, IsDirEnum },
        { ENGINE_OP_INJECT, 1055, Always },
    };
}

/*********************
*   Implementations  *
*********************/
namespace Engine
{
    Instance::Instance() noexcept
    {
        ExInitializePushLock(&_lock);
        // Không có rule tới lúc bring-up: engine rỗng, mọi verdict = IGNORE.
        _handle = engine_create(nullptr, 0);
        _status = _handle ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }

    Instance::~Instance()
    {
        if (_handle)
            engine_destroy(_handle);
    }

    void Instance::RebuildTaggers_()
    {
        for (ULONG i = 0; i < NUM_OPS; i++)
            _count[i] = 0;

        UINT32 used[64];
        size_t n = engine_referenced_ttps(_handle, used, ARRAYSIZE(used));
        if (n > ARRAYSIZE(used))
            n = ARRAYSIZE(used); // ruleset dùng > 64 TTP: phần dôi bị bỏ (đủ rộng thực tế)

        auto referenced = [&](UINT32 ttp) {
            for (size_t i = 0; i < n; i++)
                if (used[i] == ttp) return true;
            return false;
        };

        for (const auto& t : CATALOGUE)
        {
            if (!referenced(t.ttp))
                continue;
            const ULONG op = (ULONG)t.op;
            if (op < NUM_OPS && _count[op] < MAX_PER_OP)
                _by_op[op][_count[op]++] = &t;
        }
    }

    NTSTATUS Instance::Load(const void* bytes, size_t len) noexcept
    {
        EngineHandle fresh = engine_create((const uint8_t*)bytes, len);
        if (!fresh)
            return STATUS_INVALID_PARAMETER; // wire bytes không hợp lệ

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&_lock);
        EngineHandle old = _handle;
        _handle = fresh;
        RebuildTaggers_();
        ExReleasePushLockExclusive(&_lock);
        KeLeaveCriticalRegion();

        if (old)
            engine_destroy(old);
        return STATUS_SUCCESS;
    }

    NTSTATUS Instance::Feed(const Event::Event& evt, bool* deny) noexcept
    {
        *deny = false;

        EngineEvent ce;
        if (!MapEvent(evt, &ce))
            return STATUS_SUCCESS; // loại event engine không quan tâm

        UINT32 ttps[MAX_TTPS];
        ULONG nttps = 0;

        // engine_core::on_event là &mut (không thread-safe) → serialize exclusive.
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&_lock);

        if (_handle)
        {
            const ULONG op = ce.op;
            if (op < NUM_OPS)
            {
                for (ULONG i = 0; i < _count[op] && nttps < MAX_TTPS; i++)
                    if (_by_op[op][i]->match(evt))
                        ttps[nttps++] = _by_op[op][i]->ttp;
            }
            const UINT32 verdict = engine_on_event(_handle, &ce, ttps, nttps);
            *deny = (verdict >= ENGINE_VERDICT_BLOCK); // BLOCK(2) hoặc DISARM(3)
        }

        ExReleasePushLockExclusive(&_lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }
}
