#pragma once

#include <cstdint>

#include <RED4ext/CString.hpp>
#include <RED4ext/Common.hpp>
#include <RED4ext/Containers/DynArray.hpp>
#include <RED4ext/Handle.hpp>
#include <RED4ext/HashMap.hpp>
#include <RED4ext/Scripting/Natives/Generated/rend/SingleScreenShotData.hpp>
#include <RED4ext/Scripting/Natives/Generated/services/GameServices.hpp>

namespace RED4ext
{
namespace rtti
{
struct IType;
}
struct IScriptable;
struct CGameOptions;

namespace Memory
{
struct IAllocator;
}

enum class EEngineState : int32_t
{
    Idle = 0,
    BaseInitialization = 1,
    Initialization = 2,
    Running = 3
};

struct GameInstance
{
    virtual ~GameInstance() = 0;                                  // 00
    virtual IScriptable* GetSystem(const rtti::IType* aType) = 0; // 08
    virtual void Unk_10() = 0;                                    // 10
    virtual void Unk_18() = 0;                                    // 18
    virtual void Unk_20() = 0;                                    // 20
    virtual void Unk_28() = 0;                                    // 28
    virtual void Unk_30() = 0;                                    // 30
    virtual void Unk_38() = 0;                                    // 38
    virtual void Unk_40() = 0;                                    // 40
    virtual void Unk_48() = 0;                                    // 48
    virtual void Unk_50() = 0;                                    // 50
    virtual void Unk_58() = 0;                                    // 58
    virtual void Unk_60() = 0;                                    // 60
    virtual void Unk_68() = 0;                                    // 68

    HashMap<rtti::IType*, Handle<IScriptable>> systemMap;      // 08 - Maps implementation type to instance
    DynArray<Handle<IScriptable>> systemInstances;             // 38
    HashMap<rtti::IType*, rtti::IType*> systemImplementations; // 48 - Maps interface type to implementation type
    uintptr_t unk78[(0x138 - 0x78) >> 3];                      // 78
};
RED4EXT_ASSERT_SIZE(GameInstance, 0x138);

struct CBaseEngine
{
    struct UnkD0
    {
        uint8_t pad0[0x140];
        uint32_t unk140;
        uint8_t pad144[0x164 - 0x144];
        uint32_t unk164;
        uint8_t pad158[0x164 - 0x158];
        uint32_t unk174;
        void* hWnd;
        uint8_t pad180[0x9];
        uint8_t isClipped;
    };
    RED4EXT_ASSERT_OFFSET(UnkD0, unk164, 0x164);
    RED4EXT_ASSERT_OFFSET(UnkD0, unk174, 0x174);
    RED4EXT_ASSERT_OFFSET(UnkD0, hWnd, 0x178);
    RED4EXT_ASSERT_OFFSET(UnkD0, isClipped, 0x189);

    struct Unk108
    {
        int64_t unk0;
        int64_t unk8;
        int64_t unk10;
        int32_t unk18;
        int32_t unk1C;
    };
    RED4EXT_ASSERT_SIZE(Unk108, 0x20);

    struct Unk110
    {
        int8_t unk0;
        int32_t unk4;
        int32_t unk8;
        int32_t unkC;
    };
    RED4EXT_ASSERT_SIZE(Unk110, 0x10);

    virtual rtti::IType* GetNativeType() = 0;                                                   // 00
    virtual rtti::IType* GetParentType() = 0;                                                   // 08
    virtual Memory::IAllocator* GetAllocator() = 0;                                             // 10
    virtual ~CBaseEngine() = 0;                                                                 // 18
    virtual void sub_18() = 0;                                                                  // 20
    virtual void sub_28() = 0;                                                                  // 28
    virtual void sub_30() = 0;                                                                  // 30
    virtual void Terminate(int32_t aExitStatus) = 0;                                            // 38
    virtual void sub_40() = 0;                                                                  // 40
    virtual void sub_48() = 0;                                                                  // 48
    virtual void sub_50() = 0;                                                                  // 50
    virtual void sub_58() = 0;                                                                  // 58
    virtual void sub_60() = 0;                                                                  // 60
    virtual void sub_68() = 0;                                                                  // 68
    virtual void sub_70() = 0;                                                                  // 70
    virtual void sub_78() = 0;                                                                  // 78
    virtual void sub_80() = 0;                                                                  // 80
    virtual void sub_88() = 0;                                                                  // 88
    virtual void sub_90() = 0;                                                                  // 90
    virtual void sub_98() = 0;                                                                  // 98
    virtual void sub_A0() = 0;                                                                  // A0
    virtual void sub_A8() = 0;                                                                  // A8
    virtual void sub_B0() = 0;                                                                  // B0
    virtual void TakeScreenshot(const rend::SingleScreenShotData& acData, bool a2 = false) = 0; // B8
    virtual void sub_C0() = 0;                                                                  // C0
    virtual void sub_C8(CGameOptions& aOptions) = 0;                                            // C8
    virtual void sub_D0() = 0;                                                                  // D0
    virtual void sub_D8() = 0;                                                                  // D8
    virtual void sub_E0() = 0;                                                                  // E0
    virtual void sub_E8() = 0;                                                                  // E8
    virtual void sub_F0() = 0;                                                                  // F0
    virtual void sub_F8() = 0;                                                                  // F8
    virtual void sub_100() = 0;                                                                 // 100

    double unk8;                               // 08
    float unk10;                               // 10
    float unk14;                               // 14
    float unk18;                               // 18
    float unk1C;                               // 1C
    float unk20;                               // 20
    int64_t unk28;                             // 28
    int32_t unk30;                             // 30
    int8_t unk34;                              // 34
    uint64_t scriptsTimestamp;                 // 38
    int8_t unk40;                              // 40
    SharedSpinLock terminationLock;            // 41
    int32_t unk44;                             // 44
    int8_t terminating;                        // 48
    int8_t unk49;                              // 49
    int8_t unk4A;                              // 4A
    int8_t unk4B;                              // 4B
    int32_t exitStatus;                        // 4C
    int32_t unk50;                             // 50
    bool scriptsLoaded;                        // 54
    bool scriptsSilentCompilation;             // 55
    bool scriptsSilentValidation;              // 56
    int8_t unk57;                              // 57
    int8_t unk58;                              // 58
    int16_t unk5A;                             // 5A
    int32_t interopStartingPort;               // 5C
    int64_t unk60;                             // 60
    uint8_t unk68[0x90 - 0x68];                // 68 - grew by 0x20 in 2.5
    CString scriptsCompilationErrors;          // 90
    DynArray<CString> scriptsValidationErrors; // B0
    int64_t unkC0;                             // C0
    int64_t unkC8;                             // C8
    int64_t unkD0_;                            // D0
    int64_t unkD8;                             // D8
    uint8_t padE0[0x10];                       // E0
    UnkD0* unkD0;                              // F0
    double unkF8;                              // F8
    double unk100;                             // 100
    int32_t unk108;                            // 108
    int64_t unk110;                            // 110
    int64_t unk118;                            // 118
    int64_t unk120;                            // 120
    volatile EEngineState engineState;         // 128
    int32_t unk12C;                            // 12C
    int32_t unk130;                            // 130
    Unk108* unk138;                            // 138
    Unk110 unk140;                             // 140
    CString buildString;                       // 150
    CString scriptsBlobPath;                   // 170
    int32_t unk190;                            // 190
    int8_t unk194;                             // 194
    int64_t unk198;                            // 198
    int64_t unk1A0;                            // 1A0
    int64_t unk1A8;                            // 1A8
    int64_t unk1B0;                            // 1B0
    int8_t unk1B8[178];                        // 1B8
    int32_t unk26C;                            // 26C
    int8_t unk270[64];                         // 270
    DynArray<void*> unk2B0;                    // 2B0
    DynArray<void*> unk2C0;                    // 2C0
    int64_t unk2D0;                            // 2D0
    int64_t unk2D8;                            // 2D8
    int64_t unk2E0;                            // 2E0
    int64_t unk2E8;                            // 2E8
    int32_t unk2F0;                            // 2F0
    bool isEP1;                                // 2F4 - IsEP1()
    uint8_t unk2F8[0x318 - 0x2F8];             // 2F8 - new in 2.5
    int64_t unk318;                            // 318
    int64_t unk320;                            // 320
};
// Game 2.5 (3.0.88.46235): the RTTI size of CBaseEngine is 0x2D8 -> 0x318 (registration 0x158C6CC); this struct
// also holds the next 0x10 bytes. Its constructor (2.31 0x1250CE8, 2.5 0xA59C44) stores the same values up to 0x60
// (`mov dword ptr [rcx+0x54], 0x1000000` in both: scriptsLoaded unchanged), then every member from 0x70 on sits
// 0x20 higher: the CString at 0x70 (2.31 byte [rcx+0x70], dword [+0x84], qword [+0x88]) is at 0x90 (byte [rbx+0x90],
// dword [+0xA4], qword [+0xA8]); the DynArray at 0x90 is at 0xB0; Unk110 0x120 -> 0x140 (2.31 `mov byte ptr
// [rbx+0x120], 2`, 2.5 `mov byte ptr [rbx+0x140], 2`); scriptsBlobPath 0x150 -> 0x170; isEP1 0x2D4 -> 0x2F4 (2.31
// `mov byte ptr [rbx+0x2D4], sil`, 2.5 `mov byte ptr [rbx+0x2F4], sil`); 2.5 adds `lea rcx, [rbx+0x2F8]`.
// UnkD0's own fields (hWnd, isClipped) are not re-derived for 2.5.
RED4EXT_ASSERT_SIZE(CBaseEngine, 0x328);
RED4EXT_ASSERT_OFFSET(CBaseEngine, scriptsLoaded, 0x54);
RED4EXT_ASSERT_OFFSET(CBaseEngine, unkD0, 0xF0);
RED4EXT_ASSERT_OFFSET(CBaseEngine, scriptsValidationErrors, 0xB0);
RED4EXT_ASSERT_OFFSET(CBaseEngine, scriptsBlobPath, 0x170);
RED4EXT_ASSERT_OFFSET(CBaseEngine, isEP1, 0x2F4);

struct BaseGameEngine : CBaseEngine
{
    int64_t unk328; // 328
};
// Game 2.5: RTTI size 0x2E0 -> 0x320; its constructor's one store moved 0x2D8 -> 0x318 (2.31 0x1250C60, 2.5 0xA59BBC).
RED4EXT_ASSERT_SIZE(BaseGameEngine, 0x330);

struct CGameEngine : BaseGameEngine
{
    struct CGameFramework
    {
        uintptr_t unk00;            // 00
        uintptr_t unk08;            // 08
        GameInstance* gameInstance; // 10
        uintptr_t unk18;            // 18 - worldRuntimeScene
        uintptr_t unk20;            // 20
    };
    RED4EXT_ASSERT_SIZE(CGameFramework, 0x28);
    RED4EXT_ASSERT_OFFSET(CGameFramework, gameInstance, 0x10);

    static CGameEngine* Get();

    int64_t unk330;                       // 330
    int64_t unk338;                       // 338
    int32_t unk340;                       // 340
    int32_t unk344;                       // 344
    CGameFramework* framework;            // 348
    services::GameServices* gameServices; // 350
    int64_t unk358;                       // 358
    int64_t unk360;                       // 360
    int64_t unk368;                       // 368
    int64_t unk370;                       // 370
    int64_t unk378;                       // 378
    int32_t unk380;                       // 380
    int64_t unk388;                       // 388
};
// Game 2.5 (3.0.88.46235): RTTI size 0x350 -> 0x390 (registration 0x15BB1FC). Every constructor store moved by 0x40
// (2.31 0x1250B28, 2.5 0xA59A84): [rbx+0x2E0] -> [rbx+0x320], byte [rbx+0x2E8] -> [rbx+0x328], [rbx+0x308] ->
// [rbx+0x348] (framework), [rbx+0x310] -> [rbx+0x350], `lea rcx, [rbx+0x340]` -> `lea rcx, [rbx+0x380]`.
RED4EXT_ASSERT_SIZE(CGameEngine, 0x390);
RED4EXT_ASSERT_OFFSET(CGameEngine, framework, 0x348);
RED4EXT_ASSERT_OFFSET(CGameEngine, gameServices, 0x350);
} // namespace RED4ext

#ifdef RED4EXT_HEADER_ONLY
#include <RED4ext/GameEngine-inl.hpp>
#endif
