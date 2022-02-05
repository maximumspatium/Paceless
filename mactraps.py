import rsrcfork
from bare68k.consts import *
import bare68k.api.traps as traps
from macmemory import MacMemory
from collections import defaultdict
import utils

UNIMPLEMENTED_TRAP = 0xA89F
UNIMPL_TRAP_ADDR   = 0xFFFF0000

LM_RESLOAD = 0xA5E

TRAP_TABLE = {
    # trap #    trap name               method name             trap address  params
    0xA000 : ("_Open",                  'unimplemented_trap',   0xFFFFFFFF),
    0xA001 : ("_Close",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA002 : ("_Read",                  'unimplemented_trap',   0xFFFFFFFF),
    0xA003 : ("_Write",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA004 : ("_Control",               'unimplemented_trap',   0xFFFFFFFF),
    0xA005 : ("_Status",                'unimplemented_trap',   0xFFFFFFFF),
    0xA006 : ("_KillIO",                'unimplemented_trap',   0xFFFFFFFF),
    0xA007 : ("_GetVolInfo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA008 : ("_Create",                'unimplemented_trap',   0xFFFFFFFF),
    0xA009 : ("_Delete",                'unimplemented_trap',   0xFFFFFFFF),
    0xA00A : ("_OpenRF",                'unimplemented_trap',   0xFFFFFFFF),
    0xA00B : ("_Rename",                'unimplemented_trap',   0xFFFFFFFF),
    0xA00C : ("_GetFileInfo",           'unimplemented_trap',   0xFFFFFFFF),
    0xA00D : ("_SetFileInfo",           'unimplemented_trap',   0xFFFFFFFF),
    0xA00E : ("_UnmountVol",            'unimplemented_trap',   0xFFFFFFFF),
    0xA00F : ("_MountVol",              'unimplemented_trap',   0xFFFFFFFF),
    0xA010 : ("_Allocate",              'unimplemented_trap',   0xFFFFFFFF),
    0xA011 : ("_GetEOF",                'unimplemented_trap',   0xFFFFFFFF),
    0xA012 : ("_SetEOF",                'unimplemented_trap',   0xFFFFFFFF),
    0xA013 : ("_FlushVol",              'unimplemented_trap',   0xFFFFFFFF),
    0xA014 : ("_GetVol",                'unimplemented_trap',   0xFFFFFFFF),
    0xA015 : ("_SetVol",                'unimplemented_trap',   0xFFFFFFFF),
    0xA016 : ("_FInitQueue",            'unimplemented_trap',   0xFFFFFFFF),
    0xA017 : ("_Eject",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA018 : ("_GetFPos",               'unimplemented_trap',   0xFFFFFFFF),
    0xA019 : ("_InitZone",              'unimplemented_trap',   0xFFFFFFFF),
    0xA01B : ("_SetZone",               'dummy_trap',           0xFFF30100),
    0xA01C : ("_FreeMem",               'unimplemented_trap',   0xFFFFFFFF),
    0xA01F : ("_DisposePtr",            'dummy_trap',           0xFFF30110),
    0xA020 : ("_SetPtrSize",            'unimplemented_trap',   0xFFFFFFFF),
    0xA021 : ("_GetPtrSize",            'unimplemented_trap',   0xFFFFFFFF),
    0xA023 : ("_DisposeHandle",         'unimplemented_trap',   0xFFFFFFFF),
    0xA024 : ("_SetHandleSize",         'unimplemented_trap',   0xFFFFFFFF),
    0xA025 : ("_GetHandleSize",         'get_handle_size',      0xFFF30D30),
    0xA027 : ("_ReallocHandle",         'unimplemented_trap',   0xFFFFFFFF),
    0xA029 : ("_HLock",                 'dummy_trap',           0xFFF30204),
    0xA02A : ("_HUnlock",               'unimplemented_trap',   0xFFFFFFFF),
    0xA02B : ("_EmptyHandle",           'unimplemented_trap',   0xFFFFFFFF),
    0xA02C : ("_InitApplZone",          'unimplemented_trap',   0xFFFFFFFF),
    0xA02D : ("_SetApplLimit",          'unimplemented_trap',   0xFFFFFFFF),
    0xA02E : ("_BlockMove",             'block_copy',           0xFFF30308),
    0xA02F : ("_PostEvent",             'unimplemented_trap',   0xFFFFFFFF),
    0xA030 : ("_OSEventAvail",          'unimplemented_trap',   0xFFFFFFFF),
    0xA031 : ("_GetOSEvent",            'unimplemented_trap',   0xFFFFFFFF),
    0xA032 : ("_FlushEvents",           'unimplemented_trap',   0xFFFFFFFF),
    0xA033 : ("_VInstall",              'unimplemented_trap',   0xFFFFFFFF),
    0xA034 : ("_VRemove",               'unimplemented_trap',   0xFFFFFFFF),
    0xA035 : ("_OffLine",               'unimplemented_trap',   0xFFFFFFFF),
    0xA036 : ("_MoreMasters",           'unimplemented_trap',   0xFFFFFFFF),
    0xA038 : ("_WriteParam",            'unimplemented_trap',   0xFFFFFFFF),
    0xA039 : ("_ReadDateTime",          'unimplemented_trap',   0xFFFFFFFF),
    0xA03A : ("_SetDateTime",           'unimplemented_trap',   0xFFFFFFFF),
    0xA03B : ("_Delay",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA03C : ("_CmpString",             'unimplemented_trap',   0xFFFFFFFF),
    0xA03D : ("_DrvrInstall",           'unimplemented_trap',   0xFFFFFFFF),
    0xA03E : ("_DrvrRemove",            'unimplemented_trap',   0xFFFFFFFF),
    0xA03F : ("_InitUtil",              'unimplemented_trap',   0xFFFFFFFF),
    0xA040 : ("_ResrvMem",              'unimplemented_trap',   0xFFFFFFFF),
    0xA041 : ("_SetFilLock",            'unimplemented_trap',   0xFFFFFFFF),
    0xA042 : ("_RstFilLock",            'unimplemented_trap',   0xFFFFFFFF),
    0xA043 : ("_SetFilType",            'unimplemented_trap',   0xFFFFFFFF),
    0xA044 : ("_SetFPos",               'unimplemented_trap',   0xFFFFFFFF),
    0xA045 : ("_FlushFile",             'unimplemented_trap',   0xFFFFFFFF),
    0xA047 : ("_SetTrapAddress",        'unimplemented_trap',   0xFFFFFFFF),
    0xA049 : ("_HPurge",                'unimplemented_trap',   0xFFFFFFFF),
    0xA04A : ("_HNoPurge",              'dummy_trap',           0xFFF30340),
    0xA04B : ("_SetGrowZone",           'unimplemented_trap',   0xFFFFFFFF),
    0xA04C : ("_CompactMem",            'unimplemented_trap',   0xFFFFFFFF),
    0xA04D : ("_PurgeMem",              'unimplemented_trap',   0xFFFFFFFF),
    0xA04E : ("_AddDrive",              'unimplemented_trap',   0xFFFFFFFF),
    0xA04F : ("_RDrvrInstall",          'unimplemented_trap',   0xFFFFFFFF),
    0xA050 : ("_CompareString",         'unimplemented_trap',   0xFFFFFFFF),
    0xA051 : ("_ReadXPRam",             'unimplemented_trap',   0xFFFFFFFF),
    0xA052 : ("_WriteXPRam",            'unimplemented_trap',   0xFFFFFFFF),
    0xA054 : ("_UprString",             'unimplemented_trap',   0xFFFFFFFF),
    0xA055 : ("_StripAddress",          'dummy_trap',           0xFFF3040C),
    0xA056 : ("_LowerText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA057 : ("_SetApplBase",           'unimplemented_trap',   0xFFFFFFFF),
    0xA058 : ("_InsTime",               'unimplemented_trap',   0xFFFFFFFF),
    0xA059 : ("_RmvTime",               'unimplemented_trap',   0xFFFFFFFF),
    0xA05A : ("_PrimeTime",             'unimplemented_trap',   0xFFFFFFFF),
    0xA05B : ("_PowerOff",              'unimplemented_trap',   0xFFFFFFFF),
    0xA05C : ("_MemoryDispatch",        'unimplemented_trap',   0xFFFFFFFF),
    0xA05D : ("_SwapMMUMode",           'unimplemented_trap',   0xFFFFFFFF),
    0xA05E : ("_NMInstall",             'unimplemented_trap',   0xFFFFFFFF),
    0xA05F : ("_NMRemove",              'unimplemented_trap',   0xFFFFFFFF),
    0xA060 : ("_FSDispatch",            'unimplemented_trap',   0xFFFFFFFF),
    0xA061 : ("_MaxBlock",              'unimplemented_trap',   0xFFFFFFFF),
    0xA062 : ("_PurgeSpace",            'unimplemented_trap',   0xFFFFFFFF),
    0xA063 : ("_MaxApplZone",           'unimplemented_trap',   0xFFFFFFFF),
    0xA064 : ("_MoveHHi",               'dummy_trap',           0xFFF30510),
    0xA065 : ("_StackSpace",            'unimplemented_trap',   0xFFFFFFFF),
    0xA066 : ("_NewEmptyHandle",        'unimplemented_trap',   0xFFFFFFFF),
    0xA067 : ("_HSetRBit",              'unimplemented_trap',   0xFFFFFFFF),
    0xA068 : ("_HClrRBit",              'unimplemented_trap',   0xFFFFFFFF),
    0xA069 : ("_HGetState",             'dummy_trap',           0xFFF30514),
    0xA06A : ("_HSetState",             'dummy_trap',           0xFFF30518),
    0xA06C : ("_InitFS",                'unimplemented_trap',   0xFFFFFFFF),
    0xA06D : ("_InitEvents",            'unimplemented_trap',   0xFFFFFFFF),
    0xA06E : ("_SlotManager",           'unimplemented_trap',   0xFFFFFFFF),
    0xA06F : ("_SlotVInstall",          'unimplemented_trap',   0xFFFFFFFF),
    0xA070 : ("_SlotVRemove",           'unimplemented_trap',   0xFFFFFFFF),
    0xA071 : ("_AttachVBL",             'unimplemented_trap',   0xFFFFFFFF),
    0xA072 : ("_DoVBLTask",             'unimplemented_trap',   0xFFFFFFFF),
    0xA075 : ("_SIntInstall",           'unimplemented_trap',   0xFFFFFFFF),
    0xA076 : ("_SIntRemove",            'unimplemented_trap',   0xFFFFFFFF),
    0xA077 : ("_CountADBs",             'unimplemented_trap',   0xFFFFFFFF),
    0xA078 : ("_GetIndADB",             'unimplemented_trap',   0xFFFFFFFF),
    0xA079 : ("_GetADBInfo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA07A : ("_SetADBInfo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA07B : ("_ADBReInit",             'unimplemented_trap',   0xFFFFFFFF),
    0xA07C : ("_ADBOp",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA07D : ("_GetDefaultStartup",     'unimplemented_trap',   0xFFFFFFFF),
    0xA07E : ("_SetDefaultStartup",     'unimplemented_trap',   0xFFFFFFFF),
    0xA07F : ("_InternalWait",          'unimplemented_trap',   0xFFFFFFFF),
    0xA080 : ("_GetVideoDefault",       'unimplemented_trap',   0xFFFFFFFF),
    0xA081 : ("_SetVideoDefault",       'unimplemented_trap',   0xFFFFFFFF),
    0xA082 : ("_DTInstall",             'unimplemented_trap',   0xFFFFFFFF),
    0xA083 : ("_SetOSDefault",          'unimplemented_trap',   0xFFFFFFFF),
    0xA084 : ("_GetOSDefault",          'unimplemented_trap',   0xFFFFFFFF),
    0xA085 : ("_PMgrOp",                'unimplemented_trap',   0xFFFFFFFF),
    0xA086 : ("_IOPInfoAccess",         'unimplemented_trap',   0xFFFFFFFF),
    0xA087 : ("_IOPMsgRequest",         'unimplemented_trap',   0xFFFFFFFF),
    0xA088 : ("_IOPMoveData",           'unimplemented_trap',   0xFFFFFFFF),
    0xA089 : ("_SCSIAtomic",            'unimplemented_trap',   0xFFFFFFFF),
    0xA08A : ("_Sleep",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA08B : ("_CommToolboxDispatch",   'unimplemented_trap',   0xFFFFFFFF),
    0xA08D : ("_DebugUtil",             'unimplemented_trap',   0xFFFFFFFF),
    0xA08F : ("_DeferUserFn",           'unimplemented_trap',   0xFFFFFFFF),
    0xA090 : ("_SysEnvirons",           'unimplemented_trap',   0xFFFFFFFF),
    0xA091 : ("_Translate24To32",       'unimplemented_trap',   0xFFFFFFFF),
    0xA092 : ("_EgretDispatch",         'unimplemented_trap',   0xFFFFFFFF),
    0xA09F : ("_PowerDispatch",         'unimplemented_trap',   0xFFFFFFFF),
    0xA0A4 : ("_HeapDispatch",          'unimplemented_trap',   0xFFFFFFFF),
    0xA0AD : ("_GestaltDispatch",       'dummy_trap',           0xFFF30614),
    0xA0AE : ("_VADBProc",              'unimplemented_trap',   0xFFFFFFFF),
    0xA0BD : ("_CacheFlush",            'dummy_trap',           0xFFF30718),
    0xA0DD : ("_PPC",                   'unimplemented_trap',   0xFFFFFFFF),
    0xA0FE : ("_TEFindWord",            'unimplemented_trap',   0xFFFFFFFF),
    0xA0FF : ("_TEFindLine",            'unimplemented_trap',   0xFFFFFFFF),
    0xA11A : ("_GetZone",               'dummy_trap',           0xFFF3081C),
    0xA11D : ("_MaxMem",                'unimplemented_trap',   0xFFFFFFFF),
    0xA11E : ("_NewPtr",                'new_ptr',              0xFFF30820),
    0xA122 : ("_NewHandle",             'new_handle',           0xFFF30920),
    0xA126 : ("_HandleZone",            'unimplemented_trap',   0xFFFFFFFF),
    0xA128 : ("_RecoverHandle",         'recover_handle',       0xFFF30A24),
    0xA12F : ("_PPostEvent",            'unimplemented_trap',   0xFFFFFFFF),
    0xA146 : ("_GetTrapAddress",        'get_trap_addr',        0xFFF30A30),
    0xA148 : ("_PtrZone",               'unimplemented_trap',   0xFFFFFFFF),
    0xA15C : ("_MemoryDispatchA0Result",'unimplemented_trap',   0xFFFFFFFF),
    0xA162 : ("_PurgeSpace",            'dummy_trap',           0xFFF30B28),
    0xA166 : ("_NewEmptyHandle",        'unimplemented_trap',   0xFFFFFFFF),
    0xA193 : ("_Microseconds",          'unimplemented_trap',   0xFFFFFFFF),
    0xA198 : ("_HWPriv",                'unimplemented_trap',   0xFFFFFFFF),
    0xA1AD : ("_Gestalt",               'gestalt',              0xFFF30C2C),
    0xA200 : ("_HOpen",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA204 : ("_ControlImmed",          'unimplemented_trap',   0xFFFFFFFF),
    0xA207 : ("_HGetVInfo",             'unimplemented_trap',   0xFFFFFFFF),
    0xA208 : ("_HCreate",               'unimplemented_trap',   0xFFFFFFFF),
    0xA209 : ("_HDelete",               'unimplemented_trap',   0xFFFFFFFF),
    0xA20A : ("_HOpenRF",               'unimplemented_trap',   0xFFFFFFFF),
    0xA20B : ("_HRename",               'unimplemented_trap',   0xFFFFFFFF),
    0xA20C : ("_HGetFileInfo",          'unimplemented_trap',   0xFFFFFFFF),
    0xA20D : ("_HSetFileInfo",          'unimplemented_trap',   0xFFFFFFFF),
    0xA20E : ("_HUnmountVol",           'unimplemented_trap',   0xFFFFFFFF),
    0xA210 : ("_AllocContig",           'unimplemented_trap',   0xFFFFFFFF),
    0xA214 : ("_HGetVol",               'unimplemented_trap',   0xFFFFFFFF),
    0xA215 : ("_HSetVol",               'unimplemented_trap',   0xFFFFFFFF),
    0xA22E : ("_BlockMoveData",         'unimplemented_trap',   0xFFFFFFFF),
    0xA23C : ("_CmpStringMarks",        'unimplemented_trap',   0xFFFFFFFF),
    0xA241 : ("_SetFilLock",            'unimplemented_trap',   0xFFFFFFFF),
    0xA242 : ("_RstFilLock",            'unimplemented_trap',   0xFFFFFFFF),
    0xA247 : ("_SetOSTrapAddress",      'unimplemented_trap',   0xFFFFFFFF),
    0xA254 : ("_UprStringMarks",        'unimplemented_trap',   0xFFFFFFFF),
    0xA256 : ("_StripText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA260 : ("_HFSDispatch",           'hfs_dispatch',         0xFFF30D50),
    0xA285 : ("_IdleUpdate",            'unimplemented_trap',   0xFFFFFFFF),
    0xA28A : ("_SleepQInstall",         'unimplemented_trap',   0xFFFFFFFF),
    0xA31E : ("_NewPtrClear",           'new_ptr',              0xFFF30E34),
    0xA322 : ("_NewHandleClear",        'new_handle',           0xFFF30F38),
    0xA346 : ("_GetOSTrapAddress",      'get_trap_addr',        0xFFF30F3C),
    0xA3AD : ("_NewGestalt",            'unimplemented_trap',   0xFFFFFFFF),
    0xA402 : ("_ReadAsync",             'unimplemented_trap',   0xFFFFFFFF),
    0xA403 : ("_WriteAsync",            'unimplemented_trap',   0xFFFFFFFF),
    0xA404 : ("_ControlAsync",          'unimplemented_trap',   0xFFFFFFFF),
    0xA41C : ("_FreeMemSys",            'unimplemented_trap',   0xFFFFFFFF),
    0xA43C : ("_CmpStringCase",         'unimplemented_trap',   0xFFFFFFFF),
    0xA43D : ("_DrvrInstallResrvMem",   'unimplemented_trap',   0xFFFFFFFF),
    0xA440 : ("_ResrvMemSys",           'unimplemented_trap',   0xFFFFFFFF),
    0xA44D : ("_PurgeMemSys",           'unimplemented_trap',   0xFFFFFFFF),
    0xA456 : ("_UpperText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA458 : ("_InsXTime",              'unimplemented_trap',   0xFFFFFFFF),
    0xA461 : ("_MaxBlockSys",           'unimplemented_trap',   0xFFFFFFFF),
    0xA485 : ("_IdleState",             'unimplemented_trap',   0xFFFFFFFF),
    0xA48A : ("_SleepQRemove",          'unimplemented_trap',   0xFFFFFFFF),
    0xA51E : ("_NewPtrSys",             'new_ptr',              0xFFF31020),
    0xA522 : ("_NewHandleSys",          'new_handle',           0xFFF31040),
    0xA53D : ("_DrvrInstallResrvMemA0Result",   'unimplemented_trap',   0xFFFFFFFF),
    0xA562 : ("_PurgeSpaceSys",         'unimplemented_trap',   0xFFFFFFFF),
    0xA5AD : ("_ReplaceGestalt",        'unimplemented_trap',   0xFFFFFFFF),
    0xA63C : ("_CmpStringCaseMarks",    'unimplemented_trap',   0xFFFFFFFF),
    0xA647 : ("_SetToolBoxTrapAddress", 'unimplemented_trap',   0xFFFFFFFF),
    0xA656 : ("_StripUpperText",        'unimplemented_trap',   0xFFFFFFFF),
    0xA685 : ("_SerialPower",           'unimplemented_trap',   0xFFFFFFFF),
    0xA71E : ("_NewPtrSysClear",        'new_ptr',              0xFFF31050),
    0xA722 : ("_NewHandleSysClear",     'new_handle',           0xFFF31080),
    0xA746 : ("_GetToolTrapAddress",    'get_trap_addr',        0xFFF32040),
    0xA7AD : ("_GetGestaltProcPtr",     'unimplemented_trap',   0xFFFFFFFF),
    0xA800 : ("_SoundDispatch",         'unimplemented_trap',   0xFFFFFFFF),
    0xA801 : ("_SndDisposeChannel",     'unimplemented_trap',   0xFFFFFFFF),
    0xA802 : ("_SndAddModifier",        'unimplemented_trap',   0xFFFFFFFF),
    0xA803 : ("_SndDoCommand",          'unimplemented_trap',   0xFFFFFFFF),
    0xA804 : ("_SndDoImmediate",        'unimplemented_trap',   0xFFFFFFFF),
    0xA805 : ("_SndPlay",               'unimplemented_trap',   0xFFFFFFFF),
    0xA806 : ("_SndControl",            'unimplemented_trap',   0xFFFFFFFF),
    0xA807 : ("_SndNewChannel",         'unimplemented_trap',   0xFFFFFFFF),
    0xA808 : ("_InitProcMenu",          'unimplemented_trap',   0xFFFFFFFF),
    0xA809 : ("_GetControlVariant",     'unimplemented_trap',   0xFFFFFFFF),
    0xA80A : ("_GetWVariant",           'unimplemented_trap',   0xFFFFFFFF),
    0xA80B : ("_PopUpMenuSelect",       'unimplemented_trap',   0xFFFFFFFF),
    0xA80C : ("_RGetResource",          'unimplemented_trap',   0xFFFFFFFF),
    0xA80D : ("_Count1Resources",       'unimplemented_trap',   0xFFFFFFFF),
    0xA80E : ("_Get1IxResource",        'unimplemented_trap',   0xFFFFFFFF),
    0xA80F : ("_Get1IxType",            'unimplemented_trap',   0xFFFFFFFF),
    0xA810 : ("_Unique1ID",             'unimplemented_trap',   0xFFFFFFFF),
    0xA811 : ("_TESelView",             'unimplemented_trap',   0xFFFFFFFF),
    0xA812 : ("_TEPinScroll",           'unimplemented_trap',   0xFFFFFFFF),
    0xA813 : ("_TEAutoView",            'unimplemented_trap',   0xFFFFFFFF),
    0xA814 : ("_SetFractEnable",        'unimplemented_trap',   0xFFFFFFFF),
    0xA815 : ("_SCSIDispatch",          'unimplemented_trap',   0xFFFFFFFF),
    0xA816 : ("_Pack8",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA817 : ("_CopyMask",              'unimplemented_trap',   0xFFFFFFFF),
    0xA818 : ("_FixATan2",              'unimplemented_trap',   0xFFFFFFFF),
    0xA819 : ("_XMunger",               'unimplemented_trap',   0xFFFFFFFF),
    0xA81A : ("_HOpenResFile",          'unimplemented_trap',   0xFFFFFFFF),
    0xA81B : ("_HCreateResFile",        'unimplemented_trap',   0xFFFFFFFF),
    0xA81C : ("_Count1Types",           'unimplemented_trap',   0xFFFFFFFF),
    0xA81D : ("_InvalMenuBar",          'unimplemented_trap',   0xFFFFFFFF),
    0xA81F : ("_Get1Resource",          'get_resource',         0xFFF33000, 'W', 'L'),
    0xA820 : ("_Get1NamedResource",     'named_resource',       0xFFF33004, 'L', 'L'),
    0xA821 : ("_MaxSizeRsrc",           'unimplemented_trap',   0xFFFFFFFF),
    0xA822 : ("_ResourceDispatch",      'unimplemented_trap',   0xFFFFFFFF),
    0xA823 : ("_AliasDispatch",         'unimplemented_trap',   0xFFFFFFFF),
    0xA826 : ("_InsertMenuItem",        'unimplemented_trap',   0xFFFFFFFF),
    0xA827 : ("_HideDialogItem",        'unimplemented_trap',   0xFFFFFFFF),
    0xA828 : ("_ShowDialogItem",        'unimplemented_trap',   0xFFFFFFFF),
    0xA82A : ("_ComponentDispatch",     'unimplemented_trap',   0xFFFFFFFF),
    0xA82B : ("_Pack9",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA82C : ("_Pack10",                'unimplemented_trap',   0xFFFFFFFF),
    0xA82D : ("_Pack11",                'unimplemented_trap',   0xFFFFFFFF),
    0xA82E : ("_Pack12",                'unimplemented_trap',   0xFFFFFFFF),
    0xA82F : ("_Pack13",                'unimplemented_trap',   0xFFFFFFFF),
    0xA830 : ("_Pack14",                'unimplemented_trap',   0xFFFFFFFF),
    0xA831 : ("_Pack15",                'unimplemented_trap',   0xFFFFFFFF),
    0xA833 : ("_ScrnBitMap",            'unimplemented_trap',   0xFFFFFFFF),
    0xA834 : ("_SetFScaleDisable",      'unimplemented_trap',   0xFFFFFFFF),
    0xA835 : ("_FontMetrics",           'unimplemented_trap',   0xFFFFFFFF),
    0xA836 : ("_GetMaskTable",          'unimplemented_trap',   0xFFFFFFFF),
    0xA837 : ("_MeasureText",           'unimplemented_trap',   0xFFFFFFFF),
    0xA838 : ("_CalcMask",              'unimplemented_trap',   0xFFFFFFFF),
    0xA839 : ("_SeedFill",              'unimplemented_trap',   0xFFFFFFFF),
    0xA83A : ("_ZoomWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA83B : ("_TrackBox",              'unimplemented_trap',   0xFFFFFFFF),
    0xA83C : ("_TEGetOffset",           'unimplemented_trap',   0xFFFFFFFF),
    0xA83D : ("_TEDispatch",            'unimplemented_trap',   0xFFFFFFFF),
    0xA83E : ("_TEStyleNew",            'unimplemented_trap',   0xFFFFFFFF),
    0xA83F : ("_Long2Fix",              'unimplemented_trap',   0xFFFFFFFF),
    0xA840 : ("_Fix2Long",              'unimplemented_trap',   0xFFFFFFFF),
    0xA841 : ("_Fix2Frac",              'unimplemented_trap',   0xFFFFFFFF),
    0xA842 : ("_Frac2Fix",              'unimplemented_trap',   0xFFFFFFFF),
    0xA843 : ("_Fix2X",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA844 : ("_X2Fix",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA845 : ("_Frac2X",                'unimplemented_trap',   0xFFFFFFFF),
    0xA846 : ("_X2Frac",                'unimplemented_trap',   0xFFFFFFFF),
    0xA847 : ("_FracCos",               'unimplemented_trap',   0xFFFFFFFF),
    0xA848 : ("_FracSin",               'unimplemented_trap',   0xFFFFFFFF),
    0xA849 : ("_FracSqrt",              'unimplemented_trap',   0xFFFFFFFF),
    0xA84A : ("_FracMul",               'unimplemented_trap',   0xFFFFFFFF),
    0xA84B : ("_FracDiv",               'unimplemented_trap',   0xFFFFFFFF),
    0xA84D : ("_FixDiv",                'unimplemented_trap',   0xFFFFFFFF),
    0xA84E : ("_GetItemCmd",            'unimplemented_trap',   0xFFFFFFFF),
    0xA84F : ("_SetItemCmd",            'unimplemented_trap',   0xFFFFFFFF),
    0xA850 : ("_InitCursor",            'unimplemented_trap',   0xFFFFFFFF),
    0xA851 : ("_SetCursor",             'unimplemented_trap',   0xFFFFFFFF),
    0xA852 : ("_HideCursor",            'unimplemented_trap',   0xFFFFFFFF),
    0xA853 : ("_ShowCursor",            'unimplemented_trap',   0xFFFFFFFF),
    0xA854 : ("_FontDispatch",          'unimplemented_trap',   0xFFFFFFFF),
    0xA855 : ("_ShieldCursor",          'unimplemented_trap',   0xFFFFFFFF),
    0xA856 : ("_ObscureCursor",         'unimplemented_trap',   0xFFFFFFFF),
    0xA857 : ("_SetAppBase",            'unimplemented_trap',   0xFFFFFFFF),
    0xA858 : ("_BitAnd",                'unimplemented_trap',   0xFFFFFFFF),
    0xA859 : ("_BitXOr",                'unimplemented_trap',   0xFFFFFFFF),
    0xA85A : ("_BitNot",                'unimplemented_trap',   0xFFFFFFFF),
    0xA85B : ("_BitOr",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA85C : ("_BitShift",              'unimplemented_trap',   0xFFFFFFFF),
    0xA85D : ("_BitTst",                'unimplemented_trap',   0xFFFFFFFF),
    0xA85E : ("_BitSet",                'unimplemented_trap',   0xFFFFFFFF),
    0xA85F : ("_BitClr",                'unimplemented_trap',   0xFFFFFFFF),
    0xA860 : ("_WaitNextEvent",         'unimplemented_trap',   0xFFFFFFFF),
    0xA861 : ("_Random",                'unimplemented_trap',   0xFFFFFFFF),
    0xA862 : ("_ForeColor",             'unimplemented_trap',   0xFFFFFFFF),
    0xA863 : ("_BackColor",             'unimplemented_trap',   0xFFFFFFFF),
    0xA864 : ("_ColorBit",              'unimplemented_trap',   0xFFFFFFFF),
    0xA865 : ("_GetPixel",              'unimplemented_trap',   0xFFFFFFFF),
    0xA866 : ("_StuffHex",              'unimplemented_trap',   0xFFFFFFFF),
    0xA867 : ("_LongMul",               'unimplemented_trap',   0xFFFFFFFF),
    0xA868 : ("_FixMul",                'unimplemented_trap',   0xFFFFFFFF),
    0xA869 : ("_FixRatio",              'unimplemented_trap',   0xFFFFFFFF),
    0xA86A : ("_HiWord",                'unimplemented_trap',   0xFFFFFFFF),
    0xA86B : ("_LoWord",                'unimplemented_trap',   0xFFFFFFFF),
    0xA86C : ("_FixRound",              'unimplemented_trap',   0xFFFFFFFF),
    0xA86D : ("_InitPort",              'unimplemented_trap',   0xFFFFFFFF),
    0xA86E : ("_InitGraf",              'unimplemented_trap',   0xFFFFFFFF),
    0xA86F : ("_OpenPort",              'unimplemented_trap',   0xFFFFFFFF),
    0xA870 : ("_LocalToGlobal",         'unimplemented_trap',   0xFFFFFFFF),
    0xA871 : ("_GlobalToLocal",         'unimplemented_trap',   0xFFFFFFFF),
    0xA872 : ("_GrafDevice",            'unimplemented_trap',   0xFFFFFFFF),
    0xA873 : ("_SetPort",               'unimplemented_trap',   0xFFFFFFFF),
    0xA874 : ("_GetPort",               'unimplemented_trap',   0xFFFFFFFF),
    0xA875 : ("_SetPortBits",           'unimplemented_trap',   0xFFFFFFFF),
    0xA876 : ("_PortSize",              'unimplemented_trap',   0xFFFFFFFF),
    0xA877 : ("_MovePortTo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA878 : ("_SetOrigin",             'unimplemented_trap',   0xFFFFFFFF),
    0xA879 : ("_SetClip",               'unimplemented_trap',   0xFFFFFFFF),
    0xA87A : ("_GetClip",               'unimplemented_trap',   0xFFFFFFFF),
    0xA87B : ("_ClipRect",              'unimplemented_trap',   0xFFFFFFFF),
    0xA87C : ("_BackPat",               'unimplemented_trap',   0xFFFFFFFF),
    0xA87D : ("_ClosePort",             'unimplemented_trap',   0xFFFFFFFF),
    0xA87E : ("_AddPt",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA87F : ("_SubPt",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA880 : ("_SetPt",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA881 : ("_EqualPt",               'unimplemented_trap',   0xFFFFFFFF),
    0xA882 : ("_StdText",               'unimplemented_trap',   0xFFFFFFFF),
    0xA883 : ("_DrawChar",              'unimplemented_trap',   0xFFFFFFFF),
    0xA884 : ("_DrawString",            'unimplemented_trap',   0xFFFFFFFF),
    0xA885 : ("_DrawText",              'unimplemented_trap',   0xFFFFFFFF),
    0xA886 : ("_TextWidth",             'unimplemented_trap',   0xFFFFFFFF),
    0xA887 : ("_TextFont",              'unimplemented_trap',   0xFFFFFFFF),
    0xA888 : ("_TextFace",              'unimplemented_trap',   0xFFFFFFFF),
    0xA889 : ("_TextMode",              'unimplemented_trap',   0xFFFFFFFF),
    0xA88A : ("_TextSize",              'unimplemented_trap',   0xFFFFFFFF),
    0xA88B : ("_GetFontInfo",           'unimplemented_trap',   0xFFFFFFFF),
    0xA88C : ("_StringWidth",           'unimplemented_trap',   0xFFFFFFFF),
    0xA88D : ("_CharWidth",             'unimplemented_trap',   0xFFFFFFFF),
    0xA88E : ("_SpaceExtra",            'unimplemented_trap',   0xFFFFFFFF),
    0xA88F : ("_OSDispatch",            'unimplemented_trap',   0xFFFFFFFF),
    0xA890 : ("_StdLine",               'unimplemented_trap',   0xFFFFFFFF),
    0xA891 : ("_LineTo",                'unimplemented_trap',   0xFFFFFFFF),
    0xA892 : ("_Line",                  'unimplemented_trap',   0xFFFFFFFF),
    0xA893 : ("_MoveTo",                'unimplemented_trap',   0xFFFFFFFF),
    0xA894 : ("_Move",                  'unimplemented_trap',   0xFFFFFFFF),
    0xA895 : ("_ShutDown",              'unimplemented_trap',   0xFFFFFFFF),
    0xA896 : ("_HidePen",               'unimplemented_trap',   0xFFFFFFFF),
    0xA897 : ("_ShowPen",               'unimplemented_trap',   0xFFFFFFFF),
    0xA898 : ("_GetPenState",           'unimplemented_trap',   0xFFFFFFFF),
    0xA899 : ("_SetPenState",           'unimplemented_trap',   0xFFFFFFFF),
    0xA89A : ("_GetPen",                'unimplemented_trap',   0xFFFFFFFF),
    0xA89B : ("_PenSize",               'unimplemented_trap',   0xFFFFFFFF),
    0xA89C : ("_PenMode",               'unimplemented_trap',   0xFFFFFFFF),
    0xA89D : ("_PenPat",                'unimplemented_trap',   0xFFFFFFFF),
    0xA89E : ("_PenNormal",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8A0 : ("_StdRect",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8A1 : ("_FrameRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8A2 : ("_PaintRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8A3 : ("_EraseRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8A4 : ("_InvertRect",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8A5 : ("_FillRect",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8A6 : ("_EqualRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8A7 : ("_SetRect",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8A8 : ("_OffsetRect",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8A9 : ("_InsetRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8AA : ("_SectRect",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8AB : ("_UnionRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8AC : ("_Pt2Rect",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8AD : ("_PtInRect",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8AE : ("_EmptyRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8AF : ("_StdRRect",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8B0 : ("_FrameRoundRect",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8B1 : ("_PaintRoundRect",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8B2 : ("_EraseRoundRect",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8B3 : ("_InvertRoundRect",       'unimplemented_trap',   0xFFFFFFFF),
    0xA8B4 : ("_FillRoundRect",         'unimplemented_trap',   0xFFFFFFFF),
    0xA8B5 : ("_ScriptUtil",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8B6 : ("_StdOval",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8B7 : ("_FrameOval",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8B8 : ("_PaintOval",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8B9 : ("_EraseOval",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8BA : ("_InvertOval",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8BB : ("_FillOval",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8BC : ("_SlopeFromAngle",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8BD : ("_StdArc",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8BE : ("_FrameArc",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8BF : ("_PaintArc",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8C0 : ("_EraseArc",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8C1 : ("_InvertArc",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8C2 : ("_FillArc",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8C3 : ("_PtToAngle",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8C4 : ("_AngleFromSlope",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8C5 : ("_StdPoly",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8C6 : ("_FramePoly",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8C7 : ("_PaintPoly",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8C8 : ("_ErasePoly",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8C9 : ("_InvertPoly",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8CA : ("_FillPoly",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8CB : ("_OpenPoly",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8CC : ("_ClosePoly",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8CD : ("_KillPoly",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8CE : ("_OffsetPoly",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8CF : ("_PackBits",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8D0 : ("_UnpackBits",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8D1 : ("_StdRgn",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8D2 : ("_FrameRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8D3 : ("_PaintRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8D4 : ("_EraseRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8D5 : ("_InvertRgn",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8D6 : ("_FillRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8D7 : ("_BitMapToRegion",        'unimplemented_trap',   0xFFFFFFFF),
    0xA8D8 : ("_NewRgn",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8D9 : ("_DisposeRgn",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8DA : ("_OpenRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8DB : ("_CloseRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8DC : ("_CopyRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8DD : ("_SetEmptyRgn",           'unimplemented_trap',   0xFFFFFFFF),
    0xA8DE : ("_SetRectRgn",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8DF : ("_RectRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8E0 : ("_OffsetRgn",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8E1 : ("_InsetRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8E2 : ("_EmptyRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8E3 : ("_EqualRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8E4 : ("_SectRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8E5 : ("_UnionRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8E6 : ("_DiffRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8E7 : ("_XOrRgn",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8E8 : ("_PtInRgn",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8E9 : ("_RectInRgn",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8EA : ("_SetStdProcs",           'unimplemented_trap',   0xFFFFFFFF),
    0xA8EB : ("_StdBits",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8EC : ("_CopyBits",              'unimplemented_trap',   0xFFFFFFFF),
    0xA8ED : ("_StdTxMeas",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8EE : ("_StdGetPic",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8EF : ("_ScrollRect",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8F0 : ("_StdPutPic",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8F1 : ("_StdComment",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8F2 : ("_PicComment",            'unimplemented_trap',   0xFFFFFFFF),
    0xA8F3 : ("_OpenPicture",           'unimplemented_trap',   0xFFFFFFFF),
    0xA8F4 : ("_ClosePicture",          'unimplemented_trap',   0xFFFFFFFF),
    0xA8F5 : ("_KillPicture",           'unimplemented_trap',   0xFFFFFFFF),
    0xA8F6 : ("_DrawPicture",           'unimplemented_trap',   0xFFFFFFFF),
    0xA8F7 : ("_Layout",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8F8 : ("_ScalePt",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8F9 : ("_MapPt",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA8FA : ("_MapRect",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8FB : ("_MapRgn",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8FC : ("_MapPoly",               'unimplemented_trap',   0xFFFFFFFF),
    0xA8FD : ("_PrGlue",                'unimplemented_trap',   0xFFFFFFFF),
    0xA8FE : ("_InitFonts",             'unimplemented_trap',   0xFFFFFFFF),
    0xA8FF : ("_GetFontName",           'unimplemented_trap',   0xFFFFFFFF),
    0xA900 : ("_GetFNum",               'unimplemented_trap',   0xFFFFFFFF),
    0xA901 : ("_FMSwapFont",            'unimplemented_trap',   0xFFFFFFFF),
    0xA902 : ("_RealFont",              'unimplemented_trap',   0xFFFFFFFF),
    0xA903 : ("_SetFontLock",           'unimplemented_trap',   0xFFFFFFFF),
    0xA904 : ("_DrawGrowIcon",          'unimplemented_trap',   0xFFFFFFFF),
    0xA905 : ("_DragGrayRgn",           'unimplemented_trap',   0xFFFFFFFF),
    0xA906 : ("_NewString",             'unimplemented_trap',   0xFFFFFFFF),
    0xA907 : ("_SetString",             'unimplemented_trap',   0xFFFFFFFF),
    0xA908 : ("_ShowHide",              'unimplemented_trap',   0xFFFFFFFF),
    0xA909 : ("_CalcVis",               'unimplemented_trap',   0xFFFFFFFF),
    0xA90A : ("_CalcVBehind",           'unimplemented_trap',   0xFFFFFFFF),
    0xA90B : ("_ClipAbove",             'unimplemented_trap',   0xFFFFFFFF),
    0xA90C : ("_PaintOne",              'unimplemented_trap',   0xFFFFFFFF),
    0xA90D : ("_PaintBehind",           'unimplemented_trap',   0xFFFFFFFF),
    0xA90E : ("_SaveOld",               'unimplemented_trap',   0xFFFFFFFF),
    0xA90F : ("_DrawNew",               'unimplemented_trap',   0xFFFFFFFF),
    0xA910 : ("_GetWMgrPort",           'unimplemented_trap',   0xFFFFFFFF),
    0xA911 : ("_CheckUpDate",           'unimplemented_trap',   0xFFFFFFFF),
    0xA912 : ("_InitWindows",           'unimplemented_trap',   0xFFFFFFFF),
    0xA913 : ("_NewWindow",             'unimplemented_trap',   0xFFFFFFFF),
    0xA914 : ("_DisposeWindow",         'unimplemented_trap',   0xFFFFFFFF),
    0xA915 : ("_ShowWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA916 : ("_HideWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA917 : ("_GetWRefCon",            'unimplemented_trap',   0xFFFFFFFF),
    0xA918 : ("_SetWRefCon",            'unimplemented_trap',   0xFFFFFFFF),
    0xA919 : ("_GetWTitle",             'unimplemented_trap',   0xFFFFFFFF),
    0xA91A : ("_SetWTitle",             'unimplemented_trap',   0xFFFFFFFF),
    0xA91B : ("_MoveWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA91C : ("_HiliteWindow",          'unimplemented_trap',   0xFFFFFFFF),
    0xA91D : ("_SizeWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA91E : ("_TrackGoAway",           'unimplemented_trap',   0xFFFFFFFF),
    0xA91F : ("_SelectWindow",          'unimplemented_trap',   0xFFFFFFFF),
    0xA920 : ("_BringToFront",          'unimplemented_trap',   0xFFFFFFFF),
    0xA921 : ("_SendBehind",            'unimplemented_trap',   0xFFFFFFFF),
    0xA922 : ("_BeginUpDate",           'unimplemented_trap',   0xFFFFFFFF),
    0xA923 : ("_EndUpDate",             'unimplemented_trap',   0xFFFFFFFF),
    0xA924 : ("_FrontWindow",           'unimplemented_trap',   0xFFFFFFFF),
    0xA925 : ("_DragWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA926 : ("_DragTheRgn",            'unimplemented_trap',   0xFFFFFFFF),
    0xA927 : ("_InvalRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA928 : ("_InvalRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA929 : ("_ValidRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xA92A : ("_ValidRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xA92B : ("_GrowWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA92C : ("_FindWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xA92D : ("_CloseWindow",           'unimplemented_trap',   0xFFFFFFFF),
    0xA92E : ("_SetWindowPic",          'unimplemented_trap',   0xFFFFFFFF),
    0xA92F : ("_GetWindowPic",          'unimplemented_trap',   0xFFFFFFFF),
    0xA930 : ("_InitMenus",             'unimplemented_trap',   0xFFFFFFFF),
    0xA931 : ("_NewMenu",               'unimplemented_trap',   0xFFFFFFFF),
    0xA932 : ("_DisposeMenu",           'unimplemented_trap',   0xFFFFFFFF),
    0xA933 : ("_AppendMenu",            'unimplemented_trap',   0xFFFFFFFF),
    0xA934 : ("_ClearMenuBar",          'unimplemented_trap',   0xFFFFFFFF),
    0xA935 : ("_InsertMenu",            'unimplemented_trap',   0xFFFFFFFF),
    0xA936 : ("_DeleteMenu",            'unimplemented_trap',   0xFFFFFFFF),
    0xA937 : ("_DrawMenuBar",           'unimplemented_trap',   0xFFFFFFFF),
    0xA938 : ("_HiliteMenu",            'unimplemented_trap',   0xFFFFFFFF),
    0xA939 : ("_EnableItem",            'unimplemented_trap',   0xFFFFFFFF),
    0xA93A : ("_DisableItem",           'unimplemented_trap',   0xFFFFFFFF),
    0xA93B : ("_GetMenuBar",            'unimplemented_trap',   0xFFFFFFFF),
    0xA93C : ("_SetMenuBar",            'unimplemented_trap',   0xFFFFFFFF),
    0xA93D : ("_MenuSelect",            'unimplemented_trap',   0xFFFFFFFF),
    0xA93E : ("_MenuKey",               'unimplemented_trap',   0xFFFFFFFF),
    0xA93F : ("_GetItmIcon",            'unimplemented_trap',   0xFFFFFFFF),
    0xA940 : ("_SetItmIcon",            'unimplemented_trap',   0xFFFFFFFF),
    0xA941 : ("_GetItmStyle",           'unimplemented_trap',   0xFFFFFFFF),
    0xA942 : ("_SetItmStyle",           'unimplemented_trap',   0xFFFFFFFF),
    0xA943 : ("_GetItmMark",            'unimplemented_trap',   0xFFFFFFFF),
    0xA944 : ("_SetItmMark",            'unimplemented_trap',   0xFFFFFFFF),
    0xA945 : ("_CheckItem",             'unimplemented_trap',   0xFFFFFFFF),
    0xA946 : ("_GetMenuItemText",       'unimplemented_trap',   0xFFFFFFFF),
    0xA947 : ("_SetMenuItemText",       'unimplemented_trap',   0xFFFFFFFF),
    0xA948 : ("_CalcMenuSize",          'unimplemented_trap',   0xFFFFFFFF),
    0xA949 : ("_GetMenuHandle",         'unimplemented_trap',   0xFFFFFFFF),
    0xA94A : ("_SetMenuFlash",          'unimplemented_trap',   0xFFFFFFFF),
    0xA94B : ("_PlotIcon",              'unimplemented_trap',   0xFFFFFFFF),
    0xA94C : ("_FlashMenuBar",          'unimplemented_trap',   0xFFFFFFFF),
    0xA94D : ("_AppendResMenu",         'unimplemented_trap',   0xFFFFFFFF),
    0xA94E : ("_PinRect",               'unimplemented_trap',   0xFFFFFFFF),
    0xA94F : ("_DeltaPoint",            'unimplemented_trap',   0xFFFFFFFF),
    0xA950 : ("_CountMItems",           'unimplemented_trap',   0xFFFFFFFF),
    0xA951 : ("_InsertResMenu",         'unimplemented_trap',   0xFFFFFFFF),
    0xA952 : ("_DeleteMenuItem",        'unimplemented_trap',   0xFFFFFFFF),
    0xA953 : ("_UpdtControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA954 : ("_NewControl",            'unimplemented_trap',   0xFFFFFFFF),
    0xA955 : ("_DisposeControl",        'unimplemented_trap',   0xFFFFFFFF),
    0xA956 : ("_KillControls",          'unimplemented_trap',   0xFFFFFFFF),
    0xA957 : ("_ShowControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA958 : ("_HideControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA959 : ("_MoveControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA95A : ("_GetControlReference",   'unimplemented_trap',   0xFFFFFFFF),
    0xA95B : ("_SetControlReference",   'unimplemented_trap',   0xFFFFFFFF),
    0xA95C : ("_SizeControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA95D : ("_HiliteControl",         'unimplemented_trap',   0xFFFFFFFF),
    0xA95E : ("_GetControlTitle",       'unimplemented_trap',   0xFFFFFFFF),
    0xA95F : ("_SetControlTitle",       'unimplemented_trap',   0xFFFFFFFF),
    0xA960 : ("_GetControlValue",       'unimplemented_trap',   0xFFFFFFFF),
    0xA961 : ("_GetControlMinimum",     'unimplemented_trap',   0xFFFFFFFF),
    0xA962 : ("_GetControlMaximum",     'unimplemented_trap',   0xFFFFFFFF),
    0xA963 : ("_SetControlValue",       'unimplemented_trap',   0xFFFFFFFF),
    0xA964 : ("_SetControlMinimum",     'unimplemented_trap',   0xFFFFFFFF),
    0xA965 : ("_SetControlMaximum",     'unimplemented_trap',   0xFFFFFFFF),
    0xA966 : ("_TestControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA967 : ("_DragControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA968 : ("_TrackControl",          'unimplemented_trap',   0xFFFFFFFF),
    0xA969 : ("_DrawControls",          'unimplemented_trap',   0xFFFFFFFF),
    0xA96A : ("_GetControlAction",      'unimplemented_trap',   0xFFFFFFFF),
    0xA96B : ("_SetControlAction",      'unimplemented_trap',   0xFFFFFFFF),
    0xA96C : ("_FindControl",           'unimplemented_trap',   0xFFFFFFFF),
    0xA96D : ("_Draw1Control",          'unimplemented_trap',   0xFFFFFFFF),
    0xA96E : ("_Dequeue",               'dummy_trap',           0x004019F0),
    0xA96F : ("_Enqueue",               'unimplemented_trap',   0xFFFFFFFF),
    0xA970 : ("_GetNextEvent",          'unimplemented_trap',   0xFFFFFFFF),
    0xA971 : ("_EventAvail",            'unimplemented_trap',   0xFFFFFFFF),
    0xA972 : ("_GetMouse",              'unimplemented_trap',   0xFFFFFFFF),
    0xA973 : ("_StillDown",             'unimplemented_trap',   0xFFFFFFFF),
    0xA974 : ("_Button",                'unimplemented_trap',   0xFFFFFFFF),
    0xA975 : ("_TickCount",             'unimplemented_trap',   0xFFFFFFFF),
    0xA976 : ("_GetKeys",               'unimplemented_trap',   0xFFFFFFFF),
    0xA977 : ("_WaitMouseUp",           'unimplemented_trap',   0xFFFFFFFF),
    0xA978 : ("_UpdtDialog",            'unimplemented_trap',   0xFFFFFFFF),
    0xA979 : ("_CouldDialog",           'unimplemented_trap',   0xFFFFFFFF),
    0xA97A : ("_FreeDialog",            'unimplemented_trap',   0xFFFFFFFF),
    0xA97B : ("_InitDialogs",           'unimplemented_trap',   0xFFFFFFFF),
    0xA97C : ("_GetNewDialog",          'unimplemented_trap',   0xFFFFFFFF),
    0xA97D : ("_NewDialog",             'unimplemented_trap',   0xFFFFFFFF),
    0xA97E : ("_SelectDialogItemText",  'unimplemented_trap',   0xFFFFFFFF),
    0xA97F : ("_IsDialogEvent",         'unimplemented_trap',   0xFFFFFFFF),
    0xA980 : ("_DialogSelect",          'unimplemented_trap',   0xFFFFFFFF),
    0xA981 : ("_DrawDialog",            'unimplemented_trap',   0xFFFFFFFF),
    0xA982 : ("_CloseDialog",           'unimplemented_trap',   0xFFFFFFFF),
    0xA983 : ("_DisposeDialog",         'unimplemented_trap',   0xFFFFFFFF),
    0xA984 : ("_FindDialogItem",        'unimplemented_trap',   0xFFFFFFFF),
    0xA985 : ("_Alert",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA986 : ("_StopAlert",             'unimplemented_trap',   0xFFFFFFFF),
    0xA987 : ("_NoteAlert",             'unimplemented_trap',   0xFFFFFFFF),
    0xA988 : ("_CautionAlert",          'unimplemented_trap',   0xFFFFFFFF),
    0xA989 : ("_CouldAlert",            'unimplemented_trap',   0xFFFFFFFF),
    0xA98A : ("_FreeAlert",             'unimplemented_trap',   0xFFFFFFFF),
    0xA98B : ("_ParamText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA98C : ("_ErrorSound",            'unimplemented_trap',   0xFFFFFFFF),
    0xA98D : ("_GetDialogItem",         'unimplemented_trap',   0xFFFFFFFF),
    0xA98E : ("_SetDialogItem",         'unimplemented_trap',   0xFFFFFFFF),
    0xA98F : ("_SetDialogItemText",     'unimplemented_trap',   0xFFFFFFFF),
    0xA990 : ("_GetDialogItemText",     'unimplemented_trap',   0xFFFFFFFF),
    0xA991 : ("_ModalDialog",           'unimplemented_trap',   0xFFFFFFFF),
    0xA992 : ("_DetachResource",        'unimplemented_trap',   0xFFFFFFFF),
    0xA993 : ("_SetResPurge",           'unimplemented_trap',   0xFFFFFFFF),
    0xA994 : ("_CurResFile",            'dummy_trap',           0xFFF33044),
    0xA995 : ("_InitResources",         'unimplemented_trap',   0xFFFFFFFF),
    0xA996 : ("_RsrcZoneInit",          'unimplemented_trap',   0xFFFFFFFF),
    0xA997 : ("_OpenResFile",           'unimplemented_trap',   0xFFFFFFFF),
    0xA998 : ("_UseResFile",            'unimplemented_trap',   0xFFFFFFFF),
    0xA999 : ("_UpdateResFile",         'unimplemented_trap',   0xFFFFFFFF),
    0xA99A : ("_CloseResFile",          'unimplemented_trap',   0xFFFFFFFF),
    0xA99B : ("_SetResLoad",            'set_res_load',         0xFFF33048, 'B'),
    0xA99C : ("_CountResources",        'unimplemented_trap',   0xFFFFFFFF),
    0xA99D : ("_GetIndResource",        'unimplemented_trap',   0xFFFFFFFF),
    0xA99E : ("_CountTypes",            'unimplemented_trap',   0xFFFFFFFF),
    0xA99F : ("_GetIndType",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9A0 : ("_GetResource",           'get_resource',         0xFFF3404C, 'W', 'L'),
    0xA9A1 : ("_GetNamedResource",      'unimplemented_trap',   0xFFFFFFFF),
    0xA9A2 : ("_LoadResource",          'load_resource',        0xFFF34050, 'L'),
    0xA9A3 : ("_ReleaseResource",       'unimplemented_trap',   0xFFFFFFFF),
    0xA9A4 : ("_HomeResFile",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9A5 : ("_SizeResource",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9A6 : ("_GetResAttrs",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9A7 : ("_SetResAttrs",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9A8 : ("_GetResInfo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9A9 : ("_SetResInfo",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9AA : ("_ChangedResource",       'unimplemented_trap',   0xFFFFFFFF),
    0xA9AB : ("_AddResource",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9AC : ("_AddReference",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9AD : ("_RmveResource",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9AE : ("_RmveReference",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9AF : ("_ResError",              'res_error',            0xFFF34050),
    0xA9B0 : ("_WriteResource",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9B1 : ("_CreateResFile",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9B2 : ("_SystemEvent",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9B3 : ("_SystemClick",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9B4 : ("_SystemTask",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9B5 : ("_SystemMenu",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9B6 : ("_OpenDeskAcc",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9B7 : ("_CloseDeskAcc",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9B8 : ("_GetPattern",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9B9 : ("_GetCursor",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9BA : ("_GetString",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9BB : ("_GetIcon",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9BC : ("_GetPicture",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9BD : ("_GetNewWindow",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9BE : ("_GetNewControl",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9BF : ("_GetRMenu",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9C0 : ("_GetNewMBar",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9C1 : ("_UniqueID",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9C2 : ("_SysEdit",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9C3 : ("_KeyTranslate",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9C4 : ("_OpenRFPerm",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9C5 : ("_RsrcMapEntry",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9C6 : ("_SecondsToDate",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9C7 : ("_DateToSeconds",         'unimplemented_trap',   0xFFFFFFFF),
    0xA9C8 : ("_SysBeep",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9C9 : ("_SysError",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9CA : ("_PutIcon",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9CB : ("_TEGetText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9CC : ("_TEInit",                'unimplemented_trap',   0xFFFFFFFF),
    0xA9CD : ("_TEDispose",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9CE : ("_TETextBox",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9CF : ("_TESetText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9D0 : ("_TECalText",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9D1 : ("_TESetSelect",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9D2 : ("_TENew",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9D3 : ("_TEUpdate",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9D4 : ("_TEClick",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9D5 : ("_TECopy",                'unimplemented_trap',   0xFFFFFFFF),
    0xA9D6 : ("_TECut",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9D7 : ("_TEDelete",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9D8 : ("_TEActivate",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9D9 : ("_TEDeactivate",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9DA : ("_TEIdle",                'unimplemented_trap',   0xFFFFFFFF),
    0xA9DB : ("_TEPaste",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9DC : ("_TEKey",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9DD : ("_TEScroll",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9DE : ("_TEInsert",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9DF : ("_TESetAlignment",        'unimplemented_trap',   0xFFFFFFFF),
    0xA9E0 : ("_Munger",                'unimplemented_trap',   0xFFFFFFFF),
    0xA9E1 : ("_HandToHand",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9E2 : ("_PtrToXHand",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9E3 : ("_PtrToHand",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9E4 : ("_HandAndHand",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9E5 : ("_InitPack",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9E6 : ("_InitAllPacks",          'unimplemented_trap',   0xFFFFFFFF),
    0xA9E7 : ("_Pack0",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9E8 : ("_Pack1",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9E9 : ("_Pack2",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9EA : ("_Pack3",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9EB : ("_FP68K",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9EC : ("_Elems68K",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9ED : ("_Pack6",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9EE : ("_DECSTR68K",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9EF : ("_PtrAndHand",            'unimplemented_trap',   0xFFFFFFFF),
    0xA9F0 : ("_LoadSeg",               'unimplemented_trap',   0xFFFFFFFF),
    0xA9F1 : ("_UnLoadSeg",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9F2 : ("_Launch",                'unimplemented_trap',   0xFFFFFFFF),
    0xA9F3 : ("_Chain",                 'unimplemented_trap',   0xFFFFFFFF),
    0xA9F4 : ("_ExitToShell",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9F5 : ("_GetAppParms",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9F6 : ("_GetResFileAttrs",       'unimplemented_trap',   0xFFFFFFFF),
    0xA9F7 : ("_SetResFileAttrs",       'unimplemented_trap',   0xFFFFFFFF),
    0xA9F8 : ("_MethodDispatch",        'unimplemented_trap',   0xFFFFFFFF),
    0xA9F9 : ("_InfoScrap",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9FA : ("_UnloadScrap",           'unimplemented_trap',   0xFFFFFFFF),
    0xA9FB : ("_LoadScrap",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9FC : ("_ZeroScrap",             'unimplemented_trap',   0xFFFFFFFF),
    0xA9FD : ("_GetScrap",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9FE : ("_PutScrap",              'unimplemented_trap',   0xFFFFFFFF),
    0xA9FF : ("_Debugger",              'unimplemented_trap',   0xFFFFFFFF),
    0xAA00 : ("_OpenCPort",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA01 : ("_InitCPort",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA02 : ("_CloseCPort",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA03 : ("_NewPixMap",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA04 : ("_DisposePixMap",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA05 : ("_CopyPixMap",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA06 : ("_SetPortPix",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA07 : ("_NewPixPat",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA08 : ("_DisposePixPat",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA09 : ("_CopyPixPat",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA0A : ("_PenPixPat",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA0B : ("_BackPixPat",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA0C : ("_GetPixPat",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA0D : ("_MakeRGBPat",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA0E : ("_FillCRect",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA0F : ("_FillCOval",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA10 : ("_FillCRoundRect",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA11 : ("_FillCArc",              'unimplemented_trap',   0xFFFFFFFF),
    0xAA12 : ("_FillCRgn",              'unimplemented_trap',   0xFFFFFFFF),
    0xAA13 : ("_FillCPoly",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA14 : ("_RGBForeColor",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA15 : ("_RGBBackColor",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA16 : ("_SetCPixel",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA17 : ("_GetCPixel",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA18 : ("_GetCTable",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA19 : ("_GetForeColor",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA1A : ("_GetBackColor",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA1B : ("_GetCCursor",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA1C : ("_SetCCursor",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA1D : ("_AllocCursor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA1E : ("_GetCIcon",              'unimplemented_trap',   0xFFFFFFFF),
    0xAA1F : ("_PlotCIcon",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA20 : ("_OpenCPicture",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA21 : ("_OpColor",               'unimplemented_trap',   0xFFFFFFFF),
    0xAA22 : ("_HiliteColor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA23 : ("_CharExtra",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA24 : ("_DisposeCTable",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA25 : ("_DisposeCIcon",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA26 : ("_DisposeCCursor",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA27 : ("_GetMaxDevice",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA28 : ("_GetCTSeed",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA29 : ("_GetDeviceList",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA2A : ("_GetMainDevice",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA2B : ("_GetNextDevice",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA2C : ("_TestDeviceAttribute",   'unimplemented_trap',   0xFFFFFFFF),
    0xAA2D : ("_SetDeviceAttribute",    'unimplemented_trap',   0xFFFFFFFF),
    0xAA2E : ("_InitGDevice",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA2F : ("_NewGDevice",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA30 : ("_DisposeGDevice",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA31 : ("_SetGDevice",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA32 : ("_GetGDevice",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA33 : ("_Color2Index",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA34 : ("_Index2Color",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA35 : ("_InvertColor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA36 : ("_RealColor",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA37 : ("_GetSubTable",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA38 : ("_UpdatePixMap",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA39 : ("_MakeITable",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA3A : ("_AddSearch",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA3B : ("_AddComp",               'unimplemented_trap',   0xFFFFFFFF),
    0xAA3C : ("_SetClientID",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA3D : ("_ProtectEntry",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA3E : ("_ReserveEntry",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA3F : ("_SetEntries",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA40 : ("_QDError",               'unimplemented_trap',   0xFFFFFFFF),
    0xAA41 : ("_SetWinColor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA42 : ("_GetAuxWin",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA43 : ("_SetControlColor",       'unimplemented_trap',   0xFFFFFFFF),
    0xAA44 : ("_GetAuxiliaryControlRecord", 'unimplemented_trap',   0xFFFFFFFF),
    0xAA45 : ("_NewCWindow",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA46 : ("_GetNewCWindow",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA47 : ("_SetDeskCPat",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA48 : ("_GetCWMgrPort",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA49 : ("_SaveEntries",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA4A : ("_RestoreEntries",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA4B : ("_NewColorDialog",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA4C : ("_DelSearch",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA4D : ("_DelComp",               'unimplemented_trap',   0xFFFFFFFF),
    0xAA4E : ("_SetStdCProcs",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA4F : ("_CalcCMask",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA50 : ("_SeedCFill",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA51 : ("_CopyDeepMask",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA52 : ("_HighLevelFSDispatch",   'unimplemented_trap',   0xFFFFFFFF),
    0xAA53 : ("_DictionaryDispatch",    'unimplemented_trap',   0xFFFFFFFF),
    0xAA54 : ("_TextServicesDispatch",  'unimplemented_trap',   0xFFFFFFFF),
    0xAA57 : ("_DockingDispatch",       'unimplemented_trap',   0xFFFFFFFF),
    0xAA59 : ("_MixedModeDispatch",     'unimplemented_trap',   0xFFFFFFFF),
    0xAA5A : ("_CodeFragmentDispatch",  'unimplemented_trap',   0xFFFFFFFF),
    0xAA60 : ("_DeleteMCEntries",       'unimplemented_trap',   0xFFFFFFFF),
    0xAA61 : ("_GetMCInfo",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA62 : ("_SetMCInfo",             'unimplemented_trap',   0xFFFFFFFF),
    0xAA63 : ("_DisposeMCInfo",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA64 : ("_GetMCEntry",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA65 : ("_SetMCEntries",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA66 : ("_MenuChoice",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA68 : ("_DialogDispatch",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA90 : ("_InitPalettes",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA91 : ("_NewPalette",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA92 : ("_GetNewPalette",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA93 : ("_DisposePalette",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA94 : ("_ActivatePalette",       'unimplemented_trap',   0xFFFFFFFF),
    0xAA95 : ("_SetPalette",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA96 : ("_GetPalette",            'unimplemented_trap',   0xFFFFFFFF),
    0xAA97 : ("_PmForeColor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA98 : ("_PmBackColor",           'unimplemented_trap',   0xFFFFFFFF),
    0xAA99 : ("_AnimateEntry",          'unimplemented_trap',   0xFFFFFFFF),
    0xAA9A : ("_AnimatePalette",        'unimplemented_trap',   0xFFFFFFFF),
    0xAA9B : ("_GetEntryColor",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA9C : ("_SetEntryColor",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA9D : ("_GetEntryUsage",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA9E : ("_SetEntryUsage",         'unimplemented_trap',   0xFFFFFFFF),
    0xAA9F : ("_CTab2Palette",          'unimplemented_trap',   0xFFFFFFFF),
    0xAAA0 : ("_Palette2CTab",          'unimplemented_trap',   0xFFFFFFFF),
    0xAAA1 : ("_CopyPalette",           'unimplemented_trap',   0xFFFFFFFF),
    0xAAA2 : ("_PaletteDispatch",       'unimplemented_trap',   0xFFFFFFFF),
    0xAADB : ("_CursorDeviceDispatch",  'unimplemented_trap',   0xFFFFFFFF),
    0xAB1D : ("_QDExtensions",          'unimplemented_trap',   0xFFFFFFFF),
    0xABC3 : ("_NQDMisc",               'unimplemented_trap',   0xFFFFFFFF),
    0xABC9 : ("_IconDispatch",          'unimplemented_trap',   0xFFFFFFFF),
    0xABCA : ("_DeviceLoop",            'unimplemented_trap',   0xFFFFFFFF),
    0xABEB : ("_DisplayDispatch",       'unimplemented_trap',   0xFFFFFFFF),
    0xABF2 : ("_ThreadDispatch",        'unimplemented_trap',   0xFFFFFFFF),
    0xABF8 : ("_StdOpcodeProc",         'unimplemented_trap',   0xFFFFFFFF),
    0xABFC : ("_TranslationDispatch",   'unimplemented_trap',   0xFFFFFFFF),
    0xABFF : ("_DebugStr",              'unimplemented_trap',   0xFFFFFFFF)
}

class InvalidTrap(Exception):
    def __init__(self, msg):
        self._msg =  msg

class MacTraps:
    def __init__(self, rt, rf_path):
        self._rt = rt # bare68k runtime object
        self._rf = rsrcfork.open(rf_path) # rsrcfork object
        self._last_trap = UNIMPLEMENTED_TRAP
        self._res_err = 0
        self._args = []
        self._mm = MacMemory(rt)
        self._register_traps()
        self._res_used = defaultdict(dict)

    def _register_traps(self):
        ''' Register supported A-Traps with bare68k '''
        for key in TRAP_TABLE.keys():
            traps.trap_enable(key)

    def _init_memory_manager(self):
        ''' Initialize emulated memory manager '''
        pass

    def get_trap_name(self, trap_num):
        ''' Returns human readable name for trap_num to be used with disassembler '''
        if trap_num not in TRAP_TABLE:
            raise InvalidTrap("Unsupported trap %X" % trap_num)
        return TRAP_TABLE[trap_num][0]

    def atrap_handler(self, event):
        ''' Main dispatcher that intercepts and emulates Macintosh traps '''
        trap_num = event.value
        if trap_num not in TRAP_TABLE:
            raise InvalidTrap("Unsupported trap %X" % trap_num)
        self._last_trap = trap_num
        trap_info = TRAP_TABLE[trap_num]
        print("%s trap invoked!" % trap_info[0])
        if len(trap_info) > 3:
            #print("...has %d stack params!" % (len(trap_info) - 3))
            sp = self._rt.get_cpu().r_sp()
            par_size = 0
            for i in range(len(trap_info) - 3):
                if trap_info[i + 3] == 'L':
                    self._args.insert(0, self._rt.get_mem().r32(sp))
                    sp += 4
                    par_size += 4
                elif trap_info[i + 3] == 'B':
                    # WARNING: byte params always occupy words on the stack!
                    # the value of a byte param is placed into the high-order
                    # byte of the stack word
                    self._args.insert(0, self._rt.get_mem().r8(sp))
                    sp += 2
                    par_size += 2
                else:
                    self._args.insert(0, self._rt.get_mem().r16(sp))
                    sp += 2
                    par_size += 2
            self._rt.get_cpu().w_sp(sp) # remove params from 68k stack
        getattr(self, trap_info[1])()

    def dummy_trap(self):
        print("Do nothing for this trap")

    def recover_handle(self): # param: A0 - ptr, result: A0 - handle
        h = self._mm.recover_handle(self._rt.get_cpu().r_reg(M68K_REG_A0))
        self._rt.get_cpu().w_reg(M68K_REG_A0, h)

    def get_handle_size(self):
        sz = self._mm.get_handle_size(self._rt.get_cpu().r_reg(M68K_REG_A0))
        self._rt.get_cpu().w_reg(M68K_REG_D0, sz)

    def new_handle(self):
        sz = self._rt.get_cpu().r_reg(M68K_REG_D0)
        clear = self._last_trap & 0x200
        print("Handle size %X" % sz)
        print("Heap Zone: %s" % ("sys" if self._last_trap & 0x400 else "current"))
        print("Clear bytes: %s" % ("yes" if clear else "no"))
        self._rt.get_cpu().w_reg(M68K_REG_A0, self._mm.new_handle(sz, zero=clear))

    def new_ptr(self):
        sz = self._rt.get_cpu().r_reg(M68K_REG_D0)
        clear = self._last_trap & 0x200
        print("Ptr size %X" % sz)
        print("Heap Zone: %s" % ("sys" if self._last_trap & 0x400 else "current"))
        print("Clear bytes: %s" % ("yes" if clear else "no"))
        new_ptr = self._mm.alloc_mem(sz)
        if clear:
            for i in range(sz):
                self._rt.get_mem().w8(new_ptr + i, 0)
        self._rt.get_cpu().w_reg(M68K_REG_A0, new_ptr)
        self._rt.get_cpu().w_reg(M68K_REG_D0, 0) # result code = noErr!

    def get_trap_addr(self):
        trap_num = (self._rt.get_cpu().r_reg(M68K_REG_D0)) & 0xFFFF
        print("Trap num %X" % trap_num)
        if trap_num == UNIMPLEMENTED_TRAP or trap_num not in TRAP_TABLE:
            self._rt.get_cpu().w_reg(M68K_REG_A0, UNIMPL_TRAP_ADDR)
        else:
            self._rt.get_cpu().w_reg(M68K_REG_A0, TRAP_TABLE[trap_num][2])

    def block_copy(self):
        src = self._rt.get_cpu().r_reg(M68K_REG_A0)
        dst = self._rt.get_cpu().r_reg(M68K_REG_A1)
        cnt = self._rt.get_cpu().r_reg(M68K_REG_D0)
        if dst >= (src + cnt) and dst < (src + cnt):
            print("WARNING! _BlockMove source and destination regions overlap!")
        for i in range(cnt):
            self._rt.get_mem().w8(dst + i, self._rt.get_mem().r8(src + i))
        self._rt.get_cpu().w_reg(M68K_REG_D0, 0) # return noErr

    def gestalt(self):
        sel = utils.fourcc_to_bytes(self._rt.get_cpu().r_reg(M68K_REG_D0))
        print("Gestalt called, selector='%s'" % sel.decode())
        self._rt.get_cpu().w_reg(M68K_REG_D0, 0) # report noErr
        if sel == b'os  ':
            resp = 0 # bogus response
            self._rt.get_cpu().w_reg(M68K_REG_A0, resp)
        elif sel == b'proc':
            print("Tell them we have a 68020 CPU")
            self._rt.get_cpu().w_reg(M68K_REG_A0, 3)
        elif sel == b'vm  ':
            self._rt.get_cpu().w_reg(M68K_REG_A0, 0)
        else:
            print("Unimplemented selector")
            self._rt.get_cpu().w_reg(M68K_REG_A0, 0xCAFEBABE)
            self._rt.get_cpu().w_reg(M68K_REG_D0, 0xFFFFEA51)

    def set_res_load(self):
        self._rt.get_mem().w8(LM_RESLOAD, self._args[0] & 0xFF)

    def res_error(self):
        sp = self._rt.get_cpu().r_sp()
        self._rt.get_mem().w16(sp, (self._res_err & 0xFFFF))

    def _res_loaded(self, type, id):
        if type in self._res_used and id in self._res_used[type]:
            return (True, self._res_used[type][id])
        else:
            return (False, 0)

    def _res_type_and_id_from_handle(self, res_h):
        for type, ids in self._res_used.items():
            for id in ids:
                if self._res_used[type][id] == res_h:
                    return (True, type, id)
        return (False, 0, 0)

    def _load_resource(self, res_h):
        res_ptr = self._rt.get_mem().r32(res_h) # dereference resource handle
        if res_ptr == 0:
            print("Try to load resource")
            res, res_type, res_id = self._res_type_and_id_from_handle(res_h)
            if not res:
                print("Invalid resource handle passed!")
                self._res_err = -192 # resNotFound
                return

            res_info = self._rf[res_type][res_id]

            res_ptr = self._mm.alloc_mem(res_info.length)
            print("res_ptr=%X" % res_ptr)
            print("res_info.length=%X" % res_info.length)
            for i in range(res_info.length):
                self._rt.get_mem().w8(res_ptr + i, res_info.data_raw[i])

            self._rt.get_mem().w32(res_h, res_ptr)

        self._res_err = 0 # noErr

    def load_resource(self):
        self._load_resource(self._args[0])

    def get_resource(self):
        res_type = utils.fourcc_to_bytes(self._args[0])
        res_id   = utils.sign_extend(self._args[1], 16)
        print("Res type = %s" % res_type.decode())
        print("Res ID = %d" % res_id)

        self._res_err = 0 # noErr, assume we'll succeed for now

        loaded, res_h = self._res_loaded(res_type, res_id)
        if loaded:
            print("Resource %s, ID=%d already loaded" % (res_type.decode(), res_id))
            if self._rt.get_mem().r8(LM_RESLOAD):
                self._load_resource(res_h)
            sp = self._rt.get_cpu().r_sp()
            self._rt.get_mem().w32(sp, res_h) # return resource handle
            return

        if res_type not in self._rf or res_id not in self._rf[res_type]:
            print("Missing resource %s, ID=%d!" % (res_type.decode(), res_id))
            self._res_err = 0 # noErr
            sp = self._rt.get_cpu().r_sp()
            self._rt.get_mem().w32(sp, 0) # return NIL
            return

        res_info = self._rf[res_type][res_id]

        # if _res_load = FALSE return empty handle
        if not self._rt.get_mem().r8(LM_RESLOAD):
            res_h = self._mm.new_handle(0)
            self._res_used[res_type][res_id] = res_h
            sp = self._rt.get_cpu().r_sp()
            self._rt.get_mem().w32(sp, res_h) # return resource handle
            return

        # otherwise, load resource data into memory
        res_h   = self._mm.new_handle(res_info.length)
        res_ptr = self._rt.get_mem().r32(res_h)
        print("res_ptr=%X" % res_ptr)
        print("res_info.length=%X" % res_info.length)
        for i in range(res_info.length):
            self._rt.get_mem().w8(res_ptr + i, res_info.data_raw[i])

        self._res_used[res_type][res_id] = res_h

        sp = self._rt.get_cpu().r_sp()
        self._rt.get_mem().w32(sp, res_h) # return resource handle

    def named_resource(self):
        res_type = utils.fourcc_to_bytes(self._args[0])
        name_ptr = self._args[1]

        # copy Pascal string from Mac memory to Python bytearray
        pstr = bytearray()
        for i in range(self._rt.get_mem().r8(name_ptr) + 1):
            pstr.append(self._rt.get_mem().r8(name_ptr + i))

        res_name = utils.unpack_pstr(pstr)
        print("resource type: %s" % res_type.decode())
        print("resource name: %s" % res_name)

        if res_type not in self._rf:
            print("Resource type %s not found" % res_type.decode())
            self._res_err = -192 # resNotFound FIXME!??
            sp = self._rt.get_cpu().r_sp()
            self._rt.get_mem().w32(sp, 0) # return NIL
            return

        res_found = False

        for res_id in self._rf[res_type]:
            res_info = self._rf[res_type][res_id]
            if res_info.name != None and res_info.name == res_name:
                res_found = True

        if not res_found:
            self._res_err = -192 # resNotFound FIXME!??
            sp = self._rt.get_cpu().r_sp()
            self._rt.get_mem().w32(sp, 0) # return NIL
            return

        print("TODO: load named resource")

    def hfs_dispatch(self):
        pb_ptr   = self._rt.get_cpu().r_reg(M68K_REG_A0)
        selector = self._rt.get_cpu().r_reg(M68K_REG_D0)
        print("Param block ptr = 0x%X" % pb_ptr)
        print("Selector = %d" % selector)
