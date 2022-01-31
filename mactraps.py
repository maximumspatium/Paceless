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
    # trap #    trap name               method name         trap address  params
    0xA01B : ("_SetZone",               'dummy_trap',       0xFFF30100),
    0xA01F : ("_DisposePtr",            'dummy_trap',       0xFFF30110),
    0xA029 : ("_HLock",                 'dummy_trap',       0xFFF30204),
    0xA02E : ("_BlockMove",             'block_copy',       0xFFF30308),
    0xA04A : ("_HNoPurge",              'dummy_trap',       0xFFF30340),
    0xA055 : ("_StripAddress",          'dummy_trap',       0xFFF3040C),
    0xA064 : ("_MoveHHi",               'dummy_trap',       0xFFF30510),
    0xA069 : ("_HGetState",             'dummy_trap',       0xFFF30514),
    0xA06A : ("_HSetState",             'dummy_trap',       0xFFF30518),
    0xA0AD : ("_GestaltDispatch",       'dummy_trap',       0xFFF30614),
    0xA0BD : ("_CacheFlush",            'dummy_trap',       0xFFF30718),
    0xA11A : ("_GetZone",               'dummy_trap',       0xFFF3081C),
    0xA11E : ("_NewPtr",                'new_ptr',          0xFFF30820),
    0xA122 : ("_NewHandle",             'new_handle',       0xFFF30920),
    0xA128 : ("_RecoverHandle",         'recover_handle',   0xFFF30A24),
    0xA146 : ("_GetTrapAddress",        'get_trap_addr',    0xFFF30A30),
    0xA162 : ("_PurgeSpace",            'dummy_trap',       0xFFF30B28),
    0xA1AD : ("_Gestalt",               'gestalt',          0xFFF30C2C),
    0xA025 : ("_GetHandleSize",         'get_handle_size',  0xFFF30D30),
    0xA31E : ("_NewPtrClear",           'new_ptr',          0xFFF30E34),
    0xA322 : ("_NewHandleClear",        'new_handle',       0xFFF30F38),
    0xA346 : ("_GetOSTrapAddress",      'get_trap_addr',    0xFFF30F3C),
    0xA51E : ("_NewPtrSys",             'new_ptr',          0xFFF31020),
    0xA522 : ("_NewHandleSys",          'new_handle',       0xFFF31040),
    0xA71E : ("_NewPtrSysClear",        'new_ptr',          0xFFF31050),
    0xA722 : ("_NewHandleSysClear",     'new_handle',       0xFFF31080),
    0xA746 : ("_GetToolTrapAddress",    'get_trap_addr',    0xFFF32040),
    0xA81F : ("_Get1Resource",          'get_resource',     0xFFF33000, 'W', 'L'),
    0xA820 : ("_Get1NamedResource",     'named_resource',   0xFFF33004, 'L', 'L'),
    0xA96E : ("_Dequeue",               'dummy_trap',       0x004019F0),
    0xA994 : ("_CurResFile",            'dummy_trap',       0xFFF33044),
    0xA99B : ("_SetResLoad",            'set_res_load',     0xFFF33048, 'B'),
    0xA9A0 : ("_GetResource",           'get_resource',     0xFFF3404C, 'W', 'L'),
    0xA9A2 : ("_LoadResource",          'load_resource',    0xFFF34050, 'L'),
    0xA9AF : ("_ResError",              'res_error',        0xFFF34050)
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
            print("Missing resource %s, ID=%X!" % (res_type.decode(), res_id))
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
