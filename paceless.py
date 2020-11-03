import argparse
import logging
import os
import struct
import sys

import rsrcfork
from capstone import *
from bare68k import *
from bare68k.consts import *
from bare68k.machine import *
import bare68k.api.tools as tools
from mactraps import MacTraps, InvalidTrap
import utils

md = Cs(CS_ARCH_M68K, CS_MODE_M68K_020)

def disas_single_68k(address, code, mac_traps):
    ''' Disassble single 68k instruction with Capstone engine '''
    if (code[0] & 0xF0) == 0xA0:
        trap_num = (code[0] << 8) | code[1]
        try:
            print("0x%x\t\t%s" % (address, mac_traps.get_trap_name(trap_num)))
        except InvalidTrap:
            print("0x%x\t\tDC.W\t$0x%X" % (address, trap_num))
        return 2
    instrs = md.disasm(code, address)
    i = next(instrs)
    print("0x%x\t\t%s\t%s" % (i.address, i.mnemonic.upper(), i.op_str.upper()))
    return i.size

def is_cpu_reg(reg_name):
    if len(reg_name) < 2 or len(reg_name) > 2:
        return False
    if reg_name == "PC" or reg_name == "SR":
        return True
    elif reg_name.startswith("A") or reg_name.startswith("D"):
        flag,reg_num = utils.str_to_int(reg_name[1:2])
        if not flag:
            return False
        if reg_num >= 0 and reg_num <= 7:
            return True
        else:
            return False
    else:
        return False

def read_cpu_reg(cpu_obj, reg_name):
    if not is_cpu_reg(reg_name):
        print("Invalid register name %s" % reg_name)
        return
    if reg_name == "PC":
        return cpu_obj.r_pc()
    elif reg_name == "SR":
        return cpu_obj.r_sr()
    reg_num = int(reg_name[1:2], 0)
    if reg_name.startswith("A"):
        return cpu_obj.r_ax(reg_num)
    else:
        return cpu_obj.r_dx(reg_num)

def write_cpu_reg(cpu_obj, reg_name, val):
    if not is_cpu_reg(reg_name):
        print("Invalid register name %s" % reg_name)
        return
    if reg_name == "PC":
        cpu_obj.w_pc(val)
        return
    elif reg_name == "SR":
        cpu_obj.w_sr(val)
        return
    reg_num = int(reg_name[1:2], 0)
    if reg_name.startswith("A"):
        cpu_obj.w_ax(reg_num, val)
    else:
        cpu_obj.w_dx(reg_num, val)

def is_size_ind(dsize):
    if len(dsize) == 1 and (dsize == "B" or dsize == "W" or dsize == "L"):
        return True
    elif (dsize == "BYTE" or dsize == "WORD" or dsize == "LONGWORD"):
        return True
    else:
        return False

def write_memory(cpu_obj, addr, val, dsize):
    if not is_size_ind(dsize):
        print("Invalid size: %s" % dsize)
        return

    if (dsize == "B" or dsize == "BYTE"):
        mem.w8(addr, val)
    elif (dsize == "W" or dsize == "WORD"):
        if addr & 1:
            print("Store address 0x%s not aligned on word boundary!" % addr)
            return
        mem.w16(addr, val)
    elif (dsize == "L" or dsize == "LONGWORD"):
        if addr & 3:
            print("Store address 0x%X not aligned on longword boundary!" % addr)
            return
        mem.w32(addr, val)
    else:
        return

# ------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description='Mac 68k virtualization package.')
    ap.add_argument("path", help="path to the file to execute")
    ap.add_argument("-r", "--rom_path",
        help="path to ROM file to load during startup")
    ap.add_argument("-b", "--rom_base", help="base address for ROM",
        default=0xFFC00000, type=lambda x: int(x, 0))

    args = ap.parse_args()

    # configure logging
    runtime.log_setup(level=logging.INFO)

    # configure CPU: emulate a classic m68k
    cpu_cfg = CPUConfig(M68K_CPU_TYPE_68020)

    mem_cfg = MemoryConfig()

    # create a RAM region (64k) starting at address 0
    mem_cfg.add_ram_range(0, 5)

    if args.rom_path:
        print("Loading ROM...")
        with open(args.rom_path, 'rb') as rom_file:
            rom_len = os.path.getsize(args.rom_path)
            mem_cfg.add_rom_range(args.rom_base // 65536, rom_len // 65536)
            rom_data = rom_file.read()

    run_cfg = RunConfig()

    rt = Runtime(cpu_cfg, mem_cfg, run_cfg)

    mem = rt.get_mem()

    if args.rom_path:
        # copy ROM image to the dedicated memory region
        for i in range(rom_len):
            mem.w8(args.rom_base + i, rom_data[i])

        # set lowmem global ROMBase to the starting address of the loaded ROM
        mem.w32(0x2AE, args.rom_base)

    with rsrcfork.open(args.path) as rf:
        if b'CODE' in rf and 0 in rf[b'CODE']:
            print("Found executable 68k code!")
            jt_res = rf[b'CODE'][0]
            #print(jt_res.length)
            jt_data = jt_res.data_raw

            # read jump table header
            jt_header = struct.unpack('>LLLL', jt_data[0:16])

            # read first entry of the jump table
            jt_1st_entry = struct.unpack('>HHHH', jt_data[16:24])
            if jt_1st_entry[1] != 0x3F3C or jt_1st_entry[3] != 0xA9F0:
                print("Invalid jump table! 1st entry is corrupted!")
                exit(1)

            mt = MacTraps(rt, args.path)

            jt_length = jt_header[2]
            jt_offset = jt_header[3]
            print("JT length:", hex(jt_offset + jt_length))
            jt_handle = mt._mm.new_handle(jt_offset + jt_length)
            a5_base = mem.r32(jt_handle)

            # copy JT from CODE,0 to A5 + jt_offset
            for i in range(jt_length):
                mem.w8(a5_base + jt_offset + i, jt_data[16 + i])

            ep_seg_id = jt_1st_entry[2]
            ep_offset = jt_1st_entry[0]
            print("1st entry of the JT points to segment %d, offset %x" % (ep_seg_id, ep_offset))
            print("Loading code segment %d" % ep_seg_id)
            ep_res = rf[b'CODE'][ep_seg_id]
            ep_res_len = ep_res.length
            ep_data = ep_res.data_raw

            prog_handle = mt._mm.new_handle(ep_res_len)
            prog_base = mem.r32(prog_handle)
            print("prog_handle=%X, prog_base=%X" % (prog_handle, prog_base))

            for i in range(ep_res_len):
                mem.w8(prog_base + i, ep_data[i])
        else:
            print("No executable 68k code was found!")
            exit(1)


    def atrap_handler(event):
        print(hex(event.value))
        print("A-Trap handler invoked!")
        if event.value == 0xA128:
            rt.get_cpu().w_reg(M68K_REG_A0, 0xCAFEBABE)
        elif event.value == 0xA025:
            if rt.get_cpu().r_reg(M68K_REG_A0) == 0xCAFEBABE:
                rt.get_cpu().w_reg(M68K_REG_D0, ep_res_len)

    def instr_hook_handler(event):
        return CPU_EVENT_INSTR_HOOK

    def bkpt(event):
        print("Breakpoint hit!")


    rt.set_handler(CPU_EVENT_ALINE_TRAP, mt.atrap_handler)
    rt.set_handler(CPU_EVENT_INSTR_HOOK, instr_hook_handler)

    tools.setup_breakpoints(10)
    #tools.set_breakpoint(0, 0x20082, MEM_FC_SUPER_MASK, "BKPT1")
    #tools.enable_breakpoint(0)

    rt.reset(prog_base + ep_offset + 4, 0x1FF00)

    # set up A5 to point to the "A5 world" with JT loaded
    rt.get_cpu().w_reg(M68K_REG_A5, a5_base)

    #mem.w32(0x28, 0x1000)  # Exception Vector A-Line
    #mem.w16(0x1000, 0x4e70)

    #mem.w16(rt.get_reset_pc() + 2, 0xA128)
    #mem.w16(rt.get_reset_pc() + 4, 0x4e70)
    #mem.w16(PROG_BASE + 0x8A, 0x4e70)

    #for i in range(8):
    #    print(hex(mem.r16(PROG_BASE + i*2)))

    #da_obj = Disassembler()

    def instr_hook(pc):
        #print("Instruction hook invoked!")
        #print(hex(pc))
        return CPU_EVENT_DONE

    class until_hook:
        def __init__(self, target):
            self.target = target

        def func(self, pc):
            if pc == self.target:
                return CPU_EVENT_DONE

    print("\nWelcome to Mac 68k simulator.")
    print("Enter 'help' for getting help on debugging commands.\n")

    cmd = ""
    prev_cmd = ""

    while cmd != "quit":
        inp_str = input("> ")

        if inp_str == "":
            if prev_cmd != "":
                inp_str = prev_cmd
            else:
                continue

        prev_cmd = inp_str

        words = inp_str.split()
        cmd = words[0]

        if cmd == "quit":
            pass
        elif cmd == "step" or cmd == "si":
            if len(words) == 2:
                flag,count = utils.str_to_int(words[1])
                if not flag:
                    print("Invalid instruction count %s" % words[1])
                    continue
            else:
                count = 1
            rt.get_cpu().set_instr_hook_func(instr_hook)
            for i in range(count):
                rt.run()
            rt.get_cpu().set_instr_hook_func(None)
        elif cmd == "until":
            if len(words) < 2:
                print("Missing parameter")
                continue
            flag,addr = utils.str_to_int(words[1])
            if not flag:
                print("Invalid target address %s" % words[1])
                continue
            print("Execute until 0x%03X" % addr)
            uh = until_hook(addr)
            rt.get_cpu().set_instr_hook_func(uh.func)
            rt.run()
            rt.get_cpu().set_instr_hook_func(None)
            #tools.set_breakpoint(0, addr, MEM_FC_SUPER_MASK, "BKPT1")
            #done = False
            #while not done:
            #    ne = rt.get_cpu().execute(1000)
            #    print(ne)
            #    ri = rt.get_cpu().get_info()
            #    for i in range(ne):
            #        evt = ri.events[i]
            #        if evt.ev_type == CPU_EVENT_BREAKPOINT and evt.addr == addr:
            #            done = True
            #            break

            #tools.disable_breakpoint(0)
        elif cmd == "regs":
            #cpu_obj.print_state()
            print(rt.get_cpu().get_regs())
        elif cmd == "disas":
            if len(words) < 3:
                if len(words) == 1:
                    addr = rt.get_cpu().r_pc()
                    count = 5
                else:
                    print("Missing parameters")
                    continue
            else:
                if is_cpu_reg(words[1].upper()):
                    addr = read_cpu_reg(rt.get_cpu(), words[1].upper())
                else:
                    flag,addr = utils.str_to_int(words[1])
                    if not flag:
                        print("Invalid address %s" % words[1])
                        continue
                flag,count = utils.str_to_int(words[2])
                if not flag:
                    print("Invalid count %s" % words[2])
                    continue

            try:
                for i in range(count):
                    da_prefetch = bytearray()
                    for n in range(10):
                        da_prefetch.append(mem.r8(addr + n))
                    sz = disas_single_68k(addr, da_prefetch, mt)
                    addr += sz
            except StopIteration:
                print("Unable to disassemble instruction at 0x%X" % addr)
                #op, arg, pc = da_obj.disassemble_str(addr)
                #if arg != None:
                #    print("0x%X\t\t%s\t%s" % (addr, op.upper(), arg.upper()))
                #else:
                #    print("0x%X\t\t%s" % (addr, op.upper()))
                #addr = pc
        elif cmd == "dump":
            if len(words) < 3:
                print("Invalid command syntax")
                continue
            if is_cpu_reg(words[1].upper()):
                addr = read_cpu_reg(rt.get_cpu(), words[1].upper())
            else:
                flag,addr = utils.str_to_int(words[1])
                if not flag:
                    print("Invalid address %s" % words[1])
                    continue
            flag,count = utils.str_to_int(words[2])
            if not flag:
                print("Invalid count %s" % words[2])
                continue
            if len(words) == 4:
                with open(words[3], 'wb') as out_file:
                    buf = bytearray()
                    for i in range(count):
                        buf.append(mem.r8(addr + i))
                    out_file.write(buf)
            else:
                for i in range(count):
                    if (i & 0xF) == 0:
                        print("\n0x%X\t" % (addr + i), end = '')
                    print("%02X " % (mem.r8(addr + i)), end = '')
                print("\n")
        elif cmd == "set":
            if len(words) < 2:
                print("Missing parameters")
                continue
            args = words[1].split('=')
            if len(args) < 2:
                print("Invalid command syntax")
                continue
            reg = args[0].upper()
            flag,val = utils.str_to_int(args[1])
            if not flag:
                print("Invalid value %s" % args[1])
                continue
            if not is_cpu_reg(reg):
                print("Unknown CPU register %s" % reg)
                continue
            write_cpu_reg(rt.get_cpu(), reg, val)
        elif cmd == "setmem":
            if len(words) < 4:
                print("Invalid command syntax")
                continue
            if is_cpu_reg(words[1].upper()):
                addr = read_cpu_reg(rt.get_cpu(), words[1].upper())
            else:
                flag,addr = utils.str_to_int(words[1])
                if not flag:
                    print("Invalid address %s" % words[1])
                    continue
            flag,val = utils.str_to_int(words[2])
            if not flag:
                print("Invalid value %s" % words[2])
                continue
            dsize = words[3].upper()
            write_memory(rt.get_cpu(), addr, val, dsize)
        elif cmd == "help":
            print("step [N]     - execute N instructions")
            print("               N defaults to 1 when omitted\n")
            print("si           - alias for 'step'\n")
            print("until addr   - execute until addr is reached\n")
            print("disas X Y    - disassemble Y instructions starting at X")
            print("               disas with no params disassembles")
            print("               five instructions starting at PC")
            print("               X can be also any valid 68k register\n")
            print("regs         - print internal registers\n")
            print("dump X Y     - dump Y bytes starting at address X")
            print("               X can be also any valid 68k register\n")
            print("set X=Y      - change value of register X to Y\n")
            print("setmem X Y Z - set address X to value Y with designated size Z")
            print("               size is one of: byte (b), word (w), longword (l)")
            print("               X can be also any valid 68k register\n")
            print("quit         - shut down the simulator")
        else:
            print("Unknown command: %s" % cmd)

    rt.shutdown()
