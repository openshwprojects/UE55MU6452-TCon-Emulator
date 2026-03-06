#!/usr/bin/env python3
"""
ARM Cortex-M Thumb-2 Firmware Simulator — Samsung T-CON (flash2_swapped.bin)

Uses Unicorn Engine for CPU emulation and Capstone for disassembly.
Detects UART output, traces execution, and reports how far the firmware runs.

Samsung SDP T-CON chips use non-standard memory-mapped I/O addresses
(e.g., 0x009Dxxxx), so we map a very wide address space and handle
all unmapped accesses dynamically.
"""
import os, sys, struct, time, collections
from datetime import datetime

try:
    from unicorn import *
    from unicorn.arm_const import *
except ImportError:
    sys.exit("ERROR: pip install unicorn")

try:
    from capstone import *
except ImportError:
    sys.exit("ERROR: pip install capstone")

# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════
DIR = os.path.dirname(os.path.abspath(__file__))
FLASH_FILE = os.path.join(DIR, "flash2_swapped.bin")
REPORT_FILE = os.path.join(DIR, "simulation_report.txt")

MAX_INSTRUCTIONS   = 2_000_000
MAX_TIME_SECONDS   = 120

# ═══════════════════════════════════════════════════════════════════
# Globals
# ═══════════════════════════════════════════════════════════════════
uart_output = bytearray()
uart_write_map = collections.Counter()
periph_writes = []       # (addr, size, value, pc) — ALL writes outside SRAM
periph_reads = []        # (addr, size, pc)
instruction_count = 0
execution_trace = []     # (pc, size, mnemonic, op_str, count)
branch_targets = collections.Counter()
stop_reason = "max instructions reached"
start_time = 0
mapped_pages = set()     # track dynamically mapped 64KB pages
infinite_loop_detector = collections.Counter()
pc_history = collections.deque(maxlen=8)  # detect tight infinite loops
primask_val = 0  # emulated PRIMASK register
basepri_val = 0  # emulated BASEPRI register
faultmask_val = 0
last_trace_pcs = collections.deque(maxlen=20)  # for dedup in trace
timer_counter = 0  # monotonic timer counter (increments on read)

# Capstone
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
cs.detail = True

PAGE_SIZE = 0x10000  # 64KB pages for dynamic mapping


def disasm_at(uc, addr, size=4):
    try:
        code = uc.mem_read(addr, min(size, 4))
        for insn in cs.disasm(bytes(code), addr, count=1):
            return insn.mnemonic, insn.op_str
    except:
        pass
    return "???", ""


def ensure_mapped(uc, address):
    """Dynamically map a 64KB page if not already mapped."""
    page = address & ~(PAGE_SIZE - 1)
    if page not in mapped_pages:
        try:
            uc.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
            mapped_pages.add(page)
            return True
        except UcError:
            return False
    return True


# ═══════════════════════════════════════════════════════════════════
# Hooks
# ═══════════════════════════════════════════════════════════════════
def hook_code(uc, address, size, user_data):
    global instruction_count, stop_reason, start_time

    instruction_count += 1

    # Infinite loop detection: only flag truly infinite tiny loops
    infinite_loop_detector[address] += 1
    # Detect a tight loop (same 2-4 instruction pattern repeated)
    pc_history.append(address)
    if len(pc_history) == 8:
        # Check if we're in a 2-instruction loop
        if (pc_history[0] == pc_history[2] == pc_history[4] == pc_history[6] and
            pc_history[1] == pc_history[3] == pc_history[5] == pc_history[7]):
            if infinite_loop_detector[address] > 200_000:
                stop_reason = f"infinite loop detected at PC=0x{address:08X} (hit {infinite_loop_detector[address]} times)"
                uc.emu_stop()
                return

    # Timeout
    if instruction_count % 2000 == 0:
        if time.time() - start_time > MAX_TIME_SECONDS:
            stop_reason = f"wall-clock timeout ({MAX_TIME_SECONDS}s)"
            uc.emu_stop()
            return

    if instruction_count >= MAX_INSTRUCTIONS:
        stop_reason = f"max instruction limit ({MAX_INSTRUCTIONS:,})"
        uc.emu_stop()
        return

    # Trace: first 200 unique sequences + every 500th after
    if instruction_count <= 200 or instruction_count % 500 == 0:
        if address not in last_trace_pcs:  # avoid repeating loop bodies
            mnem, ops = disasm_at(uc, address, size)
            execution_trace.append((address, size, mnem, ops, instruction_count))
            last_trace_pcs.append(address)

    # Track BL/BLX call targets (first 100k instructions)
    if instruction_count <= 100_000:
        try:
            code = bytes(uc.mem_read(address, size))
            for insn in cs.disasm(code, address, count=1):
                if insn.mnemonic in ('bl', 'blx'):
                    if insn.op_str.startswith('#'):
                        try:
                            branch_targets[int(insn.op_str[1:], 0)] += 1
                        except:
                            pass
        except:
            pass


def hook_mem_write_all(uc, access, address, size, value, user_data):
    """Track all memory writes — detect UART by heuristic."""
    global uart_output
    pc = uc.reg_read(UC_ARM_REG_PC)

    # Skip SRAM writes (normal stack/data)
    if 0x20000000 <= address < 0x20010000:
        return

    if len(periph_writes) < 20000:
        periph_writes.append((address, size, value, pc))

    # UART detection: only for addresses NOT in the dedicated 0x84F8 range
    # (those are handled by hook_uart_data_write)
    if 0x84F80000 <= address < 0x84F90000:
        return  # handled by dedicated hook
    if size <= 2:
        byte_val = value & 0xFF
        if byte_val == 0x0A or byte_val == 0x0D or (0x20 <= byte_val <= 0x7E):
            uart_write_map[address] += 1
            uart_output.append(byte_val)


def hook_mem_read_all(uc, access, address, size, value, user_data):
    """Track peripheral reads."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    if 0x20000000 <= address < 0x20010000:
        return
    if 0x00000000 <= address < 0x00100000:
        return  # Flash reads are normal
    if len(periph_reads) < 20000:
        periph_reads.append((address, size, pc))


def hook_mem_invalid(uc, access, address, size, value, user_data):
    """Handle unmapped memory by dynamically mapping it."""
    if ensure_mapped(uc, address):
        return True

    global stop_reason
    pc = uc.reg_read(UC_ARM_REG_PC)
    access_type = "READ" if access in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT) else "WRITE"
    stop_reason = f"unmapped {access_type} at 0x{address:08X} from PC=0x{pc:08X} (could not map)"
    return False


def hook_intr(uc, intno, user_data):
    """Handle CPU interrupts/exceptions."""
    global stop_reason, primask_val, basepri_val, faultmask_val
    pc = uc.reg_read(UC_ARM_REG_PC)

    # Many Thumb-2 system instructions (MRS, MSR, CPS) cause exceptions
    # in Unicorn. Try to emulate them manually.
    if intno == 2:  # SVC / undefined instruction fallback
        return

    # Try to read the instruction bytes and handle MRS/MSR manually
    try:
        code = bytes(uc.mem_read(pc, 4))
        hw1 = struct.unpack_from('<H', code, 0)[0]
        hw2 = struct.unpack_from('<H', code, 2)[0]

        # MRS Rd, <spec_reg>:  encoding T1
        # 11110011 111sssss 10000ddd ssssssss
        # hw1 = 0xF3EF, hw2 = 0x8x00+reg
        if hw1 == 0xF3EF:
            rd = (hw2 >> 8) & 0xF
            sysreg = hw2 & 0xFF
            val = 0
            if sysreg == 0x10:    # PRIMASK
                val = primask_val
            elif sysreg == 0x11:  # BASEPRI
                val = basepri_val
            elif sysreg == 0x12:  # BASEPRI_MAX
                val = basepri_val
            elif sysreg == 0x13:  # FAULTMASK
                val = faultmask_val
            elif sysreg == 0x00:  # APSR / xPSR
                val = 0
            elif sysreg == 0x01:  # IAPSR
                val = 0
            elif sysreg == 0x02:  # EAPSR
                val = 0
            elif sysreg == 0x03:  # xPSR
                val = 0
            elif sysreg == 0x09:  # PSP
                val = uc.reg_read(UC_ARM_REG_SP)
            elif sysreg == 0x08:  # MSP
                val = uc.reg_read(UC_ARM_REG_SP)
            elif sysreg == 0x14:  # CONTROL
                val = 0

            reg_map = {
                0: UC_ARM_REG_R0, 1: UC_ARM_REG_R1, 2: UC_ARM_REG_R2,
                3: UC_ARM_REG_R3, 4: UC_ARM_REG_R4, 5: UC_ARM_REG_R5,
                6: UC_ARM_REG_R6, 7: UC_ARM_REG_R7, 8: UC_ARM_REG_R8,
                9: UC_ARM_REG_R9, 10: UC_ARM_REG_R10, 11: UC_ARM_REG_R11,
                12: UC_ARM_REG_R12, 13: UC_ARM_REG_SP, 14: UC_ARM_REG_LR,
                15: UC_ARM_REG_PC,
            }
            if rd in reg_map:
                uc.reg_write(reg_map[rd], val)
            uc.reg_write(UC_ARM_REG_PC, pc + 4)  # skip this 4-byte instruction
            return

        # MSR <spec_reg>, Rn:  encoding T1
        # 11110011 100Rnnnn 10001000 ssssssss
        if (hw1 & 0xFFF0) == 0xF380 and (hw2 & 0xFF00) == 0x8800:
            rn = hw1 & 0xF
            sysreg = hw2 & 0xFF
            reg_map = {
                0: UC_ARM_REG_R0, 1: UC_ARM_REG_R1, 2: UC_ARM_REG_R2,
                3: UC_ARM_REG_R3, 4: UC_ARM_REG_R4, 5: UC_ARM_REG_R5,
                6: UC_ARM_REG_R6, 7: UC_ARM_REG_R7, 8: UC_ARM_REG_R8,
                9: UC_ARM_REG_R9, 10: UC_ARM_REG_R10, 11: UC_ARM_REG_R11,
                12: UC_ARM_REG_R12, 13: UC_ARM_REG_SP, 14: UC_ARM_REG_LR,
            }
            val = uc.reg_read(reg_map.get(rn, UC_ARM_REG_R0))

            if sysreg == 0x10:
                primask_val = val & 1
            elif sysreg == 0x11:
                basepri_val = val & 0xFF
            elif sysreg == 0x12:
                if val > basepri_val: basepri_val = val & 0xFF
            elif sysreg == 0x13:
                faultmask_val = val & 1

            uc.reg_write(UC_ARM_REG_PC, pc + 4)
            return

        # CPSID/CPSIE instructions (2-byte Thumb)
        # CPSID i = 0xB672, CPSIE i = 0xB662
        hw = struct.unpack_from('<H', code, 0)[0]
        if hw == 0xB672:  # CPSID i — disable interrupts
            primask_val = 1
            uc.reg_write(UC_ARM_REG_PC, pc + 2)
            return
        if hw == 0xB662:  # CPSIE i — enable interrupts
            primask_val = 0
            uc.reg_write(UC_ARM_REG_PC, pc + 2)
            return

    except Exception:
        pass

    # Unknown exception
    stop_reason = f"CPU exception #{intno} at PC=0x{pc:08X}"
    uc.emu_stop()


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════
def run_simulation():
    global start_time, stop_reason, instruction_count
    global primask_val, basepri_val, faultmask_val, timer_counter

    print("=" * 70)
    print("  Samsung T-CON ARM Cortex-M Firmware Simulator")
    print(f"  File: {os.path.basename(FLASH_FILE)}")
    print("=" * 70)

    with open(FLASH_FILE, 'rb') as f:
        firmware = f.read()

    print(f"\n[*] Firmware: {len(firmware):,} bytes ({len(firmware)//1024} KB)")

    # Vector table
    sp_init    = struct.unpack_from('<I', firmware, 0)[0]
    reset_vec  = struct.unpack_from('<I', firmware, 4)[0]
    nmi_vec    = struct.unpack_from('<I', firmware, 8)[0]
    hf_vec     = struct.unpack_from('<I', firmware, 12)[0]
    svcall_vec = struct.unpack_from('<I', firmware, 44)[0]
    pendsv_vec = struct.unpack_from('<I', firmware, 56)[0]

    entry = reset_vec & ~1
    print(f"[*] Vectors: SP=0x{sp_init:08X}  Reset=0x{reset_vec:08X}  NMI=0x{nmi_vec:08X}")
    print(f"             HardFault=0x{hf_vec:08X}  SVCall=0x{svcall_vec:08X}  PendSV=0x{pendsv_vec:08X}")
    print(f"[*] Entry:   0x{entry:08X} (Thumb)")

    # ── Unicorn setup ──
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB + UC_MODE_LITTLE_ENDIAN)

    # Map key regions
    regions = [
        (0x00000000, 0x00100000, "Flash (1MB)"),
        (0x00100000, 0x00100000, "HW Regs 0x001-0x002"),
        (0x00200000, 0x00E00000, "HW Regs 0x002-0x010 (Samsung SDP)"),
        (0x20000000, 0x00010000, "SRAM (64KB)"),
        (0x40000000, 0x00100000, "Peripherals (1MB)"),
        (0xE0000000, 0x00100000, "Cortex-M System (1MB)"),
    ]
    for base, size, name in regions:
        uc.mem_map(base, size, UC_PROT_ALL)
        mapped_pages.update(range(base, base + size, PAGE_SIZE))
        print(f"    {name}: 0x{base:08X}-0x{base+size:08X}")

    # Load firmware into flash
    uc.mem_write(0x00000000, firmware)

    # Pre-fill Cortex-M system registers
    uc.mem_write(0xE000ED00, struct.pack('<I', 0x411FC231))   # CPUID: Cortex-M3
    uc.mem_write(0xE000ED08, struct.pack('<I', 0x00000000))   # VTOR
    uc.mem_write(0xE000E010, struct.pack('<I', 0x00000004))   # SysTick CTRL
    uc.mem_write(0xE000ED0C, struct.pack('<I', 0xFA050000))   # AIRCR

    # Samsung SDP UART status register — bit 2 = TX ready
    # The firmware polls 0x009D0E10 & 4 in a tight loop waiting for UART TX ready
    uc.mem_write(0x009D0E10, struct.pack('<I', 0x0000FFFF))   # All status bits set

    # Samsung SDP timer registers — used for delay loops
    # Pre-fill with initial values so firmware delay loops see time passing
    uc.mem_write(0x009D0B88, struct.pack('<I', 0x00001000))   # Timer counter low
    uc.mem_write(0x009D0B8C, struct.pack('<I', 0x00000000))   # Timer counter high

    # Registers
    uc.reg_write(UC_ARM_REG_SP, sp_init)
    uc.reg_write(UC_ARM_REG_LR, 0xFFFFFFFF)
    uc.reg_write(UC_ARM_REG_CONTROL, 0)

    # Hook for SDP register reads: UART status + timer counters
    def hook_sdp_read(uc, access, address, size, value, user_data):
        """Handle reads from Samsung SDP peripheral registers."""
        global timer_counter
        # Keep UART TX status register always "ready"
        if address == 0x009D0E10:
            uc.mem_write(0x009D0E10, struct.pack('<I', 0x0000FFFF))

        # Auto-increment timer counters on read
        # The delay loop at 0x6568 reads these to measure elapsed time
        if address == 0x009D0B88 or address == 0x009D0B8C:
            timer_counter += 1000  # increment by ~1000 per read (fast timer)
            lo = timer_counter & 0xFFFFFFFF
            hi = (timer_counter >> 32) & 0xFFFFFFFF
            uc.mem_write(0x009D0B88, struct.pack('<I', lo))
            uc.mem_write(0x009D0B8C, struct.pack('<I', hi))

    def hook_uart_data_write(uc, access, address, size, value, user_data):
        """Capture writes to UART data register at 0x84F8xxxx."""
        global uart_output
        pc = uc.reg_read(UC_ARM_REG_PC)
        if 0x84F80000 <= address < 0x84F80100:
            byte_val = value & 0xFF
            if byte_val == 0x0A or byte_val == 0x0D or (0x20 <= byte_val <= 0x7E):
                uart_write_map[address] += 1
                uart_output.append(byte_val)
        if len(periph_writes) < 20000:
            periph_writes.append((address, size, value, pc))

    # Hooks
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write_all)
    uc.hook_add(UC_HOOK_MEM_READ, hook_sdp_read,
                begin=0x009D0000, end=0x009E0000)
    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read_all)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_uart_data_write,
                begin=0x84F80000, end=0x84F90000)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    uc.hook_add(UC_HOOK_INTR, hook_intr)

    # ── Run with instruction-fix restart loop ──
    print(f"\n[*] Emulating (max {MAX_INSTRUCTIONS:,} insns, {MAX_TIME_SECONDS}s)...")
    start_time = time.time()
    current_entry = entry | 1
    max_restarts = 500  # max number of manual instruction fixes

    REG_MAP = {
        0: UC_ARM_REG_R0, 1: UC_ARM_REG_R1, 2: UC_ARM_REG_R2,
        3: UC_ARM_REG_R3, 4: UC_ARM_REG_R4, 5: UC_ARM_REG_R5,
        6: UC_ARM_REG_R6, 7: UC_ARM_REG_R7, 8: UC_ARM_REG_R8,
        9: UC_ARM_REG_R9, 10: UC_ARM_REG_R10, 11: UC_ARM_REG_R11,
        12: UC_ARM_REG_R12, 13: UC_ARM_REG_SP, 14: UC_ARM_REG_LR,
        15: UC_ARM_REG_PC,
    }

    for restart_count in range(max_restarts):
        try:
            uc.emu_start(current_entry, 0xFFFFFFFF,
                         timeout=MAX_TIME_SECONDS * 1_000_000)
            break  # Normal exit
        except UcError as e:
            pc = uc.reg_read(UC_ARM_REG_PC)

            if e.errno != UC_ERR_INSN_INVALID:
                stop_reason = f"UcError: {e} at PC=0x{pc:08X}"
                break

            # Try to manually emulate the invalid instruction
            try:
                code = bytes(uc.mem_read(pc, 4))
                hw1 = struct.unpack_from('<H', code, 0)[0]
                hw2 = struct.unpack_from('<H', code, 2)[0]
                handled = False

                # MRS Rd, <spec_reg> — 0xF3EF 0x8xxx
                if hw1 == 0xF3EF:
                    rd = (hw2 >> 8) & 0xF
                    sysreg = hw2 & 0xFF
                    val = 0
                    if sysreg == 0x10: val = primask_val
                    elif sysreg == 0x11: val = basepri_val
                    elif sysreg == 0x13: val = faultmask_val
                    elif sysreg in (0x08, 0x09): val = uc.reg_read(UC_ARM_REG_SP)
                    if rd in REG_MAP:
                        uc.reg_write(REG_MAP[rd], val)
                    current_entry = (pc + 4) | 1
                    handled = True

                # MSR <spec_reg>, Rn — 0xF38x 0x88xx
                elif (hw1 & 0xFFF0) == 0xF380 and (hw2 & 0xFF00) == 0x8800:
                    rn = hw1 & 0xF
                    sysreg = hw2 & 0xFF
                    val = uc.reg_read(REG_MAP.get(rn, UC_ARM_REG_R0))
                    if sysreg == 0x10: primask_val = val & 1
                    elif sysreg == 0x11: basepri_val = val & 0xFF
                    elif sysreg == 0x13: faultmask_val = val & 1
                    current_entry = (pc + 4) | 1
                    handled = True

                # MSR <spec_reg>, Rn — alternate encoding 0xF38x 0x8x00
                elif (hw1 & 0xFFF0) == 0xF380:
                    rn = hw1 & 0xF
                    sysreg = hw2 & 0xFF
                    val = uc.reg_read(REG_MAP.get(rn, UC_ARM_REG_R0))
                    if sysreg == 0x10: primask_val = val & 1
                    elif sysreg == 0x11: basepri_val = val & 0xFF
                    elif sysreg == 0x09 or sysreg == 0x08:
                        pass  # MSR MSP/PSP — ignore for now
                    current_entry = (pc + 4) | 1
                    handled = True

                # DSB/DMB/ISB (barrier instructions) — 0xF3BF 0x8Fxx
                elif hw1 == 0xF3BF and (hw2 & 0xFF00) in (0x8F00,):
                    current_entry = (pc + 4) | 1
                    handled = True

                # CPSID i = 0xB672
                elif hw1 == 0xB672:
                    primask_val = 1
                    current_entry = (pc + 2) | 1
                    handled = True

                # CPSIE i = 0xB662
                elif hw1 == 0xB662:
                    primask_val = 0
                    current_entry = (pc + 2) | 1
                    handled = True

                # SVC — skip
                elif (hw1 & 0xFF00) == 0xDF00:
                    current_entry = (pc + 2) | 1
                    handled = True

                # WFI / WFE (wait for interrupt/event)
                elif hw1 == 0xBF30 or hw1 == 0xBF20:
                    current_entry = (pc + 2) | 1
                    handled = True

                if not handled:
                    stop_reason = f"unhandled instruction 0x{hw1:04X} 0x{hw2:04X} at PC=0x{pc:08X}"
                    break

                if restart_count % 50 == 0 and restart_count > 0:
                    print(f"    [{restart_count} instruction fixes applied...]")

            except Exception as ex:
                stop_reason = f"error fixing instruction at PC=0x{pc:08X}: {ex}"
                break
    else:
        stop_reason = f"too many instruction fixes ({max_restarts})"

    elapsed = time.time() - start_time

    # ── Collect state ──
    reg_names = [
        ('R0', UC_ARM_REG_R0), ('R1', UC_ARM_REG_R1), ('R2', UC_ARM_REG_R2),
        ('R3', UC_ARM_REG_R3), ('R4', UC_ARM_REG_R4), ('R5', UC_ARM_REG_R5),
        ('R6', UC_ARM_REG_R6), ('R7', UC_ARM_REG_R7), ('R8', UC_ARM_REG_R8),
        ('R9', UC_ARM_REG_R9), ('R10', UC_ARM_REG_R10), ('R11', UC_ARM_REG_R11),
        ('R12', UC_ARM_REG_R12), ('SP', UC_ARM_REG_SP), ('LR', UC_ARM_REG_LR),
        ('PC', UC_ARM_REG_PC),
    ]
    regs = {n: uc.reg_read(r) for n, r in reg_names}

    # ═══════════════════════════════════════════════════════════════
    # Report
    # ═══════════════════════════════════════════════════════════════
    R = []
    def P(s=""):
        R.append(s); print(s)

    P(f"\n{'='*70}")
    P(f"  SIMULATION RESULTS — Samsung T-CON (flash2_swapped.bin)")
    P(f"{'='*70}")
    P(f"\n  Stop reason:     {stop_reason}")
    P(f"  Instructions:    {instruction_count:,}")
    P(f"  Wall time:       {elapsed:.2f}s")
    P(f"  Speed:           {instruction_count/max(elapsed,0.001):,.0f} insn/s")
    P(f"  Final PC:        0x{regs['PC']:08X}")
    m, o = disasm_at(uc, regs['PC'])
    P(f"  Last instruction:{m} {o}")
    P(f"  Dynamic pages:   {len(mapped_pages)} ({len(mapped_pages)*64} KB mapped)")

    P(f"\n── Registers ──")
    for n, r in reg_names:
        v = regs[n]
        tag = ""
        if 0x20000000 <= v < 0x20010000: tag = " [SRAM]"
        elif 0x00000000 <= v < 0x00100000: tag = " [Flash]"
        elif 0x40000000 <= v < 0x50000000: tag = " [Periph]"
        elif 0xE0000000 <= v < 0xF0000000: tag = " [System]"
        elif 0x00100000 <= v < 0x01000000: tag = " [SDP HW]"
        P(f"    {n:4s} = 0x{v:08X}{tag}")

    # ── UART Output ──
    P(f"\n{'='*70}")
    P(f"  UART OUTPUT")
    P(f"{'='*70}")
    if uart_output:
        if uart_write_map:
            top = uart_write_map.most_common(10)
            P(f"\n  Candidate UART TX registers (by byte-write count):")
            for addr, count in top:
                P(f"    0x{addr:08X} : {count:5d} writes")
            best = top[0][0]
            P(f"\n  ► Most likely UART TX data register: 0x{best:08X}")

        P(f"\n  Captured output ({len(uart_output)} bytes):")
        P(f"  {'─'*60}")
        text = uart_output.decode('ascii', errors='replace')
        for line in text.split('\n'):
            P(f"{line}")
        P(f"  {'─'*60}")
    else:
        P(f"  No UART output detected.")

    # ── Peripheral Access Analysis ──
    P(f"\n{'='*70}")
    P(f"  PERIPHERAL ACCESS ANALYSIS")
    P(f"{'='*70}")
    P(f"  Total writes logged: {len(periph_writes)}")
    P(f"  Total reads logged:  {len(periph_reads)}")

    if periph_writes:
        wr_addrs = collections.Counter()
        wr_first = {}
        for addr, sz, val, pc in periph_writes:
            wr_addrs[addr] += 1
            if addr not in wr_first:
                wr_first[addr] = (val, pc)

        P(f"\n  Top 25 written HW registers:")
        P(f"  {'Address':>12s}  {'Count':>6s}  {'First Value':>12s}  {'From PC':>10s}")
        for addr, count in wr_addrs.most_common(25):
            fv, fpc = wr_first[addr]
            P(f"    0x{addr:08X}  {count:6d}  0x{fv:08X}    0x{fpc:08X}")

    if periph_reads:
        rd_addrs = collections.Counter()
        for addr, sz, pc in periph_reads:
            rd_addrs[addr] += 1

        P(f"\n  Top 25 read HW registers:")
        P(f"  {'Address':>12s}  {'Count':>6s}")
        for addr, count in rd_addrs.most_common(25):
            P(f"    0x{addr:08X}  {count:6d}")

    # ── Address Space Usage ──
    P(f"\n  Address space regions accessed:")
    region_writes = collections.Counter()
    for addr, sz, val, pc in periph_writes:
        region_writes[addr >> 20] += 1
    for region, count in sorted(region_writes.items()):
        P(f"    0x{region:03X}xxxxx: {count:6d} writes")

    region_reads = collections.Counter()
    for addr, sz, pc in periph_reads:
        region_reads[addr >> 20] += 1
    for region, count in sorted(region_reads.items()):
        P(f"    0x{region:03X}xxxxx: {count:6d} reads")

    # ── Execution Trace ──
    P(f"\n{'='*70}")
    P(f"  EXECUTION TRACE (first 300 sampled)")
    P(f"{'='*70}")
    for addr, size, mnem, ops, idx in execution_trace[:300]:
        P(f"  [{idx:7d}] 0x{addr:08X}: {mnem:10s} {ops}")

    # ── Most Called Functions ──
    if branch_targets:
        P(f"\n{'='*70}")
        P(f"  MOST CALLED FUNCTION TARGETS")
        P(f"{'='*70}")
        for target, count in branch_targets.most_common(40):
            # Try to correlate with known string addresses
            P(f"    0x{target:08X}: {count:5d} calls")

    # ── Hot Loops / Tight Loops ──
    P(f"\n── Hot Loops (most-executed PCs) ──")
    for pc, count in infinite_loop_detector.most_common(20):
        m2, o2 = disasm_at(uc, pc)
        P(f"    0x{pc:08X}: {count:6d} hits — {m2} {o2}")

    # ── Code Coverage ──
    P(f"\n── Code Coverage ──")
    all_pcs = set(addr for addr, _, _, _, _ in execution_trace)
    if all_pcs:
        P(f"  PC range: 0x{min(all_pcs):08X} - 0x{max(all_pcs):08X}")
        P(f"  Unique PCs (sampled): {len(all_pcs)}")

    # ── Known Strings ──
    P(f"\n── Known String Function Status ──")
    known = {
        0x008921: "Oops!!! HardFault_Handler",
        0x0089BD: "user_debug",
        0x0089C8: "usr_boot_main",
        0x0089D6: "Enter Multi Tasking",
        0x0089EB: "UART RDY",
        0x008A05: "20170825_0922 (build timestamp)",
        0x008A13: "I2C M Init",
        0x008A2C: "MEMIF_CMD_SRAM_REFLASH",
        0x015161: "Cold Booting !!!!!",
        0x015175: "Warm Booting !!!!!",
        0x015211: "TCON RDY",
    }
    for saddr, s in sorted(known.items()):
        reached = any(abs(a - saddr) < 0x200 for a in all_pcs)
        P(f"    0x{saddr:06X} \"{s}\" — {'✓ REACHED' if reached else '✗ not reached'}")

    # ── SRAM contents peek ──
    P(f"\n── SRAM Contents (first 256 bytes from SP area) ──")
    try:
        sram_top = uc.mem_read(sp_init - 256, 256)
        for i in range(0, 256, 16):
            off = sp_init - 256 + i
            h = ' '.join(f'{b:02x}' for b in sram_top[i:i+16])
            a = ''.join(chr(b) if 32<=b<127 else '.' for b in sram_top[i:i+16])
            P(f"  0x{off:08X}: {h:<48s} {a}")
    except:
        P(f"  [could not read SRAM]")

    # Save
    P(f"\n{'='*70}")
    P(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    P(f"{'='*70}")

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(R))

    print(f"\n[✓] Done! Report saved.")


if __name__ == '__main__':
    run_simulation()
