---
name: rev-unicorn-debug
description: Debug specific code snippets or functions using Unicorn emulator with environment simulation via hooks
---

# rev-unicorn-debug - Unicorn Emulation Debugger

Debug and emulate specific code fragments or functions using the Unicorn engine. Analyze context dependencies (JNI, syscalls, library functions) and simulate them through hook mechanisms to complete the user's debugging goal.

## When to Use

Activate when the user asks to:
- Emulate / debug a specific function or code snippet with Unicorn
- Trace execution of a binary fragment without running the full program
- Understand what a function does by stepping through it
- Decrypt / decode data by emulating the algorithm
- Bypass environment dependencies (JNI, syscalls, libc) during emulation

---

## Core Principles

1. **Load file raw first** — do NOT parse ELF/PE/Mach-O headers. Read the file as raw bytes and map directly into Unicorn memory. We only need to emulate specific functions, not the entire binary.
2. **Identify context dependencies** — analyze the target code for external calls (JNI, syscalls, libc, imports) and hook them to provide simulated responses.
3. **Use callbacks extensively** — leverage Unicorn's hook system for debugging, tracing, error recovery, and environment simulation.
4. **Iterative fix** — when emulation crashes, use the callback info to diagnose and fix (map missing memory, hook unhandled calls, fix register state).

---

## Step 1: Load Binary and Map Memory

**Always prefer raw loading over format parsing:**

```python
from unicorn import *
from unicorn.arm64_const import *  # or arm_const, x86_const, etc.
import struct

# Read raw binary
with open("target.so", "rb") as f:
    binary = f.read()

# Create emulator (pick arch based on target)
mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
# mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)       # ARM32 Thumb
# mu = Uc(UC_ARCH_X86, UC_MODE_64)          # x86-64
# mu = Uc(UC_ARCH_X86, UC_MODE_32)          # x86-32
# mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32)     # MIPS32

# Map and write binary at its expected base address
BASE = 0x0
MEM_SIZE = (len(binary) + 0x1000) & ~0xFFF  # page-align
mu.mem_map(BASE, MEM_SIZE, UC_PROT_ALL)
mu.mem_write(BASE, binary)

# Stack
STACK_BASE = 0x7F000000
STACK_SIZE = 0x100000  # 1MB
mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
mu.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x100)

# Heap (for malloc simulation)
HEAP_BASE = 0x80000000
HEAP_SIZE = 0x100000
mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
heap_ptr = HEAP_BASE  # simple bump allocator
```

**If raw loading fails** (e.g. code references segments at specific addresses), then parse the format minimally — only map the segments you need:

```python
from elftools.elf.elffile import ELFFile

with open("target.so", "rb") as f:
    elf = ELFFile(f)
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD":
            addr = seg.header.p_vaddr
            size = max(seg.header.p_memsz, seg.header.p_filesz)
            size = (size + 0xFFF) & ~0xFFF
            if size == 0:
                continue
            mu.mem_map(addr, size, UC_PROT_ALL)
            mu.mem_write(addr, seg.data())
```

---

## Step 2: Analyze Context Dependencies

Before emulating, read the target function and identify what it calls:

**Common dependency categories:**

| Category | Examples | Simulation Strategy |
|----------|----------|-------------------|
| libc | `malloc`, `free`, `memcpy`, `strlen`, `printf` | Hook and implement in Python |
| JNI | `GetStringUTFChars`, `FindClass`, `GetMethodID` | Hook JNI function table, return fake objects |
| Syscalls | `read`, `write`, `mmap`, `ioctl` | Hook interrupt/svc and dispatch by syscall number |
| C++ runtime | `operator new`, `__cxa_throw` | Hook and simulate |
| Library calls | `pthread_mutex_lock`, `dlopen` | Hook and return success/stub |

---

## Step 3: Hook External Calls

### Hook Approach: Intercept BL/CALL Instructions

For imported functions, hook the known addresses (from IDA exports/imports) and simulate:

```python
# Track which addresses are import stubs that need simulation
import_hooks = {}

def hook_code(mu, address, size, user_data):
    if address in import_hooks:
        handler = import_hooks[address]
        handler(mu)
        # Skip the function — return to caller
        ret_addr = mu.reg_read(UC_ARM64_REG_LR)
        mu.reg_write(UC_ARM64_REG_PC, ret_addr)

mu.hook_add(UC_HOOK_CODE, hook_code)
```

### Simulating Common libc Functions

```python
def sim_malloc(mu):
    global heap_ptr
    size = mu.reg_read(UC_ARM64_REG_X0)
    result = heap_ptr
    heap_ptr += (size + 0xF) & ~0xF
    mu.reg_write(UC_ARM64_REG_X0, result)

def sim_free(mu):
    pass  # nop

def sim_memcpy(mu):
    dst, src, n = mu.reg_read(UC_ARM64_REG_X0), mu.reg_read(UC_ARM64_REG_X1), mu.reg_read(UC_ARM64_REG_X2)
    mu.mem_write(dst, bytes(mu.mem_read(src, n)))

def sim_strlen(mu):
    s = mu.reg_read(UC_ARM64_REG_X0)
    data = mu.mem_read(s, 0x1000)
    mu.reg_write(UC_ARM64_REG_X0, data.index(0) if 0 in data else len(data))

def sim_memset(mu):
    dst, val, n = mu.reg_read(UC_ARM64_REG_X0), mu.reg_read(UC_ARM64_REG_X1) & 0xFF, mu.reg_read(UC_ARM64_REG_X2)
    mu.mem_write(dst, bytes([val] * n))

# Register hooks
import_hooks[MALLOC_ADDR] = sim_malloc
import_hooks[FREE_ADDR] = sim_free
import_hooks[MEMCPY_ADDR] = sim_memcpy
import_hooks[STRLEN_ADDR] = sim_strlen
```

### Simulating JNI Environment (Android)

```python
# Create a fake JNIEnv function table in memory
JNIENV_BASE = 0x60000000
JNIENV_SIZE = 0x10000
mu.mem_map(JNIENV_BASE, JNIENV_SIZE, UC_PROT_ALL)

# JNIEnv* points to a pointer to the function table
# JNIEnv -> JNINativeInterface* -> function pointers
FUNC_TABLE = JNIENV_BASE + 0x1000
mu.mem_write(JNIENV_BASE, struct.pack("<Q", FUNC_TABLE))

# Populate function table entries with hook addresses
jni_hooks = {
    # offset_in_table: (name, handler)
    0x29C: ("FindClass", sim_jni_find_class),
    0x34C: ("GetMethodID", sim_jni_get_method_id),
    0x35C: ("CallObjectMethod", sim_jni_call_object_method),
    0x5A4: ("GetStringUTFChars", sim_jni_get_string_utf_chars),
    0x5AC: ("ReleaseStringUTFChars", sim_jni_release_string),
    0x5B4: ("NewStringUTF", sim_jni_new_string_utf),
    0x2A0: ("GetArrayLength", sim_jni_get_array_length),
    0x560: ("GetByteArrayElements", sim_jni_get_byte_array),
}

# Write stub addresses into function table
STUB_BASE = 0x61000000
mu.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL)
stub_offset = 0

for offset, (name, handler) in jni_hooks.items():
    stub_addr = STUB_BASE + stub_offset
    mu.mem_write(FUNC_TABLE + offset, struct.pack("<Q", stub_addr))
    # Write a RET instruction at stub address
    mu.mem_write(stub_addr, b"\xC0\x03\x5F\xD6")  # ARM64 RET
    import_hooks[stub_addr] = handler
    stub_offset += 4

def sim_jni_get_string_utf_chars(mu):
    jstring = mu.reg_read(UC_ARM64_REG_X2)
    data = mu.mem_read(jstring, 0x100)
    s = bytes(data).split(b'\x00')[0]
    global heap_ptr
    buf = heap_ptr
    heap_ptr += (len(s) + 0x10) & ~0xF
    mu.mem_write(buf, s + b'\x00')
    mu.reg_write(UC_ARM64_REG_X0, buf)
```

### Simulating Syscalls (Linux ARM64)

```python
def hook_intr(mu, intno, user_data):
    if intno == 2:  # ARM64 SVC
        syscall_num = mu.reg_read(UC_ARM64_REG_X8)
        if syscall_num == 64:    # write
            buf = mu.reg_read(UC_ARM64_REG_X1)
            count = mu.reg_read(UC_ARM64_REG_X2)
            mu.reg_write(UC_ARM64_REG_X0, count)
        elif syscall_num == 222:  # mmap
            length = (mu.reg_read(UC_ARM64_REG_X1) + 0xFFF) & ~0xFFF
            global heap_ptr
            addr = heap_ptr
            heap_ptr += length
            mu.mem_map(addr, length, UC_PROT_ALL)
            mu.reg_write(UC_ARM64_REG_X0, addr)
        else:
            mu.reg_write(UC_ARM64_REG_X0, 0)  # stub: return 0

mu.hook_add(UC_HOOK_INTR, hook_intr)
```

---

## Step 4: Debugging Callbacks

**Log verbosity principle:** Keep trace output minimal by default. Only enable instruction-level tracing on small, targeted address ranges. Prefer block-level tracing and summary logging over per-instruction dumps. When the emulated function is long or loops heavily, use counters and print summaries instead of logging every step.

### Trace Execution (Instruction Level — use sparingly)

Only trace a narrow range you're investigating, never the entire execution:

```python
def hook_code_trace(mu, address, size, user_data):
    code = mu.mem_read(address, size)
    print(f"  {address:#010x}: {bytes(code).hex()}")

# Trace ONLY the specific range under investigation
mu.hook_add(UC_HOOK_CODE, hook_code_trace, begin=FUNC_START, end=FUNC_END)
```

### Trace Basic Blocks (preferred over instruction trace)

```python
def hook_block(mu, address, size, user_data):
    print(f">>> Block {address:#x} (size={size})")

mu.hook_add(UC_HOOK_BLOCK, hook_block)
```

### Catch Memory Errors and Auto-Fix

```python
def hook_mem_invalid(mu, access, address, size, value, user_data):
    page = address & ~0xFFF
    try:
        mu.mem_map(page, 0x1000, UC_PROT_ALL)
        return True  # continue emulation
    except:
        return False  # stop

mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
```

### Trace Memory Access (targeted range only)

```python
def hook_mem_access(mu, access, address, size, value, user_data):
    op = "W" if access == UC_MEM_WRITE else "R"
    val = value if access == UC_MEM_WRITE else int.from_bytes(bytes(mu.mem_read(address, size)), 'little')
    print(f"  MEM {op}: [{address:#x}] = {val:#x}")

# Only attach to the data range you care about
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access,
            begin=DATA_START, end=DATA_END)
```

---

## Step 5: Set Up Arguments and Run

```python
# Set function arguments (ARM64 calling convention: X0-X7)
mu.reg_write(UC_ARM64_REG_X0, arg0)
mu.reg_write(UC_ARM64_REG_X1, arg1)

# Write input data to memory if needed
INPUT_BUF = 0x90000000
mu.mem_map(INPUT_BUF, 0x10000, UC_PROT_ALL)
mu.mem_write(INPUT_BUF, input_data)
mu.reg_write(UC_ARM64_REG_X0, INPUT_BUF)

# Set LR to a sentinel address to catch return
END_ADDR = 0xDEAD0000
mu.mem_map(END_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
mu.reg_write(UC_ARM64_REG_LR, END_ADDR)

# Run
FUNC_ADDR = BASE + 0x1234
try:
    mu.emu_start(FUNC_ADDR, END_ADDR, timeout=10 * UC_SECOND_SCALE)
except UcError as e:
    print(f"Error at {mu.reg_read(UC_ARM64_REG_PC):#x}: {e}")

# Read result
result = mu.reg_read(UC_ARM64_REG_X0)
output = bytes(mu.mem_read(OUTPUT_BUF, OUTPUT_SIZE))
```

---

## Iterative Debugging Workflow

When emulation fails, follow this loop:

1. **Run** — start emulation, let it crash
2. **Read callback output** — which address faulted? What type (read/write/fetch)?
3. **Diagnose**:
   - Unmapped memory fetch → missing code page, map it
   - Unmapped memory read/write → missing data section or uninitialized pointer, map or hook
   - Hitting an import stub → identify the function, add a simulation hook
   - Infinite loop → add a code hook to detect and break
4. **Fix** — add the hook / map the memory / adjust registers
5. **Re-run** — repeat until the target function completes

```python
exec_count = {}
def hook_loop_detect(mu, address, size, user_data):
    exec_count[address] = exec_count.get(address, 0) + 1
    if exec_count[address] > 10000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_loop_detect)
```

---

## Architecture Quick Reference

| Arch | Uc Const | Mode | SP Register | LR Register | Arg Registers | Return | Syscall |
|------|----------|------|-------------|-------------|---------------|--------|---------|
| ARM64 | `UC_ARCH_ARM64` | `UC_MODE_LITTLE_ENDIAN` | SP | X30/LR | X0-X7 | X0 | X8 + SVC #0 |
| ARM32 | `UC_ARCH_ARM` | `UC_MODE_THUMB` or `UC_MODE_ARM` | SP | LR | R0-R3 | R0 | R7 + SVC #0 |
| x86-64 | `UC_ARCH_X86` | `UC_MODE_64` | RSP | (stack) | RDI,RSI,RDX,RCX,R8,R9 | RAX | RAX + syscall |
| x86-32 | `UC_ARCH_X86` | `UC_MODE_32` | ESP | (stack) | (stack) | EAX | EAX + int 0x80 |
| MIPS32 | `UC_ARCH_MIPS` | `UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN` | $sp | $ra | $a0-$a3 | $v0 | $v0 + syscall |
