# SignScanner

Statically locate the QQ `wrapper.node` **sign function** — the one called by
[`SignerServer`](../SignerServer) and [`SignServer`](../SignServer) as
`f(cmd, src, len, seq, out)` — using **stable name/RTTI anchors**, not byte
signatures or a feature-code database. Pure Rust, one small binary, no
disassembler crates beyond `iced-x86`.

## How it works

The locator walks invariants of the C++ object model. Two ABIs appear across
the platforms QQ ships:

**Itanium** (Linux, macOS) — one `typeinfo` object per class:

```
RTTI name "N2nt8internal23MSFSecuritySignCallbackE"
  -> typeinfo        (the site storing &name lives at typeinfo + 8)
  -> vtable          (the site storing &typeinfo lives at vtable - 8)
  -> virtual fns     (vtable slots are RELATIVE relocations into .text)
  -> MSFSign         (the vtable slot that calls the sign core)
  -> sign function   (the callee that writes the caller's result buffer)
```

**MSVC** (Windows) — the type descriptor is not pointed at by a relocation, so
the chain starts differently:

```
type descriptor ".?AVMSFSecuritySignCallback@internal@nt@@"
  -> _RTTICompleteObjectLocator (its pTypeDescriptor RVA == td_rva)
  -> vtable          (the site storing &COL is vtable - 8)
  -> ... same as above
```

The last step is semantic, not a byte pattern: `MSFSign` calls the sign core,
which writes the caller's result lengths at `+0xFF` (SecToken), `+0x1FF`
(SecExtra) and `+0x2FF` (SecSign). The core is the direct callee that stores to
all three.

### Containers and relocation models

Static pointers in a PIE/DSO are *relocations*, so the image itself says what
every pointer resolves to. Each container is parsed by hand:

| container | relocation source |
|---|---|
| ELF | `SHT_RELA` entries of type `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE` |
| PE | base relocation `.reloc` blocks (`DIR64`, `HIGHLOW`) |
| Mach-O | `LC_DYLD_INFO[_ONLY]` rebase opcode stream |

PE and Mach-O also carry **function-boundary metadata** (PE `.pdata`,
Mach-O `LC_FUNCTION_STARTS`), which bounds a callee exactly. This matters: the
Windows x64 sign core is ~82 KB, with its result stores ~0xD386 bytes in, far
beyond any fixed scan window.

### Instruction decoders

| arch | decoder |
|---|---|
| x86-64 | `iced-x86` (direct `call rel32`, memory stores) |
| aarch64 | hand-rolled: `BL <imm26>`, and `STRB`/`STURB` immediate stores |

## Usage

```sh
cargo run --release -- /opt/QQ/resources/app/wrapper.node
cargo run --release -- "C:/QQ/resources/app/wrapper.node"
cargo run --release -- /Applications/QQ.app/Contents/Resources/app/wrapper.node
```

Example (Linux x86-64):

```
SignScanner — QQ wrapper.node sign-function locator

file        /opt/QQ/resources/app/wrapper.node
format      ELF64
slices      1

[anchor] RTTI name        N2nt8internal23MSFSecuritySignCallbackE
[anchor] typeinfo         @ RVA 0x8e1c838
[anchor] vtable           @ RVA 0x8e1c810  (5 code slots)
[chain ] MSFSign callback  RVA 0x34ee370  (217 direct calls)
[chain ] sign core         RVA 0x67f28d4  (writes out +0xFF/+0x1FF/+0x2FF)
        file offset       0x67f18d4

=> sign function RVA: 0x67f28d4
```

A universal (fat) macOS binary is reported per architecture slice; PE reports
RVAs relative to the image base.

Flags:

| flag | meaning |
|---|---|
| `--json` | machine-readable output |
| `--typeinfo NAME` | use a different RTTI anchor |
| `--quiet` | reserved |

## Platforms

| container | arch | status | verified core (3.2.34 / 9.9.36 / 7.0.2) |
|---|---|---|---|
| ELF (Linux) | x86-64 | **implemented** | `0x67f28d4` |
| ELF (Linux) | aarch64 | **implemented** | `0x43d07dc` |
| PE (Windows) | x86-64 | **implemented** | `0xbeea20` |
| PE (Windows) | aarch64 | **implemented** | `0xbcdae8` |
| Mach-O (macOS) | x86-64 | **implemented** | `0x304e2d7` |
| Mach-O (macOS) | aarch64 | **implemented** | `0x2b30e10` |

Every core above was cross-checked with `llvm-objdump`: each one stores the
three result lengths at `+0xFF`/`+0x1FF`/`+0x2FF`.

## Layout

```
src/reloc.rs    (site, target) relocation table shared by all containers
src/elf.rs      ELF64 sections/phdrs + RELATIVE relocations
src/pe.rs       PE32+ sections + base relocations + .pdata function starts
src/macho.rs    Mach-O fat/thin, rebase opcodes, LC_FUNCTION_STARTS, sections
src/decode.rs   BufferHits: the result-buffer contract every decoder fills
src/x86.rs      iced-x86: direct calls, result-buffer stores, raw prefilter
src/aarch64.rs  hand-rolled BL / STRB decoder
src/image.rs    format detection + architecture slices + container-agnostic View
src/locate.rs   Itanium/MSVC anchor chains and the ABI/arch dispatch
src/main.rs     CLI + report
tests/real_binary.rs   integration checks against real builds (skipped if absent)
```
