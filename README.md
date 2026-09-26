<p align="center">
  <img src="docs/logo.svg" width="96" alt="hookscan logo">
</p>

# hookscan

Find the code, import and export entries in a running process that no longer match the files on disk.

[![CI](https://github.com/HeathHowren/hookscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/hookscan/actions/workflows/ci.yml)

hookscan is a small, read-only integrity scanner for Windows processes. For
each loaded module it lays out the file on disk the way the loader does,
applies the module's relocations for the address it really loaded at, and
compares the executable sections with memory. What differs is grouped into
patch regions and decoded, so a patched `jmp` reads as the jump it is and
names the module it lands in. It also checks every import and export table
slot, and looks for modules with no file behind them. It opens the target
with read access only and never writes to it.

hookscan is written by Heath Howren
([Cyborg Elf](https://www.youtube.com/c/cyborgelf)) of
[Game Reversal Club](https://gamereversal.club). It is the checking side of
the inline and IAT hooking chapter of
[*The Game Hacker's Handbook*](https://gamereversal.club/books/game-hackers-handbook/),
and it disassembles with the same pinned Zydis as
[Pointer Lab](https://github.com/HeathHowren/Pointer-Lab) and
[Signature Lab](https://github.com/HeathHowren/Signature-Lab).

```
hookscan 1.0.0: pid 39996 (hookscan_fixture.exe, x64), 5 of 5 modules scanned

[inline] hookscan_fixture.exe+0x35B0 in .text, 5 bytes
  original  8D 04 49 89 44
  current   E9 CB FF FF FF
  code      jmp 0x00007FF6C1713580
  target    hookscan_fixture.exe!FixtureDetour

[iat] hookscan_fixture.exe imports KERNEL32.dll!GetTickCount
  slot      hookscan_fixture.exe+0x1E020
  expected  KERNEL32.DLL!GetTickCount
  target    hookscan_fixture.exe!FixtureFakeTickCount

2 findings
```

*Real output from `hookscan --name hookscan_fixture.exe`. The target is the
test fixture in `tests/fixture`, run in its `hooked` mode: it writes a 5-byte
`jmp` over one of its own functions and points its own `GetTickCount` import
slot at a function of its own. hookscan reports those two changes and nothing
else.*

## What it does

- **Compares code after relocation.** The file is mapped section by section
  and its base relocations are applied for the real load address before any
  byte is compared. Most naive scanners report every relocated pointer as a
  patch; this one does not.
- **Decodes each patch.** Changed bytes within 8 bytes of each other form one
  region. The region is decoded with Zydis from the start of the instruction
  it falls in (on x64, found by walking the function from its `.pdata` entry),
  and the report shows original and current bytes and the new instructions.
  A `jmp` or `call`, a `jmp [rip+disp]` or `jmp [abs]` (including the 14-byte
  absolute form), `push imm; ret`, and `mov reg, imm` followed by `jmp reg`,
  `call reg` or `push reg; ret` are all followed to their target, and the
  target is named: `module!export` when it is an export, `module+0xRVA` when
  it is inside a module, or the kind of memory it is in otherwise.
- **Checks every import slot against the export it resolves to.** Forwarded
  exports (`kernel32` to `ntdll` and so on) are followed, API set names
  (`api-ms-win-*`, `ext-ms-win-*`) are resolved through the system's API set
  schema including per-importer exceptions, and a delay-load slot that has not
  been called yet (still pointing at its own stub) is accepted. Ordinary
  Windows forwarding is not reported.
- **Checks every export slot.** An export table entry that differs from the
  file is reported, and one that points outside its module is marked.
- **Checks the modules themselves.** A listed module with no file mapping
  behind it, a module whose file can no longer be opened, a module whose
  in-memory headers do not match its file, an executable image mapping the
  loader's module list does not include, and a PE header at the start of
  private executable memory.
- **Scans itself.** `--self` scans hookscan's own process. The library call
  behind it, `hookscan::scanCurrentProcess`, lets a program check its own
  integrity.
- **Prints a report or JSON.** The default is the report above. `--json`
  prints one object for scripts, with every address as a hex string. The exit
  status is 0 with no findings, 1 with findings and 2 on an error.
- **Reads only.** The target is opened with `PROCESS_QUERY_INFORMATION |
  PROCESS_VM_READ`. hookscan asks for no write, operation or thread access, so
  it cannot change the process it scans.

## What is and is not reported

The point of the tool is to report real changes and stay quiet otherwise.
These differences are expected and handled:

- **Relocations.** Applied before the diff, for every relocation type that
  occurs on x86 and x64.
- **Data the loader or C runtime writes inside a code section.** Some linkers
  put the IAT, the delay-load IAT or the export table in an executable
  section. Those slots, the delay-load module handles, the CFG and XFG
  dispatch pointers, the security cookie and the TLS index are left out of the
  code diff. The import and export slots are checked by their own checks
  instead.
- **Forwarded exports and API sets.** Followed and resolved the way the loader
  does, so `kernel32!HeapAlloc` holding `ntdll!RtlAllocateHeap` is not a
  finding.
- **Delay-load imports.** A slot that still points at its own stub has not
  been called yet. A slot whose DLL cannot be resolved on this system (a
  delay-load that failed over to the loader's stub) and that points into a
  loaded module cannot be judged, so it becomes a note rather than a finding.
- **AnyCPU .NET assemblies.** The loader rewrites their headers when it maps
  them into a 64-bit process. They are noted and not compared.
- **The WOW64 layer.** In a 32-bit process, the 64-bit `ntdll.dll` and
  `wow64*.dll` images from System32 are mapped too but only the 64-bit loader
  lists them. Those exact images are not reported as unlisted.
- **Writable code sections.** A section that is both executable and writable
  is meant to change (packers, self-modifying code). It is noted and not
  compared unless you pass `--include-writable`.

These are real changes that Windows or a runtime makes on purpose. They are
reported, with a note that says what they are:

- **The .NET Framework runtime (`clr.dll`) patching its own code** at start-up
  (TLS offsets, write barriers). Such a patch has no jump out of the module.
- **The application compatibility shim engine** (`apphelp.dll` and the
  `Ac*.dll` shims) redirecting imports of a program Windows has compatibility
  fixes for.
- **An import slot that holds an export of the same name from another
  module** than the one the import resolves to.
- **A finding in a module with a dynamic relocation table.** Windows can
  rewrite code in such a module at load time, and the note says so. hookscan
  was developed and tested on Windows 10; newer versions may use these tables
  in more places.

Programs that change their own process on purpose are reported, because the
change is real. Chromium-based browsers and apps and Firefox, for example,
redirect functions in their own `ntdll.dll` for their sandboxes, and hookscan
lists those redirections with the module they jump into.

hookscan does not see:

- **Hooks that change no module byte.** Hardware breakpoints, guard-page
  hooks, vtable or function-pointer swaps in data, instrumentation callbacks
  and kernel hooks leave the modules' code and tables alone.
- **Code that is not in a module**, such as JIT output, except for the PE
  header check on private executable memory. A manual mapper that erases its
  header is not found.
- **Changes made after the scan read the bytes.** The scan is one snapshot.
- **A patch in an x64 function with no unwind data** (a leaf function) is
  decoded from its first changed byte, since there is no `.pdata` entry to
  walk from. The bytes and the target are still right when the first changed
  byte starts an instruction, which it usually does.

Pass `--notes` to see what was skipped in a scan and why.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/hookscan/releases). It contains:

```
hookscan.exe
LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES.md
```

There is an x64 zip and an x86 zip. The x64 `hookscan.exe` scans 64-bit
processes and the x86 one scans 32-bit processes; each says so if you point it
at the other kind. The C runtime is linked statically, so no Visual C++
redistributable is needed.

The binary is unsigned. Antivirus software may flag a tool that reads another
process's memory. Build from source if you would rather not take a binary on
trust.

## Quick start

```
hookscan --name game.exe
hookscan --pid 1234 --json > findings.json
hookscan --pid 1234 --module kernel32.dll --module ntdll.dll
hookscan --self
```

Run hookscan as the same user as the target. A process owned by another user,
or one running elevated, needs hookscan to run elevated too.

To use it from your own code, link `hookscan_core` and call:

```cpp
#include "core/Scanner.h"

std::string error;
auto result = hookscan::scanCurrentProcess({}, &error); // or scanProcess(pid, {}, &error)
if (result && !result->findings.empty()) {
    // result->findings says what changed, where, and where it now points
}
```

## Usage

```
hookscan (--pid <pid> | --name <process.exe> | --self) [options]
```

| Option | What it does |
|---|---|
| `--pid <pid>` | The process to scan. |
| `--name <exe>` | The process with this image name. If several match, hookscan lists their PIDs and stops. |
| `--self` | Scan hookscan's own process. |
| `--json` | Print one JSON object instead of the report. |
| `--module <name>` | Scan only this module. Repeat it for more. The process-wide checks for unlisted images are skipped. |
| `--notes` | List what could not be checked, and why. |
| `--include-writable` | Also compare executable sections that are writable. |
| `--gap <n>` | Equal bytes allowed inside one patch region, 0 to 64. The default is 8. |
| `--version`, `--help` | Print the version or the usage text. |

Finding kinds, as they appear in the report and in `"kind"` in the JSON:

| Kind | Meaning |
|---|---|
| `inline` | Code in an executable section differs from the relocated file. |
| `iat` | An import slot does not hold the address its export resolves to. |
| `eat` | An export slot differs from the file. |
| `unbacked-module` | A listed module with no file behind it, or whose file is gone. |
| `image-mismatch` | A listed module whose headers do not match its file. |
| `unlisted-image` | An executable image mapping the loader's module list does not name. |
| `private-image` | A PE header at the start of private or mapped executable memory. |

## How it is tested

The tests build a fixture, `hookscan_fixture.exe`, that changes its own
process in one known way per mode, by hand with `VirtualProtect` and `memcpy`,
and then waits. The tests start it, scan it as the same user, and assert that
exactly the planted change is reported, with the right address and target:
a 5-byte `jmp` plus an IAT redirection, an export pointed at a stub outside
the image, an `int3`, an extra image mapping of its own exe, and a copy of its
own headers in private memory. The unmodified fixture, the test process itself
and `hookscan --self` must all scan clean. Unit tests cover relocation types
and malformed relocation tables, the region grouping on synthetic buffers, PE
parsing on synthetic images, the API set resolver on a synthetic schema and
on the system's, and the report and JSON writers. CI runs all of them for
x64 and x86, Debug and Release.

## Build

Requirements: Visual Studio 2022 with the C++ workload and CMake 3.28 or newer.
The CMake that ships with Visual Studio is recent enough.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For the 32-bit build, configure a second tree with `-A Win32`. The first
configure fetches Zydis, pinned by commit, and Catch2 for the tests, pinned by
tag; nothing else is downloaded. To produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

## Intended use

hookscan is for checking processes **you own or are authorized to analyze**:
your own programs, to confirm a hook you wrote landed where you meant it to,
or to see what an overlay, a plugin or other software changed in a program
you run. It only reads, but reading the memory of online or competitive games
will very likely trip anti-cheat software and get the account banned. That
decision is yours; this tool does not make it for you.

## License

MIT; see [LICENSE](LICENSE). `hookscan.exe` statically links Zydis and Zycore
(both MIT). The tests use Catch2 (Boost Software License 1.0), which is not
part of the tool. Details are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
