# Changelog

All notable changes to hookscan are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-26

The first release.

### Added

- **A relocation-aware code diff.** Each module's file is laid out as the
  loader would lay it out, its base relocations are applied for the address
  it actually loaded at, and only then are executable sections compared with
  memory. A relocated pointer is not a patch.
- **Patch regions decoded with Zydis.** Changed bytes are grouped into
  regions, each region is decoded from the instruction it starts in, and a
  `jmp`, `call`, `jmp [mem]`, `push`/`ret` or `mov reg, imm` plus `jmp reg`
  is followed to its target and named, as in `jmp -> othermodule.dll+0x1A20`.
- **An IAT check that resolves imports the way the loader does.** Forwarded
  exports are followed, API set names are resolved through the system's API
  set schema with per-importer exceptions, and delay-load slots that have not
  been called yet are accepted. Ordinary Windows forwarding is not reported.
- **An EAT check.** Export table entries that differ from the file are
  reported, and those that point outside their module are marked.
- **Module checks.** A listed module with no file behind it, a module whose
  headers do not match its file, an executable image mapping that the
  loader's module list does not name, and a PE header in private executable
  memory.
- **Known benign differences handled.** Import slots, CFG and XFG dispatch
  pointers, the security cookie, the TLS index and delay-load handles are left
  out of the code diff. AnyCPU .NET assemblies whose headers the loader
  rewrites, and the WOW64 layer's own 64-bit images in a 32-bit process, are
  not reported. Changes that are real but made by Windows or the runtime (the
  shim engine, the .NET runtime patching itself) are reported with a note
  that says so.
- **A command-line tool, `hookscan.exe`.** `--pid`, `--name` or `--self`;
  `--json`, `--module`, `--notes`, `--include-writable` and `--gap`. Exit
  status 0 with no findings, 1 with findings, 2 on error. The target is
  opened with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` only.
- x64 and x86 builds. The C runtime is linked statically.
