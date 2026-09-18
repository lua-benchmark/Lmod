# Lmod - Lua SAST benchmark snapshot

Frozen snapshot of an upstream project, republished for Lua static-analysis benchmarking.
**This is not a fork for contribution.** File issues and pull requests upstream.

## Provenance

| | |
|---|---|
| Upstream | <https://github.com/TACC/Lmod> |
| Branch | `main` |
| Commit | `217cdbe02ab382522c3c0ec0ec8f2a5390c04bb1` |
| Snapshot taken | 2026-09-18 |
| Upstream stars at snapshot | 609 |
| Deliberately vulnerable (GOAT) | No |

The tree is byte-identical to upstream at that commit, with two exceptions: the `.git` directory
was removed and replaced by a single `initial version` commit, and this `BENCHMARK.md` was added.
No upstream file was modified, so every line number still matches upstream.

## Corpus metadata

**Project type:** Environment module system - CLI (module/ml command, Lua and Tcl modulefiles)

**Lua version:** 5.1-5.4

**Frameworks and libraries:** luaposix (posix.stat/access/setenv/getenv/uname/readlink), LuaFileSystem (lfs.dir/attributes), bundled Optiks CLI parser, i18n, json.lua, capture (io.popen), lmod_system_execute, sandbox_run, tcl2lua.tcl

**Size class:** Medium (~19847 LOC)

## Scan scope

The whole repository is published for provenance, but the benchmark scope is narrower:

    src/

## Taint sources of interest

Command-line arguments (arg[], optionTbl.pargs user module names into MName userName), Environment variables (os.getenv/posix.getenv: MODULEPATH, MODULERCFILE, LMOD_*, LD_LIBRARY_PATH/LD_PRELOAD), Modulefiles loaded as Lua code (io.open + sandbox_run/loadstring in loadModuleFile.lua; Tcl via tcl2lua.tcl), Local file read (lfs.dir in DirTree/Spider, spider cache loadfile in Cache.lua, ReadLmodRC loadfile); sinks capture()/io.popen, lmod_system_execute/os.execute
