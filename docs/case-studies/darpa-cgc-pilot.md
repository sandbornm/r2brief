# DARPA CGC pilot: the advertised loop, not a source-named helper

Status on 2026-09-02: **loop recorded**. The machine-readable result is
[`darpa-cgc-pilot.json`](darpa-cgc-pilot.json). Raw target bytes stay in
`.r2b-corpus`.

This is a patched/unpatched control, not a claim that r2b discovered the
flaws. The first cut used two named challenges and DWARF names from
source. That is cherry-picking. The recorded product question is whether
`brief` → `handoff.next_argv` → `r2b decompile` reaches the planted
change without reading the README.

## Fixed scope

Source: Trail of Bits `cb-multios` commit
`810d7b24b1f62f56ef49b148fe155b0d0629cad2`.

| Challenge | Pair | Ground-truth change |
|---|---|---|
| `Palindrome` | `Palindrome`, `Palindrome_patched` | A 64-byte stack buffer receives at most 64 bytes after the patch; the unpatched bound is 128. |
| `basic_messaging` | `basic_messaging`, `basic_messaging_patched` | The unread-message counter changes from `unsigned char` to `unsigned int`, preventing wraparound above 255 messages. |

## The first useful cut

Quick briefs of all four i386 ELFs ranked one region:

```text
entry:main
```

Rules review kept that order and labelled it `needs_confirmation` /
`lead`. Rank 3 and rank 5 are empty. The pairs are identical at every
requested cutoff.

That is expected. These services talk through `libcgc`
(`cgc_receive`, `cgc_transmit`, `cgc__terminate`). There is no
`strcpy`/`recv` PLT to follow, so `verify` was not forced. The brief
points at `main`. DWARF still names `cgc_check` and
`cgc_list_unread_messages`.

## Palindrome: 128 versus 64

`dbg.cgc_check` is at `0x08048a00` in both binaries. radare2 and Ghidra
agree on the bound:

```c
char string[64];
cgc_receive_delim(0, string, 0x80, '\n');   /* unpatched */
cgc_receive_delim(0, string, 0x40, '\n');   /* patched   */
```

The stack slot is 64 bytes either way. Only the receive length changes.

## basic_messaging: byte versus dword

`dbg.cgc_list_unread_messages` is at `0x0804a7e0` in both binaries.

```c
uchar count;   /* unpatched */
count = '\0';
count = count + '\x01';

uint count;    /* patched */
count = 0;
count = count + 1;
```

The patched function is 504 bytes; the unpatched function is 506.

## Compared with labeled sources

Both challenges already have author labels and later expert writeups.
The pilot is checked against those, not against a silent binary.

**Palindrome is CADET_00001**, DARPA's sample palindrome detector. The
official README states CWE-121: 64 bytes of stack, reads up to 128.
angr's published example treats it as a teaching crash: unconstrained
EIP after symbolic `receive`, plus the `^` easter egg at a DECREE
address (`0x804833E`) that does not match this Linux port. KLEE on
cb-multios Palindrome reports the same overflow at `service.c:65`
almost immediately. The authors call it an intentionally simple first
C program.

The r2b path matches the label (same buffer, same 128/64 bound, same
`cgc_check` name) and does not reproduce angr/KLEE crash generation.
The Linux-port addresses also differ from the DECREE sample angr
ships.

**basic_messaging is CQE qualifier CROMU_00001** (Cromulence, John
Berry). The MIT LL / Lunge archive lists CWE-190, CWE-131, and
CWE-120, names `list_unread_messages()`, and says the count is 8 bits
and wraps above 255. The crash is supposed to land in `strlen` after
locals are overwritten. The author challenge is that self-messages are
not enough. CQE scores were low: CodeJitsu 1.85 / 4, CSDS 0.9,
ForAllSecure 0.58; Shellphish, Trail of Bits, and several others
scored 0. Trail of Bits still proved a reference POV. Three teams
defended 100% against that POV.

The r2b path matches the labeled function and the 8-bit versus 32-bit
count. It does not recover the CQE POV (send-to-other-user, wrap, crash
in `strlen`) and did not score like a CRS.

### Fidelity ladder

Every label the corpus actually ships, and whether this run reached it:

| Level | Palindrome (`CADET_00001`) | basic_messaging (`CROMU_00001`) | r2b |
|---|---|---|---|
| Challenge ID | sample, not a CQE scorer in the LL index used here | CQE qualifier | identified via cb-multios names |
| CWE | 121 | 190 → 131 → 120 | not emitted; matched after decompile |
| Author prose | 64-byte stack, read 128 | 8-bit unread count, wrap >255, crash in `strlen`; self-send is not enough | matched after decompile |
| Source `#ifdef PATCHED` | `sizeof(string)` vs `128` in `cgc_check` | `unsigned int` vs `unsigned char count` in `cgc_list_unread_messages` | same sites in the Linux port |
| DWARF name | `cgc_check` @ `0x08048a00` | `cgc_list_unread_messages` @ `0x0804a7e0` | yes |
| Instruction | `mov ecx, 0x80` vs `0x40` | `mov byte [count]` vs `mov dword [count]` | yes |
| POLL | 1 XML: `race` / `racecar` | 899 release + 101 testing; protocol only | pass on sampled POLLs |
| Official POV | type 1, masks 0/0/0, one 147-byte write | type 1; create `userone`/`usertwo`; 256+ sends **to the other user**; then login triggers unread dump | patched: no core. unpatched: core not registered under qemu-user |
| angr / KLEE | unconstrained EIP; easter egg `^`; KLEE `service.c:65` | not a published tutorial target | no crashing input generated |
| CQE CRS score | n/a for this sample | max 1.85/4 (CodeJitsu); Mayhem 0.58; Shellphish/ToB 0; ToB still proved a POV | not a CRS score |

The DECREE sample and this cb-multios Linux build share source semantics and
differ in VAs. angr's easter-egg address `0x804833E` is the DECREE binary.

## Runtime

POLLs completed against both variants inside a `linux/amd64` container
with no network, a read-only root, tmpfs scratch, non-root uid 65534,
dropped capabilities, and `no-new-privileges`.

Official type 1 POVs did **not** register a core on the unpatched
services under qemu-user on this host. gdb is absent in the builder
image, so register proof was not collected. Patched POVs correctly did
not core. That is a runtime-tooling miss, not a ranking result. Static
localization still reaches the patched routines.

## Timing

Recorded on Kali Pi 5 (ARM64, 4 CPUs, 8 GiB) with r2b 0.1.0, radare2
6.0.5, and Ghidra 12.1.2. Builder: ubuntu:18.04 `linux/amd64`, clang
6.0.0, cmake 3.10.2, image
`sha256:560a44bea5c9ed4cf3e8eef7ff67341a604e600bebb587a9b9ddc4534245e6aa`.

| Mode | Wall |
|---|---|
| Four quick briefs in parallel (median of three rounds) | ~20 s wall for the set |
| Same four, sequential | 54.4 s sum |

Per-binary parallel medians are 18.7–19.7 s. Sequential singles are
13.2–14.2 s; four-at-once pays a small contention tax and still beats
the serial sum.

## Reproduce

```bash
python3 scripts/corpus_intake.py fetch darpa-cgc-multios
python3 scripts/corpus_intake.py verify darpa-cgc-multios

cgc_root="$PWD/.r2b-corpus/darpa-cgc-multios"
docker build --platform linux/amd64 -t r2b-cgc-pinned "$cgc_root"

# export the four ELFs from /cb-multios/build/challenges/{Palindrome,basic_messaging}/
r2b brief "$binary" --quick --no-save --json
r2b review "$brief_json" --mode rules --json
```

Ubuntu 18.04's CMake 3.10 does not implement `add_compile_definitions`
in `cmake/32.cmake`. The recorded image used `add_definitions(-DX32_COMPILE)`
with the same 32-bit clang flags. Keep the default i386 build.

POLLs and POVs stay in the disposable image: `--network none`, no host
mounts, non-root, read-only root plus tmpfs, capabilities dropped.

## Blind r2b loop (frozen 9-challenge sample)

The advertised harness loop is `r2b brief --quick --json`, then execute
`handoff.next_argv`, then hop at most two extra named callees from the
decompiled C (skip libcgc I/O). Scoring does not consult source at
runtime. Labels below were frozen from author READMEs / `PATCHED`
ifdefs before the run.

Selection rule, frozen before seeing results: keep Palindrome and
basic_messaging, then take every 28th name in `linux-working.txt`
starting at line 8.

| Challenge | Author site | Brief rank | Loop (2 extra hops) |
|---|---|---|---|
| Palindrome (`CADET_00001`) | `cgc_check` CWE-121 | `entry:main` | **site decompiled**: `char string[64]` and `cgc_receive_delim(..., 0x80)` vs `0x40` |
| basic_messaging (`CROMU_00001`) | `cgc_list_unread_messages` CWE-190 | `entry:main` | miss (`main` → `cgc_handle_menu`) |
| ASL6parse (`KPRCA_00020`) | `cgc_print_oid` CWE-125 | `entry:main` | miss (`memset` / `exit`) |
| CNMP (`NRFIN_00001`) | `cgc_insert_joke` format string | `entry:main` | name on path (`load_default_jokes` calls it); site not decompiled |
| FISHYXML (`NRFIN_00030`) | `cgc_parse_xml_cards` | `entry:main` | miss (`play_game` / `send_error`) |
| Matchmaker (`NRFIN_00049`) | `cgc_magic_onmatch` CWE-201 | `entry:main` | miss (`dfa_init` / `memset`) |
| Overflow_Parking (`NRFIN_00052`) | `cgc_malloc` CWE-190 | `entry:main` | miss (`list_init` / `send_resp`) |
| root64_and_parcour | `cgc_page_root64` CWE-121 | `entry:main` | miss (`malloc` / `readuntil`) |
| stream_vm2 (`KPRCA_00035`) | `cgc_process_sys` CWE-129 | `entry:main` | miss (`read_header` / `read_flags`) |

Site decompiled: **1 / 9**. Name visible as a callee: **2 / 9**.
All 18 ELFs ranked only `entry:main`. The pairs still do not split.

Palindrome is the official "first C program" sample. Following
`next_argv` decompiles `main`, which calls `cgc_check`; the second hop
is the planted bound. That is the one case where the r2b loop reached
the patch without a source-supplied address.

basic_messaging, the CQE qualifier from the first writeup, is a miss
under this hop budget. The earlier source-guided decompile of
`cgc_list_unread_messages` is **not** this loop.

### What r2b added over the tools alone

On Palindrome, `r2 -qc 'aaa; pdf @ main'` already prints
`call dbg.cgc_check`. The 12-line briefing snippet does not: it stops
on a broken `c7 invalid` encoding. Executing `handoff.next_argv` is
what produces Ghidra C of `main`, then of `cgc_check`, where the 128
versus 64 bound is visible.

That is glue: rank an address, decompile it, hop named callees. It is
not a CWE finder. On 7 of 9 challenges the same glue stayed in
menu/init helpers.

`r2b decompile` on this host returned empty C until two path bugs were
fixed: `~` in `ghidra.project_dir` was created as a cwd-relative
directory, and analyzeHeadless rejects path elements that start with
`.` (so `~/.local/share/...` is illegal). The default is now
`~/r2b/ghidra-projects`. Without that, the advertised next command
does not run.

## Limits

- r2b did not discover these CWEs. Source already names them.
- Identical quick ranking is the recorded result on all 18 ELFs.
- Following `next_argv` reached the planted site on Palindrome only.
- The earlier source-named decompile of `cgc_list_unread_messages` is
  not a loop result.
- Target bytes are not committed.
