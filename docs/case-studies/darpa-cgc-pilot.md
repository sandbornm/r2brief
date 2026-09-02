# DARPA CGC pilot handoff

Status on 2026-09-01: intake is pinned and tested. No CGC service binary has
been built or analyzed by r2b. Keep the public status **pending** until the
completion checks below pass.

## Fixed scope

Source: Trail of Bits `cb-multios` commit
`810d7b24b1f62f56ef49b148fe155b0d0629cad2`.

| Challenge | Pair | Ground-truth change |
|---|---|---|
| `Palindrome` | `Palindrome`, `Palindrome_patched` | A 64-byte stack buffer receives at most 64 bytes after the patch; the unpatched bound is 128. |
| `basic_messaging` | `basic_messaging`, `basic_messaging_patched` | The unread-message counter changes from `unsigned char` to `unsigned int`, preventing wraparound above 255 messages. |

The sparse checkout contains these two challenges, their POLLs and POVs, the
CGC compatibility library, build files, and platform exclusion lists. Do not
expand the pilot to the full CGC collection before this four-binary comparison
has a recorded result.

## Host split

The checked `kali` SSH host is a Raspberry Pi 5 running ARM64 Linux with 4 CPUs,
8 GiB RAM, and 166 GiB free. Docker 28.5.2, bubblewrap, radare2 6.0.5, and
`linux/amd64` binfmt emulation are ready. Ghidra and GNU `time` are absent.

Use Kali for the pinned checkout, `linux/amd64` container build, four parallel
quick briefs, and isolated POLL/POV runs. Keep native execution inside a
no-egress container. Use a non-Pi lab host for Ghidra or angr depth; do not run
`uv sync --extra analyzers` on the Pi.

## Resume on Kali

```bash
git clone https://github.com/sandbornm/r2brief.git
cd r2brief
R2B_FLAVOR=core ./scripts/install.sh

python3 scripts/corpus_intake.py fetch darpa-cgc-multios
python3 scripts/corpus_intake.py verify darpa-cgc-multios
```

Build the upstream source as `linux/amd64`, even though Kali is ARM64. The
upstream CMake project emits patched and unpatched targets from the same source
and flags. Its default build is 32-bit x86; retain that default for the first
pilot. Record the Docker image ID and compiler versions with the result.

```bash
cgc_root="$PWD/.r2b-corpus/darpa-cgc-multios"
pilot_root="$PWD/.r2b-corpus/work/darpa-cgc-pilot"
mkdir -p "$pilot_root/bin" "$pilot_root/results" "$pilot_root/timing"

docker build --platform linux/amd64 -t r2b-cgc-pinned "$cgc_root"
```

Export these four files from the image without running them:

```text
/cb-multios/build/challenges/Palindrome/Palindrome
/cb-multios/build/challenges/Palindrome/Palindrome_patched
/cb-multios/build/challenges/basic_messaging/basic_messaging
/cb-multios/build/challenges/basic_messaging/basic_messaging_patched
```

Before analysis, save `sha256sum`, `file`, `r2b --version`, `r2b env --json`,
the Docker image ID, and compiler versions under `pilot_root`. Raw source,
binaries, core dumps, and POLL/POV transcripts stay in `.r2b-corpus`; they are
not release artifacts.

## Timed triage

Run one unmeasured warm-up. Then run three measured rounds. Start the four
quick briefs together, with one process per binary:

```bash
r2b brief "$binary" --quick --no-save --json
r2b review "$brief_json" --mode rules --json
```

GNU `time` is not installed on the checked Kali host. Install the `time`
package before measured runs, or have the harness record monotonic start/end
times. Save wall time, maximum resident memory, output bytes, input SHA-256,
and the per-tool durations already present in r2b output. Report the median of
the three rounds and compare it with one sequential round.

Do not start four deep passes together. Each deep pass already runs enabled
adapters concurrently. Run at most two deep subjects together on the non-Pi
host and keep each patched/unpatched pair on the same tool versions.

## Runtime ground truth

POLLs should complete against both variants. A POV should distinguish the
unpatched service from its patched counterpart. Run these only in a disposable
`linux/amd64` container with:

- `--network none`, no host mounts, and a non-root user;
- a read-only root filesystem plus a bounded writable scratch volume;
- all capabilities dropped, `no-new-privileges`, PID/CPU/memory/time limits;
- core dumps confined to scratch and deleted after the verdict is recorded.

This is a separate runtime check. `brief`, `review`, `verify`, and `decompile`
remain static. Do not enable Frida or GEF for this pilot.

## Completion checks

Change the status from **pending** to **pilot recorded** only when:

- the source commit and all four binary hashes are saved;
- quick briefing and rules-review JSON exists for all four binaries;
- the patched/unpatched region order and evidence-screen disposition are
  compared at ranks 1, 3, and 5;
- targeted decompilation records whether it reaches `cgc_check` in
  `Palindrome` and `cgc_list_unread_messages` in `basic_messaging`;
- POLL and POV outcomes are recorded under the isolation rules above;
- serial and parallel timing, peak memory, tool versions, and replay commands
  are included;
- a machine-readable result and a short case-study reading are committed, with
  no raw target bytes.

Do not force `verify` into the result when there is no relevant external import
sink. The useful question is whether the brief and one-function decompile lead
to the patched routine. An identical quick ranking across a pair is a valid
negative result if the deeper step localizes the source-level change.
