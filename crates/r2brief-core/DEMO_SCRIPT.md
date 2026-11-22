# Suggested walkthrough for the recorded demo

Audience: ELF / binary-RE experts. No marketing voice. Every claim on screen
is checkable with `readelf` in a second pane.
Record against `web/wasm-elf-demo/` served locally. Do not use r2brief.com.

## Setup (before record)

```bash
python3 -m http.server 8765 --directory web/wasm-elf-demo
# open http://127.0.0.1:8765/
```

Have a terminal open in `web/wasm-elf-demo/samples/` with binutils available.
Open DevTools → Network and leave it visible: after the page loads, analyzing
a file produces no requests.

## Script (~4 minutes)

1. **Constraint.** "This runs in the tab as wasm in a Web Worker. The file is
   not uploaded. Every finding cites an offset you can check."

2. **Lead with the hard case: `triage-x86_64-note-sstrip`.**
   - Findings: `elf:pt_note_to_load:7` and `elf:no_section_headers`.
   - Evidence line: `PT_LOAD[7] flags=R E file=0x338+0x30 va=0x204000+0x30`.
   - Terminal: `readelf -lW triage-x86_64-note-sstrip`. Point at LOAD[7]: it
     comes after `DYNAMIC`, outside the LOAD run at indices 2–5, and there are
     no section headers at all. The rule uses phdr order alone.
   - Say what it is: the fixture is a structural rewrite of the note phdr.
     It does not carry a working parasite, and the entry point is not redirected.

3. **Control: `triage-x86_64-nopie`.**
   - Single RX LOAD from file offset 0 (`-no-pie -z noseparate-code`). That
     layout tripped a naive "small exec LOAD" heuristic. It produces no
     infection finding here.
   - `readelf -lW triage-x86_64-nopie` shows the one RX LOAD.

4. **Clean stripped baseline: `triage-x86_64-stripped`.**
   - Function table: each start lists its sources (eh_frame, call_target,
     address_taken, ...). PLT stubs are listed separately.
   - State the numbers: 37 of 38 functions at precision 1.000 on this
     fixture. The miss is `register_tm_clones`, which has no FDE and is reached
     only by a tail jump. AArch64 build: 39/39. "One synthetic program, so read
     this as a regression floor, not a benchmark."

5. **init_array hijack via relocation: `triage-x86_64-init`.**
   - Finding `elf:dt_init_array:entry0:outside_text`, value `0x7fff00000000`.
   - Terminal:
     `readelf -x .init_array triage-x86_64-init` shows `0x1340` in slot 0
     (the original `frame_dummy`, inside .text).
     `readelf -rW triage-x86_64-init | head` shows `R_X86_64_RELATIVE` at
     `0x3c80` with addend `7fff00000000`.
   - Point: in a PIE, ld.so writes the addend. A reader that trusts the
     section bytes misses this.

6. **Text padding: `triage-x86_64-pad`.** `elf:text_padding:3:7`: an exec
   LOAD in the page slack after the text segment. Check with `readelf -lW`.

7. **Arch parity: `triage-aarch64-note`.** `elf:pt_note_to_load:5`.

8. **Evidence bundle.** Click **Download .r2br**, then:
   `r2b bundle inspect ./triage-x86_64-note-sstrip.r2br`
   Shows `r2b.bundle.v1`, the subject sha256 and the members. The target bytes
   are not embedded.

9. **Left out, one sentence.** "Reverse-text, PLT/GOT hijack, DT_NEEDED
   injection and RELR aren't shown because no fixture verifies them yet."

## Do not

- Claim 100% function recovery or generality beyond the fixture corpus.
- Claim the infected fixtures are working malware.
- Deploy or mention a public URL.
