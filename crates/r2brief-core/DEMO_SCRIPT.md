# Suggested walkthrough for the recorded demo

Audience: ELF / binary-RE experts (e.g. ElfMaster). No marketing voice.
Record against `web/wasm-elf-demo/` served locally. Do not use r2brief.com.

## Setup (before record)

```bash
python3 -m http.server 8765 --directory web/wasm-elf-demo
# open http://127.0.0.1:8765/
```

Confirm the status line reads `wasm ready · r2brief-core 0.1.0 · nothing uploaded`.

## Script (~3–4 minutes)

1. **State the constraint.** “Everything runs in this tab. The ELF is not
   uploaded. Findings have to cite offsets I can check with readelf.”

2. **Clean stripped baseline.** Click `triage-x86_64-stripped`.
   - Point at: `stripped: yes`, recovered function count, `eh_frame` count.
   - Open the function table: starts come from `.eh_frame` FDEs and call
     targets. Say the measured numbers out loud:
     x86-64 stripped precision ≈ 0.62, recall ≈ 0.94 (±4-byte tolerance
     against the unstripped twin). Same fixture, aarch64 ≈ 0.62 / 0.97.
   - Note there is **no** infection finding on the clean binary.

3. **PT_NOTE → PT_LOAD.** Click `triage-x86_64-note`.
   - Finding `elf:pt_note_to_load:N` should be top-ranked.
   - Read the evidence line: phdr index, flags `R E`, file offset, VA.
   - Switch to a terminal (or a second pane) and show:
     `readelf -l samples/triage-x86_64-note` — the small executable LOAD at
     the cited VA, isolated from the others.
   - Optional: same click path on `triage-aarch64-note` to show arch parity.

4. **Text-padding.** Click `triage-x86_64-pad`.
   - Finding `elf:text_padding:A:B` — executable LOAD in the page slack
     after the text segment’s filesz.
   - Cite both offsets from the evidence block.

5. **init_array hijack.** Click `triage-x86_64-init`.
   - Finding `elf:dt_init_array:entry0:outside_text`.
   - Evidence shows the bogus VA. Confirm with
     `readelf -d` + hex dump of `.init_array` if time allows.

6. **Evidence bundle.** Click **Download .r2br**.
   - In the terminal: `r2b bundle inspect ./triage-x86_64-note.r2br`
   - Show `schema_version r2b.bundle.v1`, subject sha256, members. Emphasize
     the target bytes are **not** embedded by default.

7. **What you deliberately left out.** One sentence: reverse-text and
   PLT/GOT graph claims are not in this demo because they are not fixture-
   verified yet. No fluff.

## Do not

- Claim 100% function recovery.
- Open any network tab that suggests an upload.
- Deploy or mention a public URL.
