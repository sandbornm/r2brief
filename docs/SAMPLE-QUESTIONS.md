# Questions for the next sample

Use these questions to investigate a program, not to label every unfamiliar
program malicious. Start with Q01–Q06 and Q21–Q24. Select at most three behavior
questions relevant to the sample. Do not force every question onto every file.

## Identity and scope

| ID | Question | Evidence to retain |
|---|---|---|
| Q01 | What exact bytes are we examining, and where did they come from? | SHA-256, size, acquisition source/time, report reference; distinguish archive and extracted-child hashes |
| Q02 | What format, architecture, OS/runtime, and entry points can we establish? | Header evidence and tool output; explicitly record unsupported architectures |
| Q03 | Is this executable code, a container, an installer, a library, or a data file? | Classification evidence and relevant child artifacts |
| Q04 | Are packing, compression, encryption, or compiler/runtime conventions limiting analysis? | Identification results, tool warnings, sections, entropy as a clue rather than proof |
| Q05 | Have we already analyzed these exact bytes? | Existing sample/run IDs; identical hashes only, not a similarity inference |
| Q06 | Which three places are worth inspecting first, and why? | Addresses with address type, source tool, evidence references; record a thin result honestly |

## Program behavior

| ID | Question | Evidence to retain |
|---|---|---|
| Q07 | Which external inputs does the program consume? | Relevant callers and data flow for arguments, files, messages, or environment values |
| Q08 | Where does configuration come from, and which code consumes it? | Configuration location/format, parsing code, consumers; preserve original bytes |
| Q09 | Which files or directories does it read, create, change, or delete? | Code references and operation context; distinguish static possibilities from observed operations |
| Q10 | Does it communicate over a network, and what code controls that communication? | Callers, protocol evidence, configuration sources; strings alone are insufficient |
| Q11 | Does it launch other programs or load additional modules? | Relevant caller and arguments where recoverable; unresolved arguments remain unknown |
| Q12 | Does it arrange to run again after restart or login? | Relevant startup-setting changes and supporting code; a registry or path string alone is a lead |
| Q13 | Does it collect sensitive information, and what supports that interpretation? | Accessing code, data categories, subsequent use; avoid copying actual secrets into reports |
| Q14 | What transformations does it apply to data? | Relevant compression, encoding, cryptographic, or parsing routines with supporting observations |
| Q15 | What conditions select different behavior? | Configuration flags, platform checks, error paths, or input-dependent branches |
| Q16 | What externally visible artifacts could a defender check for? | Supported paths, configuration characteristics, or other observables, with scope and limitations |
| Q17 | If a runtime observation is available, does it agree with the static interpretation? | Trace/run identity and conditions; otherwise mark not assessed—this question authorizes no execution |

## Report and comparison questions

| ID | Question | Evidence to retain |
|---|---|---|
| Q18 | Which claims from the source report are supported by our own evidence? | Claim IDs, source quotation/reference, independent supporting evidence, contradictions |
| Q19 | If a comparison sample is supplied, what changed that matters to this question? | Both hashes, matched scope, changed evidence; distinguish rebuild noise from explained behavior changes |
| Q20 | What plausible ordinary functionality explains an apparently suspicious lead? | Alternative interpretation and supporting evidence, including benign controls where appropriate |

## Coverage and handoff

| ID | Question | Evidence to retain |
|---|---|---|
| Q21 | What ran, what was skipped or failed, and what remains outside coverage? | Adapter statuses, versions, rule revisions, limits, timeouts, unsupported features |
| Q22 | Which conclusions are observations, which are interpretations, and which remain unsupported? | Claim-level evidence links and limitations; no probability inferred from ranking points |
| Q23 | What single follow-up inspection would most reduce the remaining uncertainty? | A bounded analyst-selected question and required evidence; no automatic command execution |
| Q24 | Can another analyst reproduce the result and resume without repeating the same work? | Run manifest, tool outputs, trajectory, project reference, question answers, unresolved items |

## Answer format

Each answer uses a stable question ID and these fields:

```json
{
  "question_id": "Q10",
  "status": "unresolved",
  "answer": "A URL string is present; its use has not been established.",
  "evidence_refs": [],
  "source_claim_refs": [],
  "limitations": ["No caller or relevant data flow inspected."],
  "next_question": "Is the string referenced by communication code?"
}
```

Allowed statuses: `supported`, `contradicted`, `unresolved`, `not_assessed`,
`not_applicable`. Each status concerns the written answer or identified claim;
it is not a malware or vulnerability verdict. `supported` requires evidence
references. `contradicted` requires both the contradicted claim and evidence.
Absence of a match is not automatically a contradiction.

Keep source-report claims separate from answers. In a blind evaluation, record
source claims for scoring but withhold the detailed report from the analyst or
agent until its first pass is frozen. Preserve both the first pass and later
corrections. Do not overwrite misses with the corrected answer.

The machine-readable catalog is [sample-questions.json](../corpora/sample-questions.json).
It is a research questionnaire, not a new CLI command or a planner instruction.
These questions do not alter briefing ranking or authorize model/tool execution.

## Small daily exercise

Choose one sample and one behavior question. Save a first-pass brief, inspect
enough evidence to answer or abstain, and write one answer record. Note any
repeated work, wrong address handoff, missing evidence, or misleading summary.
Use that friction to choose the next r2b improvement. Keep benign controls and
unsupported samples in the set, rather than selecting only successful results.
