# Fixture evaluation (honest)

Tolerance: ±4 bytes for function-start matching.

## Stripped function recovery

```json
{
  "aarch64": {
    "precision": 0.6207,
    "recall": 0.973,
    "f1": 0.7579
  },
  "x86-64": {
    "precision": 0.6182,
    "recall": 0.9444,
    "f1": 0.7473
  }
}
```

## Infection detection (hit rate)

```json
{
  "triage-x86_64-note": {
    "technique": "pt_note_to_load",
    "hit_rate": 1.0,
    "hits": [
      "elf:pt_note_to_load:7"
    ],
    "misses": []
  },
  "triage-x86_64-pad": {
    "technique": "text_padding",
    "hit_rate": 1.0,
    "hits": [
      "elf:text_padding:3:7"
    ],
    "misses": []
  },
  "triage-x86_64-rwx": {
    "technique": "rwx",
    "hit_rate": 1.0,
    "hits": [
      "elf:rwx_segment:3"
    ],
    "misses": []
  },
  "triage-x86_64-interp": {
    "technique": "interp_tamper",
    "hit_rate": 1.0,
    "hits": [
      "elf:interp_unusual"
    ],
    "misses": []
  },
  "triage-x86_64-init": {
    "technique": "init_array_hijack",
    "hit_rate": 1.0,
    "hits": [
      "elf:dt_init_array:entry0:outside_text"
    ],
    "misses": []
  },
  "triage-aarch64-note": {
    "technique": "pt_note_to_load",
    "hit_rate": 1.0,
    "hits": [
      "elf:pt_note_to_load:5"
    ],
    "misses": []
  },
  "triage-aarch64-pad": {
    "technique": "text_padding",
    "hit_rate": 1.0,
    "hits": [
      "elf:text_padding:2:5"
    ],
    "misses": []
  },
  "triage-aarch64-rwx": {
    "technique": "rwx",
    "hit_rate": 1.0,
    "hits": [
      "elf:rwx_segment:2"
    ],
    "misses": []
  },
  "triage-aarch64-interp": {
    "technique": "interp_tamper",
    "hit_rate": 1.0,
    "hits": [
      "elf:interp_unusual"
    ],
    "misses": []
  },
  "triage-aarch64-init": {
    "technique": "init_array_hijack",
    "hit_rate": 1.0,
    "hits": [
      "elf:dt_init_array:entry0:outside_text"
    ],
    "misses": []
  }
}
```

Clean (non-infected) samples produced **zero** infection-tagged findings.
