---
name: custom-carver
description: >-
  Author a custom carver for the unearth MCP `scan` tool so it can recover
  a file type it doesn't support natively. Use when someone wants to carve or
  recover files of an unknown, proprietary, or unsupported format from a disk
  image or device, and you have (or can obtain) at least one intact sample file
  of that type. Guides you to identify the format's magic number, derive an
  EXACT size rule (fixed / size_field / footer), verify the rule reproduces a
  known file's length, and only then run the recovery — so a custom carver never
  emits a wrong-length file.
---

# Authoring a custom carver for `unearth`

`unearth`'s MCP `scan` tool accepts a `custom_carvers` array so you can
recover a file type it doesn't know natively, for that scan only. Each entry is
a **magic number** plus a **declarative rule for how long each match is**. This
skill is the procedure for authoring one correctly.

## The one rule that matters

**Never ship a size rule you have not verified reproduces a known sample's exact
byte length.** The tool guarantees a custom carver can't over-read the source or
overflow — but it cannot know whether *your* size rule is the *right* rule for
the format. A wrong offset or a body-length-vs-total-length mix-up yields a
file that is plausibly sized but corrupt.

Corollary: **if you cannot determine an exact size rule, do not create a
carver.** Tell the user the format can't be sized reliably and stop. Guessing is
worse than not carving — a guessed carver produces corrupt files that look
recovered.

## Prerequisites

You need at least one **intact sample** of the target file type (ideally two or
three of different sizes). Everything below is derived and *verified* against
those samples. No sample → no reliable carver.

## Step 1 — Find the magic number

Look at the first bytes of the sample(s):

```
xxd -l 64 sample.xyz      # or: hexdump -C sample.xyz | head
```

Pick a **stable byte sequence** near the start that every sample shares:

- Prefer **≥ 4 bytes** — shorter magics cause many false matches and slow scans.
- Confirm it appears at the **same offset** in every sample (usually 0). That
  offset is `magic_offset`.
- If the magic is generic (e.g. a container others also use), find a second
  distinguishing sequence for `secondary` (`{ "offset", "bytes" }`).

Express the magic as a hex string: `"89 50 4E 47"` (spaces, `:`, and a `0x`
prefix are all accepted).

## Step 2 — Derive the EXACT size rule

Work out how the true length of a file is encoded, then pick the matching
strategy. **Validate your rule against the sample's real size** (`ls -l`, or
`stat -c%s sample.xyz`) before trusting it.

### `fixed` — every file is the same size
Only if the format is genuinely constant-length. `{ "strategy": "fixed", "size": N }`.

### `size_field` — a length is stored in the header
Find the field: its byte `offset`, its `width` (8/16/32/64 bits), and its
`endian` (`le`/`be`). Then work out what the field *means*:

- If the field is the **total file size**: `mul = 1`, `add = 0`.
- If it counts only the **body** after a fixed header of H bytes: `add = H`.
- If it's in **units** (sectors, words, blocks) of U bytes: `mul = U`.

The computed size is `value * mul + add`. **Verify:** read the field from the
sample and check `value * mul + add == stat -c%s sample`. If it doesn't match
exactly for every sample, your offset/width/endian/mul/add is wrong — fix it or
abandon the carver.

```
# e.g. read a little-endian u32 at offset 4:
python3 - <<'PY'
import struct
d = open("sample.xyz","rb").read()
val = struct.unpack_from("<I", d, 4)[0]
print("field:", val, "  file size:", len(d), "  match:", val == len(d))
PY
```

### `footer` — the file ends at a terminator
If the format has a distinctive end marker (like PNG's `IEND` chunk), use
`{ "strategy": "footer", "marker": "<hex>", "trailing": N }` where the file ends
`N` bytes after the marker sequence. Verify the marker actually appears once, at
the end, in your samples — a marker that can occur inside the data will truncate
files.

## Step 3 — Build the spec

```jsonc
{
  "name": "Widget file",          // human-readable
  "ext": "wdg",                    // output extension: [A-Za-z0-9_-], 1..16 chars
  "magic": "57 44 47 31",          // from Step 1
  "magic_offset": 0,               // default 0
  "secondary": { "offset": 8, "bytes": "AA BB" },   // optional
  "max_size": 1048576,             // REQUIRED hard cap (bytes), <= 1 TiB
  "length": {                      // from Step 2
    "strategy": "size_field",
    "offset": 4, "width": 32, "endian": "le", "mul": 1, "add": 0
  }
}
```

Set `max_size` to a sane ceiling for the format (comfortably above the largest
plausible file, but not absurd — it bounds a runaway carve).

## Step 4 — Verify before the real recovery

Do **not** trust a carver until you've seen it recover a *known* file exactly:

1. Put a known-good sample inside a test image (or point `scan` at a small image
   you know contains one).
2. Call `scan` with your `custom_carvers` entry into a scratch `output_dir`.
3. Compare the recovered file to the original — byte-for-byte
   (`cmp recovered.wdg sample.xyz`) or by SHA-256 (the `scan` result lists each
   file's `sha256`; `read_file` returns bytes for inspection).

If it doesn't match exactly, the size rule is wrong. Return to Step 2. Only run
the real recovery once a sample round-trips perfectly.

## Step 5 — Run the recovery

Call `scan` on the real source with the validated `custom_carvers`. A malformed
spec is reported as an error *before* the job starts; a valid one runs as a
background job (poll `scan_status`, stop with `scan_cancel`).

## Field reference

| Field | Meaning |
| ----- | ------- |
| `name` | Human-readable label. |
| `ext` | Output extension; `[A-Za-z0-9_-]`, 1–16 chars. |
| `magic` | Hex bytes identifying the type (≥4 recommended). |
| `magic_offset` | Where the magic sits in the file (default 0). |
| `secondary` | `{ "offset", "bytes" }` to disambiguate a shared magic. |
| `max_size` | Required cap in bytes (≤ 1 TiB). |
| `length.strategy` | `fixed` \| `size_field` \| `footer`. |
| `length.size` | (`fixed`) exact byte length. |
| `length.offset/width/endian/mul/add` | (`size_field`) `value*mul+add`; width ∈ {8,16,32,64}; endian ∈ {le,be}; mul/add default 1/0. |
| `length.marker/trailing` | (`footer`) ends `trailing` bytes after the marker. |

## When to stop

Abandon the carver (and say so) if any of these hold:

- You have no intact sample to derive and verify a rule from.
- No length rule reproduces the sample's exact size.
- The only usable magic is 1–2 bytes (too weak) with no `secondary` tag.
- The size is only knowable by fully parsing a complex/variable structure — that
  is a built-in carver's job, not a declarative custom one.
