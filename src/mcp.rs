//! A minimal Model Context Protocol (MCP) server over stdio, so an AI agent can
//! drive recovery and reason over the results.
//!
//! MCP is JSON-RPC 2.0 with newline-delimited messages on stdin/stdout. This
//! server implements the handshake (`initialize`), `tools/list`, `tools/call`,
//! and `ping`, exposing the tool's capabilities as callable tools:
//!
//! * `list_types`   — the file types carving can recover
//! * `list_volumes` — detect partitions/filesystems in a source (+ deleted counts)
//! * `scan`         — start background signature carving (returns a job id)
//! * `scan_status`  — poll a scan job's progress and result
//! * `scan_cancel`  — request cancellation of a scan/image job
//! * `image`        — background, bad-sector-tolerant disk imaging (returns a job id)
//! * `undelete`     — filesystem-aware recovery into an output directory
//! * `verify`       — re-hash recovered files against a `--report` manifest
//! * `read_file`    — read a recovered file's bytes (base64) for inspection
//! * `triage`       — summarize a directory of recovered files
//! * `identify`     — identify a file's type from its contents
//!
//! It is built on the crate's own [`crate::json`] so it pulls in no new
//! dependencies and runs synchronously (no async runtime).

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::Result;

use crate::carver::ProgressSink;
use crate::json::{self, obj, s, Json};
use crate::{carver, hash, manifest, recover, signatures, source::Source};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "filerecovery";
/// Cap on per-file records embedded in a tool result, to bound response size.
const MAX_FILES_IN_RESULT: usize = 1000;

fn n(v: u64) -> Json {
    Json::Num(v as f64)
}

/// Serve MCP over the given reader/writer until end of input.
pub fn serve<R: BufRead, W: Write>(reader: R, mut writer: W) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match json::parse(&line) {
            Ok(req) => handle_request(&req),
            Err(e) => Some(error_response(
                Json::Null,
                -32700,
                &format!("parse error: {e}"),
            )),
        };
        if let Some(resp) = response {
            writer.write_all(resp.to_string().as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Handle one parsed JSON-RPC message, returning the response (or `None` for a
/// notification, which gets no reply).
pub fn handle_request(req: &Json) -> Option<Json> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params");

    match method {
        "initialize" => {
            let version = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION)
                .to_string();
            Some(ok_response(
                id?,
                obj(vec![
                    ("protocolVersion", s(version)),
                    ("capabilities", obj(vec![("tools", obj(vec![]))])),
                    (
                        "serverInfo",
                        obj(vec![
                            ("name", s(SERVER_NAME)),
                            ("version", s(env!("CARGO_PKG_VERSION"))),
                        ]),
                    ),
                ]),
            ))
        }
        "ping" => Some(ok_response(id?, obj(vec![]))),
        "tools/list" => Some(ok_response(id?, obj(vec![("tools", tool_definitions())]))),
        "tools/call" => {
            let id = id?;
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = params.and_then(|p| p.get("arguments"));
            Some(match call_tool(name, args) {
                Ok(value) => ok_response(id, tool_content(&value.to_string(), false)),
                Err(msg) => ok_response(id, tool_content(&msg, true)),
            })
        }
        // Notifications (no id) are silently accepted.
        _ if id.is_none() => None,
        _ => Some(error_response(
            id.unwrap_or(Json::Null),
            -32601,
            &format!("method not found: {method}"),
        )),
    }
}

fn ok_response(id: Json, result: Json) -> Json {
    obj(vec![("jsonrpc", s("2.0")), ("id", id), ("result", result)])
}

fn error_response(id: Json, code: i64, message: &str) -> Json {
    obj(vec![
        ("jsonrpc", s("2.0")),
        ("id", id),
        (
            "error",
            obj(vec![
                ("code", Json::Num(code as f64)),
                ("message", s(message)),
            ]),
        ),
    ])
}

/// Wrap a result string as an MCP tool-call result (a single text content block).
fn tool_content(text: &str, is_error: bool) -> Json {
    obj(vec![
        (
            "content",
            Json::Arr(vec![obj(vec![("type", s("text")), ("text", s(text))])]),
        ),
        ("isError", Json::Bool(is_error)),
    ])
}

fn tool_definitions() -> Json {
    let str_prop = |desc: &str| obj(vec![("type", s("string")), ("description", s(desc))]);
    let bool_prop = |desc: &str| obj(vec![("type", s("boolean")), ("description", s(desc))]);
    let int_prop = |desc: &str| obj(vec![("type", s("integer")), ("description", s(desc))]);
    let schema = |props: Vec<(&str, Json)>, required: Vec<&str>| {
        obj(vec![
            ("type", s("object")),
            ("properties", obj(props)),
            ("required", Json::Arr(required.into_iter().map(s).collect())),
        ])
    };

    let mut tools = Vec::new();
    let mut tool = |name: &str, desc: &str, schema: Json| {
        tools.push(obj(vec![
            ("name", s(name)),
            ("description", s(desc)),
            ("inputSchema", schema),
        ]));
    };

    tool(
        "list_types",
        "List the file types signature carving can recover.",
        schema(vec![], vec![]),
    );
    tool(
        "list_volumes",
        "Detect the partitions/filesystems in a source (disk image or device). \
         Set deleted=true to also count recoverable deleted files per volume.",
        schema(
            vec![
                (
                    "source",
                    str_prop("Path to a disk image or device (read-only)."),
                ),
                (
                    "deleted",
                    bool_prop("Also count recoverable deleted files."),
                ),
            ],
            vec!["source"],
        ),
    );
    tool(
        "scan",
        "Start carving files from a source by signature into output_dir \
         (filesystem-agnostic). Runs as a background job (carving a large drive \
         is slow): returns a job_id — poll scan_status, and use scan_cancel to \
         stop it.",
        schema(
            vec![
                (
                    "source",
                    str_prop("Path to a disk image or device (read-only)."),
                ),
                (
                    "output_dir",
                    str_prop("Directory to write recovered files into."),
                ),
                (
                    "types",
                    obj(vec![
                        ("type", s("array")),
                        ("items", obj(vec![("type", s("string"))])),
                        (
                            "description",
                            s("File-type extensions to recover (default: all)."),
                        ),
                    ]),
                ),
                (
                    "min_size",
                    int_prop("Ignore carved files smaller than this many bytes."),
                ),
                (
                    "include_files",
                    bool_prop("Include the per-file list with SHA-256 (default true)."),
                ),
                (
                    "validate",
                    bool_prop("Structural validation (default true)."),
                ),
                (
                    "dedup",
                    bool_prop("Skip byte-identical duplicates (default false)."),
                ),
            ],
            vec!["source", "output_dir"],
        ),
    );
    tool(
        "image",
        "Copy a source (disk image or device) to an image file, read-only and \
         bad-sector tolerant. Best practice for a failing drive: image it once, \
         then scan/undelete the image. Runs as a background job: returns a \
         job_id — poll scan_status, and use scan_cancel to stop it.",
        schema(
            vec![
                (
                    "source",
                    str_prop("Path to a disk image or device (read-only)."),
                ),
                ("output", str_prop("Image file to create (overwritten).")),
                ("start", int_prop("Start byte offset (default 0).")),
                (
                    "end",
                    int_prop("Exclusive end byte offset (default: device end)."),
                ),
                (
                    "sparse",
                    bool_prop("Skip zero runs, leaving holes (default true)."),
                ),
                (
                    "sector_size",
                    int_prop("Bad-sector retry granularity in bytes (default 512)."),
                ),
                (
                    "map",
                    str_prop("Checkpoint/map file for resume (default: <output>.map)."),
                ),
                (
                    "resume",
                    bool_prop("Resume from the map file if present (default false)."),
                ),
                (
                    "retries",
                    int_prop("Extra passes to re-read unreadable regions (default 0)."),
                ),
            ],
            vec!["source", "output"],
        ),
    );
    tool(
        "undelete",
        "Recover deleted files from a FAT/exFAT/NTFS/ext volume into output_dir, \
         keeping original names where possible.",
        schema(
            vec![
                (
                    "source",
                    str_prop("Path to a disk image or device (read-only)."),
                ),
                (
                    "output_dir",
                    str_prop("Directory to write recovered files into."),
                ),
                (
                    "offset",
                    int_prop("Byte offset of the volume (default: auto-detect)."),
                ),
                (
                    "min_size",
                    int_prop("Ignore deleted files smaller than this many bytes."),
                ),
                (
                    "dry_run",
                    bool_prop("Report what would be recovered without writing."),
                ),
                (
                    "include_files",
                    bool_prop("Include the per-file list with SHA-256 (default true)."),
                ),
            ],
            vec!["source", "output_dir"],
        ),
    );
    tool(
        "verify",
        "Re-hash recovered files against a scan/undelete --report manifest.",
        schema(
            vec![
                (
                    "manifest",
                    str_prop("Path to a .json or .csv report manifest."),
                ),
                ("base", str_prop("Directory the recovered files live in.")),
            ],
            vec!["manifest", "base"],
        ),
    );
    tool(
        "read_file",
        "Read the contents of a recovered file (base64), so the agent can inspect \
         it. Capped at 1 MiB; use max_bytes for a smaller preview.",
        schema(
            vec![
                ("path", str_prop("Path to the file to read.")),
                (
                    "max_bytes",
                    int_prop("Maximum bytes to return (default 65536, cap 1 MiB)."),
                ),
            ],
            vec!["path"],
        ),
    );
    tool(
        "triage",
        "Summarize a directory of recovered files: counts and bytes per type, the \
         largest files, content duplicates, and empty files.",
        schema(
            vec![
                (
                    "dir",
                    str_prop("Directory of recovered files to summarize."),
                ),
                (
                    "top",
                    int_prop("How many of the largest files to list (default 10)."),
                ),
            ],
            vec!["dir"],
        ),
    );
    tool(
        "identify",
        "Identify a file's type from its contents (signature + structural check), \
         independent of its extension.",
        schema(
            vec![("path", str_prop("Path to the file to identify."))],
            vec!["path"],
        ),
    );
    tool(
        "scan_status",
        "Check a background job started by `scan` or `image`: running flag, bytes \
         processed / total, and the full result once done.",
        schema(
            vec![("job_id", int_prop("Job id returned by scan or image."))],
            vec!["job_id"],
        ),
    );
    tool(
        "scan_cancel",
        "Request cancellation of a running scan/image job; it stops at the next \
         chunk and keeps whatever was already produced.",
        schema(
            vec![("job_id", int_prop("Job id returned by scan or image."))],
            vec!["job_id"],
        ),
    );

    Json::Arr(tools)
}

/// Standard base64 encoding (with padding), so recovered bytes can travel in a
/// JSON string. Hand-rolled to avoid a dependency.
fn to_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

fn call_tool(name: &str, args: Option<&Json>) -> Result<Json, String> {
    let arg_str = |key: &str| -> Result<&str, String> {
        args.and_then(|a| a.get(key))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing required string argument '{key}'"))
    };
    let arg_bool = |key: &str| args.and_then(|a| a.get(key)).and_then(|v| v.as_bool());
    let arg_u64 = |key: &str| args.and_then(|a| a.get(key)).and_then(|v| v.as_u64());

    match name {
        "list_types" => Ok(Json::Arr(
            signatures::SIGNATURES
                .iter()
                .map(|sig| obj(vec![("ext", s(sig.ext)), ("name", s(sig.name))]))
                .collect(),
        )),

        "list_volumes" => {
            let source = open(arg_str("source")?)?;
            let deleted = arg_bool("deleted").unwrap_or(false);
            let vols = recover::detect(&source).unwrap_or_default();
            let list = vols
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let del = if deleted {
                        let opts = recover::RecoverOptions {
                            min_size: 0,
                            dry_run: true,
                        };
                        match v.recover_deleted(&source, Path::new("."), &opts) {
                            Ok(stbuf) => n(stbuf.recovered),
                            Err(_) => Json::Null,
                        }
                    } else {
                        Json::Null
                    };
                    obj(vec![
                        ("index", n(i as u64)),
                        ("filesystem", s(v.fs_label())),
                        ("offset", n(v.offset())),
                        ("size", n(v.size())),
                        ("deleted", del),
                    ])
                })
                .collect();
            Ok(obj(vec![
                ("source_bytes", n(source.size)),
                ("volumes", Json::Arr(list)),
            ]))
        }

        "scan" => {
            // Carving a large drive can take an hour, so run it as a background
            // job and return a job id; the agent polls `scan_status`. Capture
            // the arguments as owned values for the worker thread.
            let source_path = arg_str("source")?.to_string();
            let output_dir = arg_str("output_dir")?.to_string();
            let types: Vec<String> = args
                .and_then(|a| a.get("types"))
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let min_size = arg_u64("min_size").unwrap_or(0);
            let validate = arg_bool("validate").unwrap_or(true);
            let dedup = arg_bool("dedup").unwrap_or(false);
            let include_files = arg_bool("include_files").unwrap_or(true);

            let id = crate::job::start("scan", move |progress| {
                let source = open(&source_path)?;
                let active = signatures::select(&types).map_err(|e| e.to_string())?;
                let opts = carver::CarveOptions {
                    output_dir: output_dir.clone().into(),
                    start: 0,
                    end: None,
                    min_size,
                    max_files: None,
                    allow_nested: false,
                    validate,
                    dedup,
                    progress: false,
                };
                let stats =
                    carver::carve(&source, &active, &opts, progress).map_err(|e| e.to_string())?;
                let per_type = Json::Obj(
                    stats
                        .per_type
                        .iter()
                        .map(|(k, v)| (k.to_string(), n(*v)))
                        .collect(),
                );
                let mut result = vec![
                    ("output_dir", s(output_dir)),
                    ("cancelled", Json::Bool(progress.cancelled())),
                    ("files_recovered", n(stats.files_recovered)),
                    ("bytes_recovered", n(stats.bytes_recovered)),
                    ("rejected", n(stats.rejected)),
                    ("duplicates", n(stats.duplicates)),
                    ("per_type", per_type),
                ];
                if include_files {
                    let files: Vec<Json> = stats
                        .files
                        .iter()
                        .take(MAX_FILES_IN_RESULT)
                        .map(|f| {
                            obj(vec![
                                ("name", s(f.name.as_str())),
                                ("type", s(f.ext)),
                                ("offset", n(f.offset)),
                                ("size", n(f.size)),
                                ("sha256", s(hash::to_hex(&f.sha256))),
                            ])
                        })
                        .collect();
                    result.push((
                        "files_truncated",
                        Json::Bool(stats.files.len() > files.len()),
                    ));
                    result.push(("files", Json::Arr(files)));
                }
                Ok(obj(result))
            });
            Ok(obj(vec![
                ("job_id", n(id)),
                ("status", s("started")),
                (
                    "note",
                    s(
                        "carving runs in the background; poll scan_status with this job_id, \
                       and scan_cancel to stop it",
                    ),
                ),
            ]))
        }

        "scan_status" => {
            let id = arg_u64("job_id").ok_or("missing required integer argument 'job_id'")?;
            crate::job::status(id).ok_or_else(|| format!("no such job {id}"))
        }

        "scan_cancel" => {
            let id = arg_u64("job_id").ok_or("missing required integer argument 'job_id'")?;
            let existed = crate::job::cancel(id);
            if existed {
                Ok(obj(vec![
                    ("job_id", n(id)),
                    ("cancel_requested", Json::Bool(true)),
                ]))
            } else {
                Err(format!("no such job {id}"))
            }
        }

        "image" => {
            // Imaging a large drive is slow, so run it as a background job and
            // return a job id; the agent polls `scan_status` (shared job API).
            let source_path = arg_str("source")?.to_string();
            let output = arg_str("output")?.to_string();
            let start = arg_u64("start").unwrap_or(0);
            let end = arg_u64("end");
            let sparse = arg_bool("sparse").unwrap_or(true);
            let sector_size = arg_u64("sector_size").unwrap_or(crate::image::DEFAULT_SECTOR);
            let resume = arg_bool("resume").unwrap_or(false);
            let retries = arg_u64("retries").unwrap_or(0) as u32;
            // A map file enables checkpoint/resume; default it next to the image.
            let map: Option<String> = args
                .and_then(|a| a.get("map"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| Some(format!("{output}.map")));

            let id = crate::job::start("image", move |progress| {
                let source = open(&source_path)?;
                let opts = crate::image::ImageOptions {
                    output: output.clone().into(),
                    start,
                    end,
                    sparse,
                    sector_size,
                    map: map.clone().map(Into::into),
                    resume,
                    retries,
                };
                let stats =
                    crate::image::image(&source, &opts, progress).map_err(|e| e.to_string())?;
                let regions: Vec<Json> = stats
                    .bad_regions
                    .iter()
                    .take(MAX_FILES_IN_RESULT)
                    .map(|r| obj(vec![("offset", n(r.offset)), ("length", n(r.len))]))
                    .collect();
                Ok(obj(vec![
                    ("output", s(output)),
                    ("cancelled", Json::Bool(stats.cancelled)),
                    ("bytes_total", n(stats.bytes_total)),
                    ("bytes_copied", n(stats.bytes_copied)),
                    ("bytes_sparse", n(stats.bytes_sparse)),
                    ("bytes_zeroed", n(stats.bytes_zeroed)),
                    ("retry_passes", n(stats.retry_passes as u64)),
                    ("bytes_recovered_retry", n(stats.bytes_recovered_retry)),
                    ("bad_region_count", n(stats.bad_regions.len() as u64)),
                    (
                        "bad_regions_truncated",
                        Json::Bool(stats.bad_regions.len() > regions.len()),
                    ),
                    ("bad_regions", Json::Arr(regions)),
                ]))
            });
            Ok(obj(vec![
                ("job_id", n(id)),
                ("status", s("started")),
                (
                    "note",
                    s(
                        "imaging runs in the background; poll scan_status with this job_id, \
                       and scan_cancel to stop it",
                    ),
                ),
            ]))
        }

        "undelete" => {
            let source = open(arg_str("source")?)?;
            let output_dir = arg_str("output_dir")?.to_string();
            let opts = recover::RecoverOptions {
                min_size: arg_u64("min_size").unwrap_or(0),
                dry_run: arg_bool("dry_run").unwrap_or(false),
            };
            let volumes = match arg_u64("offset") {
                Some(off) => vec![recover::parse_at(&source, off).map_err(|e| e.to_string())?],
                None => recover::detect(&source).map_err(|e| e.to_string())?,
            };
            let multi = volumes.len() > 1;
            let include_files = arg_bool("include_files").unwrap_or(true);
            let (mut recovered, mut bytes, mut skipped) = (0u64, 0u64, 0u64);
            let mut files: Vec<Json> = Vec::new();
            let mut total_files = 0usize;
            for (i, vol) in volumes.iter().enumerate() {
                let out = if multi {
                    Path::new(&output_dir).join(format!("volume_{i}"))
                } else {
                    Path::new(&output_dir).to_path_buf()
                };
                let st = vol
                    .recover_deleted(&source, &out, &opts)
                    .map_err(|e| e.to_string())?;
                recovered += st.recovered;
                bytes += st.bytes_recovered;
                skipped += st.skipped;
                if include_files {
                    total_files += st.files.len();
                    for f in &st.files {
                        if files.len() >= MAX_FILES_IN_RESULT {
                            break;
                        }
                        files.push(obj(vec![
                            ("volume", n(i as u64)),
                            ("path", s(f.path.to_string_lossy().into_owned())),
                            ("size", n(f.size)),
                            ("recovered", Json::Bool(f.recovered)),
                            (
                                "sha256",
                                match &f.sha256 {
                                    Some(d) => s(hash::to_hex(d)),
                                    None => Json::Null,
                                },
                            ),
                        ]));
                    }
                }
            }
            let mut result = vec![
                ("output_dir", s(output_dir)),
                ("volumes", n(volumes.len() as u64)),
                ("dry_run", Json::Bool(opts.dry_run)),
                ("recovered", n(recovered)),
                ("bytes_recovered", n(bytes)),
                ("skipped", n(skipped)),
            ];
            if include_files {
                result.push(("files_truncated", Json::Bool(total_files > files.len())));
                result.push(("files", Json::Arr(files)));
            }
            Ok(obj(result))
        }

        "verify" => {
            let manifest_path = arg_str("manifest")?;
            let base = arg_str("base")?;
            let text = std::fs::read_to_string(manifest_path)
                .map_err(|e| format!("reading manifest: {e}"))?;
            let is_json = Path::new(manifest_path)
                .extension()
                .map(|e| e.eq_ignore_ascii_case("json"))
                .unwrap_or(false);
            let entries = manifest::parse(&text, is_json).map_err(|e| e.to_string())?;
            let (mut ok, mut mismatched, mut missing, mut no_digest) = (0u64, 0u64, 0u64, 0u64);
            for e in &entries {
                let expected = match &e.sha256 {
                    Some(s) => s,
                    None => {
                        no_digest += 1;
                        continue;
                    }
                };
                match std::fs::read(Path::new(base).join(&e.path)) {
                    Ok(data) => {
                        if hash::to_hex(&hash::digest(&data)).eq_ignore_ascii_case(expected) {
                            ok += 1;
                        } else {
                            mismatched += 1;
                        }
                    }
                    Err(_) => missing += 1,
                }
            }
            Ok(obj(vec![
                ("ok", n(ok)),
                ("mismatched", n(mismatched)),
                ("missing", n(missing)),
                ("no_digest", n(no_digest)),
            ]))
        }

        "read_file" => {
            const HARD_CAP: u64 = 1 << 20; // 1 MiB
            let path = arg_str("path")?;
            let max_bytes = arg_u64("max_bytes").unwrap_or(65536).min(HARD_CAP);
            let meta = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
            let size = meta.len();
            let mut buf = vec![0u8; max_bytes.min(size) as usize];
            {
                use std::io::Read;
                let mut f =
                    std::fs::File::open(path).map_err(|e| format!("opening {path}: {e}"))?;
                let mut read = 0usize;
                while read < buf.len() {
                    let nb = f.read(&mut buf[read..]).map_err(|e| e.to_string())?;
                    if nb == 0 {
                        break;
                    }
                    read += nb;
                }
                buf.truncate(read);
            }
            Ok(obj(vec![
                ("path", s(path)),
                ("size", n(size)),
                ("bytes_returned", n(buf.len() as u64)),
                ("truncated", Json::Bool((buf.len() as u64) < size)),
                ("encoding", s("base64")),
                ("data", s(to_base64(&buf))),
            ]))
        }

        "triage" => {
            let dir = arg_str("dir")?;
            let top = arg_u64("top").unwrap_or(10) as usize;
            let sum = crate::triage::summarize(Path::new(dir), top).map_err(|e| e.to_string())?;
            let by_type = Json::Obj(
                sum.by_type
                    .iter()
                    .map(|(ext, st)| {
                        (
                            ext.clone(),
                            obj(vec![("count", n(st.count)), ("bytes", n(st.bytes))]),
                        )
                    })
                    .collect(),
            );
            let largest = sum
                .largest
                .iter()
                .map(|(p, sz)| obj(vec![("path", s(p.as_str())), ("size", n(*sz))]))
                .collect();
            Ok(obj(vec![
                ("dir", s(dir)),
                ("total_files", n(sum.total_files)),
                ("total_bytes", n(sum.total_bytes)),
                ("empty_files", n(sum.empty_files)),
                ("duplicate_sets", n(sum.duplicate_sets)),
                ("duplicate_bytes", n(sum.duplicate_bytes)),
                ("by_type", by_type),
                ("largest", Json::Arr(largest)),
            ]))
        }

        "identify" => {
            use std::io::Read;
            let path = arg_str("path")?;
            let mut head = vec![0u8; 64 * 1024];
            let mut f = std::fs::File::open(path).map_err(|e| format!("opening {path}: {e}"))?;
            let mut read = 0usize;
            while read < head.len() {
                let nb = f.read(&mut head[read..]).map_err(|e| e.to_string())?;
                if nb == 0 {
                    break;
                }
                read += nb;
            }
            head.truncate(read);
            Ok(match crate::identify::identify(&head) {
                Some(d) => obj(vec![
                    ("path", s(path)),
                    ("identified", Json::Bool(true)),
                    ("type", s(d.ext)),
                    ("name", s(d.name)),
                    ("validated", Json::Bool(d.validated)),
                ]),
                None => obj(vec![("path", s(path)), ("identified", Json::Bool(false))]),
            })
        }

        other => Err(format!("unknown tool '{other}'")),
    }
}

fn open(path: &str) -> Result<Source, String> {
    Source::open(Path::new(path)).map_err(|e| format!("opening {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(req: &str) -> Json {
        handle_request(&json::parse(req).unwrap()).unwrap()
    }

    #[test]
    fn initialize_handshake() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        );
        assert_eq!(resp.get("id").unwrap().as_u64(), Some(1));
        let result = resp.get("result").unwrap();
        assert_eq!(
            result
                .get("serverInfo")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str(),
            Some("filerecovery")
        );
        assert!(result.get("capabilities").unwrap().get("tools").is_some());
    }

    #[test]
    fn notification_gets_no_response() {
        let req = json::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(handle_request(&req).is_none());
    }

    #[test]
    fn unknown_method_errors() {
        let resp = call(r#"{"jsonrpc":"2.0","id":2,"method":"bogus"}"#);
        assert_eq!(
            resp.get("error").unwrap().get("code").unwrap().as_u64(),
            None
        );
        assert_eq!(
            resp.get("error").unwrap().get("code").unwrap(),
            &Json::Num(-32601.0)
        );
    }

    #[test]
    fn tools_list_has_the_tools() {
        let resp = call(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#);
        let tools = resp
            .get("result")
            .unwrap()
            .get("tools")
            .unwrap()
            .as_array()
            .unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        for want in [
            "list_types",
            "list_volumes",
            "scan",
            "image",
            "undelete",
            "verify",
            "read_file",
            "triage",
            "identify",
            "scan_status",
            "scan_cancel",
        ] {
            assert!(names.contains(&want), "missing tool {want}");
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(to_base64(b""), "");
        assert_eq!(to_base64(b"f"), "Zg==");
        assert_eq!(to_base64(b"fo"), "Zm8=");
        assert_eq!(to_base64(b"foo"), "Zm9v");
        assert_eq!(to_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn list_types_tool_call() {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_types","arguments":{}}}"#,
        );
        let result = resp.get("result").unwrap();
        assert_eq!(result.get("isError").unwrap().as_bool(), Some(false));
        let text = result.get("content").unwrap().as_array().unwrap()[0]
            .get("text")
            .unwrap()
            .as_str()
            .unwrap();
        // The text is a JSON array of {ext,name}; jpg must be in there.
        let parsed = json::parse(text).unwrap();
        assert!(parsed
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e.get("ext").and_then(|x| x.as_str()) == Some("jpg")));
    }

    #[test]
    fn tool_error_is_reported_in_band() {
        // Missing required argument => isError true, not a protocol error.
        let resp = call(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_volumes","arguments":{}}}"#,
        );
        let result = resp.get("result").unwrap();
        assert_eq!(result.get("isError").unwrap().as_bool(), Some(true));
    }
}
