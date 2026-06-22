//! A minimal Model Context Protocol (MCP) server over stdio, so an AI agent can
//! drive recovery and reason over the results.
//!
//! MCP is JSON-RPC 2.0 with newline-delimited messages on stdin/stdout. This
//! server implements the handshake (`initialize`), `tools/list`, `tools/call`,
//! and `ping`, exposing the tool's capabilities as callable tools:
//!
//! * `list_types`   — the file types carving can recover
//! * `list_volumes` — detect partitions/filesystems in a source (+ deleted counts)
//! * `scan`         — signature carving into an output directory
//! * `undelete`     — filesystem-aware recovery into an output directory
//! * `verify`       — re-hash recovered files against a `--report` manifest
//!
//! It is built on the crate's own [`crate::json`] so it pulls in no new
//! dependencies and runs synchronously (no async runtime).

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::Result;

use crate::json::{self, obj, s, Json};
use crate::{carver, hash, manifest, recover, signatures, source::Source};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "filerecovery";

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
        "Carve files from a source by signature into output_dir (filesystem-agnostic).",
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

    Json::Arr(tools)
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
            let source = open(arg_str("source")?)?;
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
            let active = signatures::select(&types).map_err(|e| e.to_string())?;
            let opts = carver::CarveOptions {
                output_dir: output_dir.clone().into(),
                start: 0,
                end: None,
                min_size: arg_u64("min_size").unwrap_or(0),
                max_files: None,
                allow_nested: false,
                validate: arg_bool("validate").unwrap_or(true),
                dedup: arg_bool("dedup").unwrap_or(false),
                progress: false,
            };
            let stats = carver::carve(&source, &active, &opts, &carver::NoProgress)
                .map_err(|e| e.to_string())?;
            let per_type = Json::Obj(
                stats
                    .per_type
                    .iter()
                    .map(|(k, v)| (k.to_string(), n(*v)))
                    .collect(),
            );
            Ok(obj(vec![
                ("output_dir", s(output_dir)),
                ("files_recovered", n(stats.files_recovered)),
                ("bytes_recovered", n(stats.bytes_recovered)),
                ("rejected", n(stats.rejected)),
                ("duplicates", n(stats.duplicates)),
                ("per_type", per_type),
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
            let (mut recovered, mut bytes, mut skipped) = (0u64, 0u64, 0u64);
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
            }
            Ok(obj(vec![
                ("output_dir", s(output_dir)),
                ("volumes", n(volumes.len() as u64)),
                ("dry_run", Json::Bool(opts.dry_run)),
                ("recovered", n(recovered)),
                ("bytes_recovered", n(bytes)),
                ("skipped", n(skipped)),
            ]))
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
        for want in ["list_types", "list_volumes", "scan", "undelete", "verify"] {
            assert!(names.contains(&want), "missing tool {want}");
        }
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
