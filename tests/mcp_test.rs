//! End-to-end test of the MCP server: drive `mcp::serve` over in-memory buffers
//! with a real session (initialize, then tool calls that actually recover data).

mod common;

use std::io::Cursor;

use filerecovery::json::{self, Json};
use filerecovery::mcp;

/// Feed newline-delimited JSON-RPC requests through the server and return the
/// parsed responses (in order).
fn session(requests: &[&str]) -> Vec<Json> {
    let input = requests.join("\n");
    let mut output = Vec::new();
    mcp::serve(Cursor::new(input.into_bytes()), &mut output).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| json::parse(l).unwrap())
        .collect()
}

/// Pull the parsed `result.content[0].text` JSON out of a tool-call response.
fn tool_result(resp: &Json) -> Json {
    let result = resp.get("result").unwrap();
    assert_eq!(
        result.get("isError").unwrap().as_bool(),
        Some(false),
        "tool reported an error: {resp}"
    );
    let text = result.get("content").unwrap().as_array().unwrap()[0]
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    json::parse(text).unwrap()
}

#[test]
fn full_session_initializes_and_scans() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("out");

    // An image with one planted JPEG.
    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 600];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let scan_req = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
        img.display(),
        out.display()
    );
    let resps = session(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        &scan_req,
    ]);

    // initialize + scan responses (the notification produces none).
    assert_eq!(
        resps.len(),
        2,
        "two responses, no reply to the notification"
    );
    assert_eq!(resps[0].get("id").unwrap().as_u64(), Some(1));
    assert_eq!(
        resps[0]
            .get("result")
            .unwrap()
            .get("serverInfo")
            .unwrap()
            .get("name")
            .unwrap()
            .as_str(),
        Some("filerecovery")
    );

    let scan = tool_result(&resps[1]);
    assert_eq!(scan.get("files_recovered").unwrap().as_u64(), Some(1));
    assert_eq!(
        scan.get("per_type").unwrap().get("jpg").unwrap().as_u64(),
        Some(1)
    );
    // The JPEG was actually written to the output directory.
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);

    // The per-file manifest is inline, with a digest matching the bytes on disk.
    let files = scan.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].get("type").unwrap().as_str(), Some("jpg"));
    let expected = filerecovery::hash::to_hex(&filerecovery::hash::digest(&jpeg));
    assert_eq!(
        files[0].get("sha256").unwrap().as_str(),
        Some(expected.as_str())
    );
    assert_eq!(scan.get("files_truncated").unwrap().as_bool(), Some(false));
}

#[test]
fn list_volumes_and_undelete_tools() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("rec");
    std::fs::write(&img, common::ext_volume("notes.txt", b"hello mcp")).unwrap();

    let lv = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"list_volumes","arguments":{{"source":"{}","deleted":true}}}}}}"#,
        img.display()
    );
    let und = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"undelete","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
        img.display(),
        out.display()
    );
    let resps = session(&[&lv, &und]);

    let volumes = tool_result(&resps[0]);
    let vols = volumes.get("volumes").unwrap().as_array().unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(
        vols[0].get("filesystem").unwrap().as_str(),
        Some("ext2/3/4")
    );
    assert_eq!(vols[0].get("deleted").unwrap().as_u64(), Some(1));

    let undelete = tool_result(&resps[1]);
    assert_eq!(undelete.get("recovered").unwrap().as_u64(), Some(1));
    assert_eq!(std::fs::read(out.join("notes.txt")).unwrap(), b"hello mcp");

    // The recovered file is listed inline with its path and digest.
    let files = undelete.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].get("path").unwrap().as_str(), Some("notes.txt"));
    let expected = filerecovery::hash::to_hex(&filerecovery::hash::digest(b"hello mcp"));
    assert_eq!(
        files[0].get("sha256").unwrap().as_str(),
        Some(expected.as_str())
    );

    // The agent can read the recovered file's bytes back for inspection.
    let recovered_path = out.join("notes.txt");
    let rf = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        recovered_path.display()
    );
    let resps = session(&[&rf]);
    let read = tool_result(&resps[0]);
    assert_eq!(read.get("size").unwrap().as_u64(), Some(9)); // "hello mcp"
    assert_eq!(read.get("truncated").unwrap().as_bool(), Some(false));
    assert_eq!(read.get("encoding").unwrap().as_str(), Some("base64"));
    // "hello mcp" base64-encodes to "aGVsbG8gbWNw".
    assert_eq!(read.get("data").unwrap().as_str(), Some("aGVsbG8gbWNw"));
}
