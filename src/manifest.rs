//! Parsing of the recovery manifests written by `scan --report` and
//! `undelete --report`, so the `verify` command can read them back and re-check
//! the recovered files.
//!
//! Both CSV and JSON manifests are supported, and both the carve manifest
//! (which names files in a `name` column) and the undelete manifest (a `path`
//! column) are handled. Each parsed [`Entry`] pairs a file path, relative to
//! the recovery output directory, with the SHA-256 recorded for it.

use anyhow::{anyhow, bail, Result};

/// One row of a manifest.
pub struct Entry {
    /// File path relative to the recovery output directory.
    pub path: String,
    /// The recorded SHA-256 (lower-case hex), or `None` when the manifest left
    /// it blank (a skipped file or a dry run).
    pub sha256: Option<String>,
}

/// Parse a manifest. `is_json` selects the format (chosen by the caller from
/// the file extension).
pub fn parse(text: &str, is_json: bool) -> Result<Vec<Entry>> {
    if is_json {
        parse_json(text)
    } else {
        parse_csv(text)
    }
}

fn parse_csv(text: &str) -> Result<Vec<Entry>> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next().ok_or_else(|| anyhow!("manifest is empty"))?;
    let cols = split_csv_line(header);
    let path_idx = cols
        .iter()
        .position(|c| c == "name" || c == "path")
        .ok_or_else(|| anyhow!("manifest has no 'name' or 'path' column"))?;
    let sha_idx = cols
        .iter()
        .position(|c| c == "sha256")
        .ok_or_else(|| anyhow!("manifest has no 'sha256' column"))?;

    let mut out = Vec::new();
    for line in lines {
        let fields = split_csv_line(line);
        let path = match fields.get(path_idx) {
            Some(p) => p.clone(),
            None => continue,
        };
        let sha = fields
            .get(sha_idx)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        out.push(Entry { path, sha256: sha });
    }
    Ok(out)
}

fn parse_json(text: &str) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        if !line.starts_with('{') {
            continue;
        }
        let path = match json_str_field(line, "name").or_else(|| json_str_field(line, "path")) {
            Some(p) => p,
            None => continue,
        };
        let sha = json_str_field(line, "sha256").filter(|s| !s.is_empty());
        out.push(Entry { path, sha256: sha });
    }
    if out.is_empty() {
        bail!("no entries found in JSON manifest");
    }
    Ok(out)
}

/// Split one CSV line into fields, honouring the `"`-quoting and `""` escaping
/// produced by the report writer.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => out.push(std::mem::take(&mut field)),
                _ => field.push(c),
            }
        }
    }
    out.push(field);
    out
}

/// Extract a string-valued JSON field (`"key": "value"`) from one line of the
/// manifest, undoing `\\` / `\"` escaping. Returns `None` if the key is absent
/// or its value is not a string.
fn json_str_field(line: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let start = line.find(&pat)?;
    let rest = &line[start + pat.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None; // a numeric or other non-string value
    }
    let mut s = String::new();
    let mut escaped = false;
    for c in after[1..].chars() {
        if escaped {
            s.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(s);
        } else {
            s.push(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_carve_csv() {
        let csv = "name,type,offset,size,sha256\n\
                   00000000_0x0.jpg,jpg,0,100,abc123\n";
        let e = parse(csv, false).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].path, "00000000_0x0.jpg");
        assert_eq!(e[0].sha256.as_deref(), Some("abc123"));
    }

    #[test]
    fn parses_undelete_csv_with_quoted_path() {
        // A path containing a comma is quoted by the writer.
        let csv = "filesystem,volume_offset,path,size,recovered,sha256\n\
                   ext2/3/4,0,\"dir/a,b.txt\",10,true,deadbeef\n\
                   ext2/3/4,0,skipped.bin,0,false,\n";
        let e = parse(csv, false).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].path, "dir/a,b.txt");
        assert_eq!(e[0].sha256.as_deref(), Some("deadbeef"));
        // The skipped row has no digest.
        assert_eq!(e[1].path, "skipped.bin");
        assert_eq!(e[1].sha256, None);
    }

    #[test]
    fn parses_json() {
        let json = "[\n\
            {\"name\": \"f.jpg\", \"type\": \"jpg\", \"offset\": 1000, \"size\": 5, \"sha256\": \"feed\"},\n\
            {\"name\": \"g.png\", \"type\": \"png\", \"offset\": 2000, \"size\": 6, \"sha256\": \"\"}\n\
            ]\n";
        let e = parse(json, true).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].path, "f.jpg");
        assert_eq!(e[0].sha256.as_deref(), Some("feed"));
        assert_eq!(e[1].sha256, None);
    }

    #[test]
    fn json_path_with_escapes() {
        let json = "[\n{\"path\": \"a\\\\b\\\"c\", \"size\": 1, \"sha256\": \"00\"}\n]\n";
        let e = parse(json, true).unwrap();
        assert_eq!(e[0].path, "a\\b\"c");
    }

    #[test]
    fn missing_columns_error() {
        assert!(parse("foo,bar\n1,2\n", false).is_err());
    }
}
