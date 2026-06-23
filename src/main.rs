//! `filerecovery` command-line entry point.

mod cli;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use clap::CommandFactory;
use cli::{
    Cli, Command, CompletionsArgs, IdentifyArgs, ImageArgs, InfoArgs, RecoverArgs, ScanArgs,
    TriageArgs, UndeleteArgs, VerifyArgs,
};
use filerecovery::carver::{self, CarveOptions, ProgressSink};
use filerecovery::recover;
use filerecovery::signatures::{self, SIGNATURES};
use filerecovery::source::Source;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ListTypes => {
            list_types();
            Ok(())
        }
        Command::Scan(args) => scan(args),
        Command::Undelete(args) => undelete(args),
        Command::Recover(args) => recover_all(args),
        Command::Info(args) => info(args),
        Command::Image(args) => image(args),
        Command::Verify(args) => verify(args),
        Command::Triage(args) => triage(args),
        Command::Identify(args) => identify(args),
        Command::Mcp => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            filerecovery::mcp::serve(stdin.lock(), stdout.lock())
        }
        Command::Completions(args) => {
            completions(args);
            Ok(())
        }
    }
}

/// Print a shell completion script for `filerecovery` to stdout.
fn completions(args: CompletionsArgs) {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "filerecovery", &mut std::io::stdout());
}

fn verify(args: VerifyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.manifest)
        .map_err(|e| anyhow::anyhow!("reading manifest {}: {e}", args.manifest.display()))?;
    let is_json = args
        .manifest
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let entries = filerecovery::manifest::parse(&text, is_json)?;

    let mut ok = 0u64;
    let mut mismatched = 0u64;
    let mut missing = 0u64;
    let mut no_digest = 0u64;

    for e in &entries {
        let expected = match &e.sha256 {
            Some(s) => s,
            None => {
                no_digest += 1;
                continue;
            }
        };
        let path = args.base.join(&e.path);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                missing += 1;
                println!("MISSING   {}", e.path);
                continue;
            }
        };
        let got = filerecovery::hash::to_hex(&filerecovery::hash::digest(&data));
        if got.eq_ignore_ascii_case(expected) {
            ok += 1;
        } else {
            mismatched += 1;
            println!("MISMATCH  {} (expected {expected}, got {got})", e.path);
        }
    }

    println!(
        "Verified {ok} OK, {mismatched} mismatched, {missing} missing, {no_digest} without a digest."
    );
    if mismatched > 0 || missing > 0 {
        anyhow::bail!("verification failed: {mismatched} mismatched, {missing} missing");
    }
    Ok(())
}

/// Count recoverable deleted files in a volume via a dry-run recovery; `None`
/// when the caller didn't ask, `Some(-1)` when the scan errored.
fn deleted_count(vol: &recover::Volume, source: &Source, requested: bool) -> Option<i64> {
    if !requested {
        return None;
    }
    let opts = recover::RecoverOptions {
        min_size: 0,
        dry_run: true,
    };
    Some(
        match vol.recover_deleted(source, std::path::Path::new("."), &opts) {
            Ok(stats) => stats.recovered as i64,
            Err(_) => -1,
        },
    )
}

fn triage(args: TriageArgs) -> Result<()> {
    use filerecovery::json::{obj, s, Json};

    let sum = filerecovery::triage::summarize(&args.dir, args.top)?;

    if args.json {
        let by_type = Json::Obj(
            sum.by_type
                .iter()
                .map(|(ext, st)| {
                    (
                        ext.clone(),
                        obj(vec![
                            ("count", Json::Num(st.count as f64)),
                            ("bytes", Json::Num(st.bytes as f64)),
                        ]),
                    )
                })
                .collect(),
        );
        let largest = sum
            .largest
            .iter()
            .map(|(p, sz)| {
                obj(vec![
                    ("path", s(p.as_str())),
                    ("size", Json::Num(*sz as f64)),
                ])
            })
            .collect();
        let out = obj(vec![
            ("dir", s(args.dir.display().to_string())),
            ("total_files", Json::Num(sum.total_files as f64)),
            ("total_bytes", Json::Num(sum.total_bytes as f64)),
            ("empty_files", Json::Num(sum.empty_files as f64)),
            ("duplicate_sets", Json::Num(sum.duplicate_sets as f64)),
            ("duplicate_bytes", Json::Num(sum.duplicate_bytes as f64)),
            ("by_type", by_type),
            ("largest", Json::Arr(largest)),
        ]);
        println!("{out}");
        return Ok(());
    }

    println!(
        "{} file(s), {} total.",
        sum.total_files,
        human_bytes(sum.total_bytes)
    );
    if sum.empty_files > 0 {
        println!("  {} empty file(s).", sum.empty_files);
    }
    if sum.duplicate_sets > 0 {
        println!(
            "  {} duplicate set(s), {} redundant.",
            sum.duplicate_sets,
            human_bytes(sum.duplicate_bytes)
        );
    }
    if !sum.by_type.is_empty() {
        println!("\nBy type:");
        for (ext, st) in &sum.by_type {
            let label = if ext.is_empty() { "(none)" } else { ext };
            println!("  {:<8} {:>5}  {}", label, st.count, human_bytes(st.bytes));
        }
    }
    if !sum.largest.is_empty() {
        println!("\nLargest:");
        for (path, size) in &sum.largest {
            println!("  {:>10}  {}", human_bytes(*size), path);
        }
    }
    Ok(())
}

fn identify(args: IdentifyArgs) -> Result<()> {
    use std::io::Read;
    let mut head = vec![0u8; 64 * 1024];
    let mut f = std::fs::File::open(&args.file)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", args.file.display()))?;
    let mut read = 0usize;
    while read < head.len() {
        let nb = f.read(&mut head[read..])?;
        if nb == 0 {
            break;
        }
        read += nb;
    }
    head.truncate(read);
    let detected = filerecovery::identify::identify(&head);

    if args.json {
        use filerecovery::json::{obj, s, Json};
        let out = match &detected {
            Some(d) => obj(vec![
                ("file", s(args.file.display().to_string())),
                ("identified", Json::Bool(true)),
                ("type", s(d.ext)),
                ("name", s(d.name)),
                ("validated", Json::Bool(d.validated)),
            ]),
            None => obj(vec![
                ("file", s(args.file.display().to_string())),
                ("identified", Json::Bool(false)),
            ]),
        };
        println!("{out}");
        return Ok(());
    }

    match detected {
        Some(d) => {
            let note = if d.validated {
                "structurally validated"
            } else {
                "by magic"
            };
            println!("{}: {} ({}, {note})", args.file.display(), d.name, d.ext);
        }
        None => println!("{}: unknown", args.file.display()),
    }
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let source = Source::open(&args.source)?;
    let detected = recover::detect(&source);

    if args.json {
        let vols = detected.unwrap_or_default();
        let mut out = String::from("{\n");
        out.push_str(&format!(
            "  \"source\": \"{}\",\n",
            json_escape(&args.source.display().to_string())
        ));
        out.push_str(&format!("  \"source_bytes\": {},\n", source.size));
        if vols.is_empty() {
            out.push_str("  \"volumes\": []\n");
        } else {
            out.push_str("  \"volumes\": [\n");
            for (i, vol) in vols.iter().enumerate() {
                let deleted = match deleted_count(vol, &source, args.deleted) {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                let comma = if i + 1 < vols.len() { "," } else { "" };
                out.push_str(&format!(
                    "    {{\"index\": {}, \"filesystem\": \"{}\", \"offset\": {}, \"size\": {}, \"deleted\": {}}}{}\n",
                    i,
                    json_escape(&vol.fs_label()),
                    vol.offset(),
                    vol.size(),
                    deleted,
                    comma
                ));
            }
            out.push_str("  ]\n");
        }
        out.push_str("}\n");
        print!("{out}");
        return Ok(());
    }

    println!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    let volumes = match detected {
        Ok(v) => v,
        Err(e) => {
            println!("No supported volumes detected: {e}");
            return Ok(());
        }
    };

    println!("\nDetected {} volume(s):\n", volumes.len());
    println!(
        "  {:<3} {:<10} {:<14} {:<10} DELETED",
        "#", "FS", "OFFSET", "SIZE"
    );
    println!(
        "  {:<3} {:<10} {:<14} {:<10} -------",
        "-", "--", "------", "----"
    );
    for (i, vol) in volumes.iter().enumerate() {
        let deleted = match deleted_count(vol, &source, args.deleted) {
            None => "-".to_string(),
            Some(-1) => "?".to_string(),
            Some(n) => n.to_string(),
        };
        println!(
            "  {:<3} {:<10} {:<14} {:<10} {}",
            i,
            vol.fs_label(),
            vol.offset(),
            human_bytes(vol.size()),
            deleted
        );
    }
    if !args.deleted {
        println!("\nRun with --deleted to count recoverable deleted files per volume.");
    }
    Ok(())
}

fn list_types() {
    println!("Recoverable file types:\n");
    println!("  {:<6}  DESCRIPTION", "EXT");
    println!("  {:<6}  -----------", "---");
    for sig in SIGNATURES {
        println!("  {:<6}  {}", sig.ext, sig.name);
    }
    println!("\nUse: filerecovery scan <SOURCE> --type <EXT> [--type <EXT> ...]");
}

fn scan(args: ScanArgs) -> Result<()> {
    let started = std::time::Instant::now();
    let active = signatures::select(&args.types)?;

    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );
    let type_list: Vec<&str> = active.iter().map(|s| s.ext).collect();
    eprintln!("Recovering: {}", type_list.join(", "));
    eprintln!("Output:     {}", args.output.display());

    // A checkpoint file enables resume; default it next to the output directory
    // when --resume is requested without an explicit --checkpoint.
    let checkpoint = args.checkpoint.clone().or_else(|| {
        if args.resume {
            let mut p = args.output.clone().into_os_string();
            p.push(".checkpoint");
            Some(p.into())
        } else {
            None
        }
    });

    let opts = CarveOptions {
        output_dir: args.output,
        start: args.start,
        end: args.end,
        min_size: args.min_size,
        max_files: args.max_files,
        allow_nested: args.allow_nested,
        validate: !args.no_validate,
        dedup: args.dedup,
        progress: !args.quiet,
        checkpoint: checkpoint.clone(),
        resume: args.resume,
        organize: args.organize,
    };

    let progress: Box<dyn ProgressSink> = if opts.progress {
        Box::new(Bar::new())
    } else {
        Box::new(carver::NoProgress)
    };

    let stats = carver::carve(&source, &active, &opts, progress.as_ref())?;

    eprintln!();
    println!(
        "Done. Recovered {} file(s), {}.",
        stats.files_recovered,
        human_bytes(stats.bytes_recovered)
    );
    if !stats.per_type.is_empty() {
        for (ext, count) in &stats.per_type {
            println!("  {:<6} {}", ext, count);
        }
    }
    if stats.rejected > 0 {
        println!(
            "Rejected {} candidate(s) that failed validation (use --no-validate to keep them).",
            stats.rejected
        );
    }
    if let Some(report_path) = &args.report {
        write_carve_report(report_path, &stats.files)?;
        eprintln!("Report written to {}", report_path.display());
    }
    if stats.duplicates > 0 {
        println!(
            "Skipped {} duplicate(s) with identical content.",
            stats.duplicates
        );
    }
    if let Some(summary_path) = &args.summary {
        let per_type: Vec<(String, u64)> = stats
            .per_type
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let fields = [
            ("command", Sv::S("scan".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(opts.output_dir.display().to_string())),
            ("types", Sv::S(type_list.join(","))),
            ("validate", Sv::B(!args.no_validate)),
            ("dedup", Sv::B(args.dedup)),
            ("allow_nested", Sv::B(args.allow_nested)),
            ("min_size", Sv::N(args.min_size)),
            ("files_recovered", Sv::N(stats.files_recovered)),
            ("bytes_recovered", Sv::N(stats.bytes_recovered)),
            ("rejected", Sv::N(stats.rejected)),
            ("duplicates", Sv::N(stats.duplicates)),
            ("per_type", Sv::Map(per_type)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

fn undelete(args: UndeleteArgs) -> Result<()> {
    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    let volumes = match args.offset {
        Some(off) => vec![recover::parse_at(&source, off)?],
        None => recover::detect(&source)?,
    };
    eprintln!("Found {} volume(s).", volumes.len());

    let opts = recover::RecoverOptions {
        min_size: args.min_size,
        dry_run: args.dry_run,
    };
    if args.dry_run {
        eprintln!("Dry run: no files will be written.");
    } else {
        std::fs::create_dir_all(&args.output)
            .map_err(|e| anyhow::anyhow!("creating output dir {}: {e}", args.output.display()))?;
    }

    let mut total_recovered = 0u64;
    let mut total_bytes = 0u64;
    let mut total_skipped = 0u64;
    // Report rows: (filesystem, volume offset, relative path, size, recovered,
    // sha256-hex). The digest is empty for skipped files and dry runs.
    let mut report_rows: Vec<(String, u64, String, u64, bool, String)> = Vec::new();

    for (i, vol) in volumes.iter().enumerate() {
        // Keep each volume's output separate to avoid path collisions.
        let out = if volumes.len() > 1 {
            args.output.join(format!("volume_{i}"))
        } else {
            args.output.clone()
        };
        eprintln!(
            "Volume {i}: {} at offset {} -> {}",
            vol.fs_label(),
            vol.offset(),
            out.display()
        );
        let stats = vol.recover_deleted(&source, &out, &opts)?;
        total_recovered += stats.recovered;
        total_bytes += stats.bytes_recovered;
        total_skipped += stats.skipped;

        let label = vol.fs_label();
        let offset = vol.offset();
        for f in &stats.files {
            let sha = f
                .sha256
                .map(|d| filerecovery::hash::to_hex(&d))
                .unwrap_or_default();
            report_rows.push((
                label.clone(),
                offset,
                f.path.to_string_lossy().into_owned(),
                f.size,
                f.recovered,
                sha,
            ));
        }
    }

    if let Some(report_path) = &args.report {
        write_report(report_path, &report_rows)?;
        eprintln!("Report written to {}", report_path.display());
    }

    eprintln!();
    let verb = if args.dry_run {
        "Would recover"
    } else {
        "Recovered"
    };
    println!(
        "Done. {verb} {} deleted file(s), {} ({} skipped as unrecoverable).",
        total_recovered,
        human_bytes(total_bytes),
        total_skipped
    );

    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("undelete".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("volumes", Sv::N(volumes.len() as u64)),
            ("dry_run", Sv::B(args.dry_run)),
            ("min_size", Sv::N(args.min_size)),
            ("recovered", Sv::N(total_recovered)),
            ("bytes_recovered", Sv::N(total_bytes)),
            ("skipped", Sv::N(total_skipped)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

/// One-pass recovery: filesystem-aware undelete into `named/`, then carving
/// into `carved/` (content-deduplicated against the undelete results).
fn recover_all(args: RecoverArgs) -> Result<()> {
    use std::collections::HashSet;

    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    // Pass 1: filesystem-aware undelete (restores names and paths).
    let named_dir = args.output.join("named");
    let volumes = match args.offset {
        Some(off) => vec![recover::parse_at(&source, off)?],
        None => recover::detect(&source).unwrap_or_default(),
    };
    if volumes.is_empty() {
        eprintln!("No supported filesystem detected; carving only.");
    }
    let ropts = recover::RecoverOptions {
        min_size: args.min_size,
        dry_run: false,
    };
    let multi = volumes.len() > 1;
    let mut named_recovered = 0u64;
    let mut named_bytes = 0u64;
    // Digests of everything undelete restored, so carving skips that content.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // Combined manifest rows: (kind, path-relative-to-output, size, sha256-hex).
    let mut report_rows: Vec<(&str, String, u64, String)> = Vec::new();
    for (i, vol) in volumes.iter().enumerate() {
        let out = if multi {
            named_dir.join(format!("volume_{i}"))
        } else {
            named_dir.clone()
        };
        eprintln!(
            "Undelete: {} at offset {} -> {}",
            vol.fs_label(),
            vol.offset(),
            out.display()
        );
        let st = vol.recover_deleted(&source, &out, &ropts)?;
        named_recovered += st.recovered;
        named_bytes += st.bytes_recovered;
        for f in &st.files {
            if let Some(d) = f.sha256 {
                seen.insert(d);
            }
            let rel = if multi {
                format!("named/volume_{i}/{}", f.path.to_string_lossy())
            } else {
                format!("named/{}", f.path.to_string_lossy())
            };
            let sha = f
                .sha256
                .map(|d| filerecovery::hash::to_hex(&d))
                .unwrap_or_default();
            report_rows.push(("named", rel, f.size, sha));
        }
    }

    // With --unallocated, carve only each volume's free space (so live files
    // aren't re-found). Available only when every volume can report its free
    // map; otherwise fall back to carving the whole source.
    let carve_regions: Option<Vec<(u64, u64)>> = if args.unallocated {
        let mut regions = Vec::new();
        let mut supported = !volumes.is_empty();
        for v in &volumes {
            match v.free_extents(&source) {
                Some(r) => regions.extend(r),
                None => {
                    supported = false;
                    break;
                }
            }
        }
        if supported {
            Some(regions)
        } else {
            eprintln!(
                "--unallocated: free-space map unavailable for the detected filesystem(s); \
                 carving the whole source instead."
            );
            None
        }
    } else {
        None
    };

    // Pass 2: carving for whatever the metadata could not restore.
    let active = signatures::select(&args.types)?;
    let carved_dir = args.output.join("carved");
    let mk_opts = |start: u64, end: Option<u64>, progress: bool| CarveOptions {
        output_dir: carved_dir.clone(),
        start,
        end,
        min_size: args.min_size,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: true,
        progress,
        checkpoint: None,
        resume: false,
        organize: args.organize,
    };
    let (mut carved_files, mut carved_bytes, mut carved_dups) = (0u64, 0u64, 0u64);
    let push_carved = |files: &[carver::CarvedFile],
                       rows: &mut Vec<(&str, String, u64, String)>| {
        for f in files {
            rows.push((
                "carved",
                format!("carved/{}", f.name),
                f.size,
                filerecovery::hash::to_hex(&f.sha256),
            ));
        }
    };
    match carve_regions {
        Some(regions) => {
            eprintln!(
                "Carve:    {} unallocated region(s) into {}",
                regions.len(),
                carved_dir.display()
            );
            for (rstart, rlen) in regions {
                let opts = mk_opts(rstart, Some(rstart + rlen), false);
                let cs = carver::carve_seeded(
                    &source,
                    &active,
                    &opts,
                    &carver::NoProgress,
                    seen.clone(),
                )?;
                carved_files += cs.files_recovered;
                carved_bytes += cs.bytes_recovered;
                carved_dups += cs.duplicates;
                push_carved(&cs.files, &mut report_rows);
            }
        }
        None => {
            eprintln!("Carve:    into {}", carved_dir.display());
            let opts = mk_opts(0, None, !args.quiet);
            let progress: Box<dyn ProgressSink> = if opts.progress {
                Box::new(Bar::new())
            } else {
                Box::new(carver::NoProgress)
            };
            let cs = carver::carve_seeded(&source, &active, &opts, progress.as_ref(), seen)?;
            carved_files += cs.files_recovered;
            carved_bytes += cs.bytes_recovered;
            carved_dups += cs.duplicates;
            push_carved(&cs.files, &mut report_rows);
        }
    }

    eprintln!();
    println!(
        "Done. Undelete recovered {} named file(s), {}.",
        named_recovered,
        human_bytes(named_bytes)
    );
    println!(
        "Carving recovered {} additional file(s), {} ({} duplicate(s) of already-recovered content skipped).",
        carved_files,
        human_bytes(carved_bytes),
        carved_dups
    );

    if let Some(report_path) = &args.report {
        write_recover_report(report_path, &report_rows)?;
        eprintln!("Report written to {}", report_path.display());
    }
    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("recover".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("named_recovered", Sv::N(named_recovered)),
            ("named_bytes", Sv::N(named_bytes)),
            ("unallocated_only", Sv::B(args.unallocated)),
            ("carved_recovered", Sv::N(carved_files)),
            ("carved_bytes", Sv::N(carved_bytes)),
            ("carved_duplicates", Sv::N(carved_dups)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

/// Write the combined `recover` manifest as CSV, or JSON when the path ends in
/// `.json`. Each row records whether a file came from the undelete pass
/// (`named`) or carving (`carved`), its path relative to the output directory,
/// its size, and its SHA-256 — so `verify --base <OUTPUT>` can re-check it.
fn write_recover_report(
    path: &std::path::Path,
    rows: &[(&str, String, u64, String)],
) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, (kind, p, size, sha)) in rows.iter().enumerate() {
            let comma = if i + 1 < rows.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"kind\": \"{}\", \"path\": \"{}\", \"size\": {}, \"sha256\": \"{}\"}}{}\n",
                kind,
                json_escape(p),
                size,
                sha,
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("kind,path,size,sha256\n");
        for (kind, p, size, sha) in rows {
            out.push_str(&format!("{},{},{},{}\n", kind, csv_escape(p), size, sha));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

fn image(args: ImageArgs) -> Result<()> {
    use filerecovery::image::{self, ImageOptions};

    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );
    eprintln!("Image:  {}", args.output.display());

    // A map file enables resume; default it next to the image when --resume is
    // requested without an explicit --map.
    let map = args.map.clone().or_else(|| {
        if args.resume {
            let mut p = args.output.clone().into_os_string();
            p.push(".map");
            Some(p.into())
        } else {
            None
        }
    });

    let opts = ImageOptions {
        output: args.output.clone(),
        start: args.start,
        end: args.end,
        sparse: !args.no_sparse,
        sector_size: args.sector_size,
        map,
        resume: args.resume,
        retries: args.retry_bad,
    };

    let progress: Box<dyn ProgressSink> = if args.quiet {
        Box::new(carver::NoProgress)
    } else {
        Box::new(Bar::new())
    };

    let stats = image::image(&source, &opts, progress.as_ref())?;

    eprintln!();
    if stats.cancelled {
        println!("Cancelled.");
    }
    println!(
        "Done. Imaged {} ({} copied, {} sparse).",
        human_bytes(stats.bytes_total),
        human_bytes(stats.bytes_copied),
        human_bytes(stats.bytes_sparse),
    );
    if stats.retry_passes > 0 {
        println!(
            "Retried unreadable regions {} pass(es), salvaging {}.",
            stats.retry_passes,
            human_bytes(stats.bytes_recovered_retry)
        );
    }
    if !stats.bad_regions.is_empty() {
        println!(
            "WARNING: {} unreadable region(s), {} zero-filled:",
            stats.bad_regions.len(),
            human_bytes(stats.bytes_zeroed)
        );
        for r in stats.bad_regions.iter().take(20) {
            println!("  offset {} length {}", r.offset, human_bytes(r.len));
        }
        if stats.bad_regions.len() > 20 {
            println!("  ... and {} more", stats.bad_regions.len() - 20);
        }
    }

    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("image".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("sparse", Sv::B(!args.no_sparse)),
            ("sector_size", Sv::N(args.sector_size)),
            ("resume", Sv::B(args.resume)),
            ("retry_bad", Sv::N(args.retry_bad as u64)),
            ("bytes_total", Sv::N(stats.bytes_total)),
            ("bytes_copied", Sv::N(stats.bytes_copied)),
            ("bytes_sparse", Sv::N(stats.bytes_sparse)),
            ("bytes_zeroed", Sv::N(stats.bytes_zeroed)),
            ("retry_passes", Sv::N(stats.retry_passes as u64)),
            ("bytes_recovered_retry", Sv::N(stats.bytes_recovered_retry)),
            ("bad_regions", Sv::N(stats.bad_regions.len() as u64)),
            ("cancelled", Sv::B(stats.cancelled)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }

    if !stats.bad_regions.is_empty() {
        anyhow::bail!(
            "{} unreadable region(s) were zero-filled",
            stats.bad_regions.len()
        );
    }
    Ok(())
}

/// Seconds since the Unix epoch (0 if the clock is before it).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A value in a run summary.
enum Sv {
    S(String),
    N(u64),
    B(bool),
    /// A nested object of string -> number (e.g. the per-type breakdown).
    Map(Vec<(String, u64)>),
}

/// Write a run summary as JSON (when the path ends in `.json`) or plain text.
fn write_summary(path: &std::path::Path, fields: &[(&str, Sv)]) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("{\n");
        for (i, (k, v)) in fields.iter().enumerate() {
            let comma = if i + 1 < fields.len() { "," } else { "" };
            match v {
                Sv::S(s) => out.push_str(&format!("  \"{k}\": \"{}\"{comma}\n", json_escape(s))),
                Sv::N(n) => out.push_str(&format!("  \"{k}\": {n}{comma}\n")),
                Sv::B(b) => out.push_str(&format!("  \"{k}\": {b}{comma}\n")),
                Sv::Map(m) => {
                    if m.is_empty() {
                        out.push_str(&format!("  \"{k}\": {{}}{comma}\n"));
                    } else {
                        out.push_str(&format!("  \"{k}\": {{\n"));
                        for (j, (sk, sn)) in m.iter().enumerate() {
                            let c2 = if j + 1 < m.len() { "," } else { "" };
                            out.push_str(&format!("    \"{}\": {sn}{c2}\n", json_escape(sk)));
                        }
                        out.push_str(&format!("  }}{comma}\n"));
                    }
                }
            }
        }
        out.push_str("}\n");
    } else {
        for (k, v) in fields {
            match v {
                Sv::S(s) => out.push_str(&format!("{k}: {s}\n")),
                Sv::N(n) => out.push_str(&format!("{k}: {n}\n")),
                Sv::B(b) => out.push_str(&format!("{k}: {b}\n")),
                Sv::Map(m) => {
                    out.push_str(&format!("{k}:\n"));
                    for (sk, sn) in m {
                        out.push_str(&format!("  {sk}: {sn}\n"));
                    }
                }
            }
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing summary {}: {e}", path.display()))?;
    Ok(())
}

/// Write a recovery report as CSV, or JSON when the path ends in `.json`. The
/// `sha256` column is a forensic manifest: a verifiable digest of each
/// recovered file's contents (empty for skipped files and dry runs).
fn write_report(
    path: &std::path::Path,
    rows: &[(String, u64, String, u64, bool, String)],
) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, (fs, off, p, size, rec, sha)) in rows.iter().enumerate() {
            let comma = if i + 1 < rows.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"filesystem\": \"{}\", \"volume_offset\": {}, \"path\": \"{}\", \"size\": {}, \"recovered\": {}, \"sha256\": \"{}\"}}{}\n",
                json_escape(fs),
                off,
                json_escape(p),
                size,
                rec,
                sha,
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("filesystem,volume_offset,path,size,recovered,sha256\n");
        for (fs, off, p, size, rec, sha) in rows {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                fs,
                off,
                csv_escape(p),
                size,
                rec,
                sha
            ));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

/// Write a carve manifest as CSV, or JSON when the path ends in `.json`. Each
/// row records the output filename, type, source offset, size, and the SHA-256
/// of the carved bytes — so the report is a verifiable record of the run.
fn write_carve_report(path: &std::path::Path, files: &[carver::CarvedFile]) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, f) in files.iter().enumerate() {
            let comma = if i + 1 < files.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"name\": \"{}\", \"type\": \"{}\", \"offset\": {}, \"size\": {}, \"sha256\": \"{}\"}}{}\n",
                json_escape(&f.name),
                f.ext,
                f.offset,
                f.size,
                filerecovery::hash::to_hex(&f.sha256),
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("name,type,offset,size,sha256\n");
        for f in files {
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                csv_escape(&f.name),
                f.ext,
                f.offset,
                f.size,
                filerecovery::hash::to_hex(&f.sha256)
            ));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// indicatif-backed progress sink.
struct Bar {
    inner: ProgressBar,
}

impl Bar {
    fn new() -> Self {
        Bar {
            inner: ProgressBar::hidden(),
        }
    }
}

impl ProgressSink for Bar {
    fn begin(&self, total: u64) {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        // Replace the hidden bar with a live one.
        self.inner.set_length(total);
        self.inner.set_style(pb.style());
        self.inner
            .set_draw_target(indicatif::ProgressDrawTarget::stderr());
    }
    fn update(&self, scanned: u64) {
        self.inner.set_position(scanned);
    }
    fn finish(&self, scanned: u64) {
        self.inner.set_position(scanned);
        self.inner.finish_and_clear();
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}
