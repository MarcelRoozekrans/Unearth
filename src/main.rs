//! `filerecovery` command-line entry point.

mod cli;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Command, InfoArgs, ScanArgs, UndeleteArgs};
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
        Command::Info(args) => info(args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let source = Source::open(&args.source)?;
    println!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    let volumes = match recover::detect(&source) {
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
        let deleted = if args.deleted {
            let opts = recover::RecoverOptions {
                min_size: 0,
                dry_run: true,
            };
            match vol.recover_deleted(&source, std::path::Path::new("."), &opts) {
                Ok(stats) => stats.recovered.to_string(),
                Err(_) => "?".to_string(),
            }
        } else {
            "-".to_string()
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

    let opts = CarveOptions {
        output_dir: args.output,
        start: args.start,
        end: args.end,
        min_size: args.min_size,
        max_files: args.max_files,
        allow_nested: args.allow_nested,
        validate: !args.no_validate,
        progress: !args.quiet,
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
    Ok(())
}

fn undelete(args: UndeleteArgs) -> Result<()> {
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
    // Report rows: (filesystem, volume offset, relative path, size, recovered).
    let mut report_rows: Vec<(String, u64, String, u64, bool)> = Vec::new();

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
            report_rows.push((
                label.clone(),
                offset,
                f.path.to_string_lossy().into_owned(),
                f.size,
                f.recovered,
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
    Ok(())
}

/// Write a recovery report as CSV, or JSON when the path ends in `.json`.
fn write_report(path: &std::path::Path, rows: &[(String, u64, String, u64, bool)]) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, (fs, off, p, size, rec)) in rows.iter().enumerate() {
            let comma = if i + 1 < rows.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"filesystem\": \"{}\", \"volume_offset\": {}, \"path\": \"{}\", \"size\": {}, \"recovered\": {}}}{}\n",
                json_escape(fs),
                off,
                json_escape(p),
                size,
                rec,
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("filesystem,volume_offset,path,size,recovered\n");
        for (fs, off, p, size, rec) in rows {
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                fs,
                off,
                csv_escape(p),
                size,
                rec
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
