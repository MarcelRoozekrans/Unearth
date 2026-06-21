//! `filerecovery` command-line entry point.

mod cli;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Command, ScanArgs, UndeleteArgs};
use filerecovery::carver::{self, CarveOptions, ProgressSink};
use filerecovery::fat;
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
    }
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
        Some(off) => vec![fat::Volume::parse(&source, off)?],
        None => fat::detect_volumes(&source)?,
    };
    eprintln!("Found {} FAT volume(s).", volumes.len());

    std::fs::create_dir_all(&args.output)
        .map_err(|e| anyhow::anyhow!("creating output dir {}: {e}", args.output.display()))?;

    let mut total_recovered = 0u64;
    let mut total_bytes = 0u64;
    let mut total_skipped = 0u64;
    for (i, vol) in volumes.iter().enumerate() {
        // Keep each volume's output separate to avoid path collisions.
        let out = if volumes.len() > 1 {
            args.output.join(format!("volume_{i}"))
        } else {
            args.output.clone()
        };
        eprintln!(
            "Volume {i}: {:?} at offset {} -> {}",
            vol.fat_type,
            vol.offset,
            out.display()
        );
        let stats = vol.recover_deleted(&source, &out, args.min_size)?;
        total_recovered += stats.recovered;
        total_bytes += stats.bytes_recovered;
        total_skipped += stats.skipped;
    }

    eprintln!();
    println!(
        "Done. Recovered {} deleted file(s), {} ({} skipped as unrecoverable).",
        total_recovered,
        human_bytes(total_bytes),
        total_skipped
    );
    Ok(())
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
