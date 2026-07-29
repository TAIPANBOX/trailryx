//! One command to reproduce any run.
//!
//!     trailryx-sim-run --seed 42 --steps 5000 --hostile --crash-ppm 3000
//!
//! Print the trace of a failing seed with `--trace`, and the same seed will
//! print the same bytes on any machine.

use trailryx_core::sim::{SimConfig, run};
use trailryx_sim::{BusFaults, IoFaults};

fn main() {
    let mut cfg = SimConfig::default();
    let mut show_trace = false;
    let mut sweep = 0u64;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_default()
        };
        match a {
            "--seed" => cfg.seed = next(&mut i).parse().unwrap_or(1),
            "--steps" => cfg.steps = next(&mut i).parse().unwrap_or(1_000),
            "--shards" => cfg.shards = next(&mut i).parse().unwrap_or(2),
            "--sync-every" => cfg.sync_every = next(&mut i).parse().unwrap_or(8),
            "--crash-ppm" => cfg.crash_ppm = next(&mut i).parse().unwrap_or(0),
            "--crash-at" => cfg.crash_at = next(&mut i).parse().ok(),
            "--sweep" => sweep = next(&mut i).parse().unwrap_or(0),
            "--hostile" => {
                cfg.io_faults = IoFaults::HOSTILE;
                cfg.bus_faults = BusFaults::HOSTILE;
            }
            "--honest-disk" => cfg.io_faults.lying_fsync_ppm = 0,
            "--trace" => show_trace = true,
            "--help" | "-h" => {
                println!(
                    "trailryx-sim-run [--seed N] [--steps N] [--shards N] [--sync-every N]\n\
                     \x20                [--crash-ppm N] [--crash-at N] [--hostile] [--honest-disk]\n\
                     \x20                [--sweep N] [--trace]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if sweep > 0 {
        let base = cfg.seed;
        let mut failures = 0u64;
        for k in 0..sweep {
            let mut c = cfg;
            c.seed = base.wrapping_add(k);
            let r = run(c);
            if r.durability_violations > 0 {
                failures += 1;
                println!("FAIL {}", r.summary());
            }
        }
        println!("sweep of {sweep} seeds from {base}: {} failing", failures);
        if failures > 0 {
            std::process::exit(1);
        }
        return;
    }

    let r = run(cfg);
    println!("{}", r.summary());
    if show_trace {
        println!("--- trace ---");
        print!("{}", String::from_utf8_lossy(&r.trace_bytes));
    }
    if r.durability_violations > 0 {
        std::process::exit(1);
    }
}
