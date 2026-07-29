//! The exit criteria of stage 0, as tests.
//!
//! 1. A seed reproduces a run byte for byte.
//! 2. Different seeds explore different runs.
//! 3. With an honest disk, nothing acked is ever lost, across many seeds,
//!    with crashes injected at every step.
//! 4. When the disk lies about `fsync`, the harness notices.

use trailryx_core::sim::{SimConfig, run};
use trailryx_sim::{BusFaults, IoFaults};

fn hostile(seed: u64) -> SimConfig {
    SimConfig {
        seed,
        shards: 3,
        steps: 600,
        sync_every: 5,
        io_faults: IoFaults {
            // An unreliable disk, but an honest one: it never claims a sync
            // happened when it did not.
            lying_fsync_ppm: 0,
            ..IoFaults::HOSTILE
        },
        bus_faults: BusFaults::HOSTILE,
        crash_ppm: 8_000,
        crash_at: None,
        trace_cap_bytes: 8 << 20,
    }
}

#[test]
fn same_seed_produces_byte_identical_trace() {
    for seed in [1u64, 7, 12345, u64::MAX / 3] {
        let a = run(hostile(seed));
        let b = run(hostile(seed));
        assert_eq!(
            a.trace_bytes, b.trace_bytes,
            "trace diverged for seed {seed}"
        );
        assert_eq!(a.trace_digest, b.trace_digest);
        assert_eq!(a.trace_lines, b.trace_lines);
        assert_eq!(a.crashes, b.crashes);
        assert_eq!(a.acked_total, b.acked_total);
        assert_eq!(a.io, b.io);
        assert_eq!(a.bus, b.bus);
    }
}

#[test]
fn different_seeds_explore_different_runs() {
    let a = run(hostile(1));
    let b = run(hostile(2));
    assert_ne!(a.trace_digest, b.trace_digest);
}

#[test]
fn a_run_actually_exercises_the_faults() {
    // A test that passes because nothing happened is worthless.
    let r = run(hostile(99));
    assert!(r.crashes > 0, "no crashes were injected");
    assert!(r.io.short_writes > 0, "no short writes happened");
    assert!(r.io.fsync_errors > 0, "no sync failures happened");
    assert!(r.bus.dropped > 0, "no messages were dropped");
    assert!(r.acked_total > 0, "nothing was ever acked");
}

#[test]
fn honest_disk_never_loses_acked_data() {
    // Many seeds, crashes throughout, an unreliable but honest disk.
    for seed in 0..300u64 {
        let r = run(hostile(seed));
        assert_eq!(
            r.durability_violations,
            0,
            "acked data lost with an honest disk, seed {seed}\n{}",
            r.summary()
        );
    }
}

#[test]
fn crash_at_every_single_step_is_survivable() {
    // Walk the crash point across the whole run rather than sampling it.
    for step in 1..=120u64 {
        let cfg = SimConfig {
            seed: 4242,
            shards: 2,
            steps: 150,
            sync_every: 4,
            io_faults: IoFaults {
                lying_fsync_ppm: 0,
                ..IoFaults::HOSTILE
            },
            bus_faults: BusFaults::HOSTILE,
            crash_ppm: 0,
            crash_at: Some(step),
            trace_cap_bytes: 1 << 20,
        };
        let r = run(cfg);
        assert_eq!(r.crashes, 1);
        assert_eq!(
            r.durability_violations,
            0,
            "crash at step {step} lost acked data\n{}",
            r.summary()
        );
    }
}

#[test]
fn the_harness_catches_a_lying_fsync() {
    // A disk that reports success without flushing is the classic write hole.
    // We cannot defend against it, but the harness must see it. If this test
    // stops failing to find violations, the crash model has gone soft.
    let mut found = 0;
    for seed in 0..200u64 {
        let cfg = SimConfig {
            seed,
            shards: 2,
            steps: 300,
            sync_every: 3,
            io_faults: IoFaults {
                lying_fsync_ppm: 300_000,
                short_write_ppm: 0,
                fsync_error_ppm: 0,
                no_space_ppm: 0,
            },
            bus_faults: BusFaults::NONE,
            crash_ppm: 20_000,
            crash_at: None,
            trace_cap_bytes: 1 << 20,
        };
        if run(cfg).durability_violations > 0 {
            found += 1;
        }
    }
    assert!(
        found > 0,
        "the simulator never noticed a lying fsync: the crash model is too gentle"
    );
}

/// Regression, found by the simulator on the first hostile run.
///
/// A refused write in the middle of a record used to leave orphaned bytes in
/// the stream, and the next tick started a *new* record after them. Recovery
/// stops at the first thing that does not verify, so everything written after
/// the orphan became unreachable while the acked watermark kept climbing:
/// promised 13, recovered 3.
#[test]
fn a_refused_write_mid_record_does_not_break_the_stream() {
    for seed in 0..400u64 {
        let cfg = SimConfig {
            seed,
            shards: 2,
            steps: 400,
            sync_every: 3,
            io_faults: IoFaults {
                no_space_ppm: 250_000,
                short_write_ppm: 250_000,
                lying_fsync_ppm: 0,
                fsync_error_ppm: 0,
            },
            bus_faults: BusFaults::NONE,
            crash_ppm: 15_000,
            crash_at: None,
            trace_cap_bytes: 1 << 20,
        };
        let r = run(cfg);
        assert_eq!(
            r.durability_violations,
            0,
            "stream broken by a refused write, seed {seed}\n{}",
            r.summary()
        );
    }
}

/// A journal that survives one crash must still be usable after it. If the torn
/// tail were left in place, every later recovery would stop at the same offset
/// and the store would be frozen while pretending to accept writes.
#[test]
fn a_journal_keeps_growing_across_repeated_crashes() {
    let cfg = SimConfig {
        seed: 31337,
        shards: 1,
        steps: 900,
        sync_every: 4,
        io_faults: IoFaults {
            lying_fsync_ppm: 0,
            ..IoFaults::HOSTILE
        },
        bus_faults: BusFaults::NONE,
        crash_ppm: 25_000,
        crash_at: None,
        trace_cap_bytes: 1 << 20,
    };
    let r = run(cfg);
    assert!(
        r.crashes >= 5,
        "expected repeated crashes, got {}",
        r.crashes
    );
    assert_eq!(r.durability_violations, 0, "{}", r.summary());
    // The real point: progress continued after the crashes rather than stalling
    // at whatever offset the first torn tail sat on.
    assert!(
        r.acked_total > 50,
        "journal stopped making progress after a crash: {}",
        r.summary()
    );
}

#[test]
fn no_shards_and_no_steps_are_not_special_cases() {
    let r = run(SimConfig {
        shards: 1,
        steps: 0,
        ..SimConfig::default()
    });
    assert_eq!(r.acked_total, 0);
    assert_eq!(r.durability_violations, 0);
}
