//! The simulator: one seed in, one report out.
//!
//! Everything nondeterministic is owned here and driven by the seed. Two runs
//! with the same configuration must produce byte-identical traces; that
//! equality is the exit criterion of stage 0.

use crate::shard::{Msg, Shard};
use trailryx_sim::{
    Bus, BusFaults, BusStats, IoFaults, IoStats, Parts, Rng, RngExt, ShardId, SimBus, SimClock,
    SimIo, SimRng, Trace, trace,
};

#[derive(Debug, Clone, Copy)]
pub struct SimConfig {
    pub seed: u64,
    pub shards: u16,
    pub steps: u64,
    pub sync_every: u64,
    pub io_faults: IoFaults,
    pub bus_faults: BusFaults,
    /// Chance per step of a power cut, in parts per million.
    pub crash_ppm: u32,
    /// Crash at exactly this step, in addition to any random crashes.
    pub crash_at: Option<u64>,
    pub trace_cap_bytes: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            shards: 2,
            steps: 1_000,
            sync_every: 8,
            io_faults: IoFaults::NONE,
            bus_faults: BusFaults::NONE,
            crash_ppm: 0,
            crash_at: None,
            trace_cap_bytes: 4 << 20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub seed: u64,
    pub steps: u64,
    pub trace_digest: u64,
    pub trace_lines: u64,
    pub trace_bytes: Vec<u8>,
    pub crashes: u64,
    /// Acked data that did not survive a crash. With an honest disk this must
    /// be zero; anything else is a bug in the write path.
    pub durability_violations: u64,
    pub acked_total: u64,
    pub written_total: u64,
    pub pongs_total: u64,
    pub io: IoStats,
    pub bus: BusStats,
}

impl Report {
    pub fn digest_hex(&self) -> String {
        format!("{:016x}", self.trace_digest)
    }

    pub fn summary(&self) -> String {
        format!(
            "seed={} steps={} digest={} lines={} crashes={} violations={} acked={} written={} \
             pongs={} short_writes={} lying_fsyncs={} fsync_errors={} nospace={} \
             msgs_sent={} delivered={} dropped={}",
            self.seed,
            self.steps,
            self.digest_hex(),
            self.trace_lines,
            self.crashes,
            self.durability_violations,
            self.acked_total,
            self.written_total,
            self.pongs_total,
            self.io.short_writes,
            self.io.lying_fsyncs,
            self.io.fsync_errors,
            self.io.no_space,
            self.bus.sent,
            self.bus.delivered,
            self.bus.dropped,
        )
    }
}

/// Run one simulation. Same config, same result, always.
pub fn run(cfg: SimConfig) -> Report {
    // Each subsystem gets its own stream derived from the seed, so adding a
    // random draw in one of them cannot shift the others.
    let mut master = SimRng::new(cfg.seed);
    let mut rng = master.fork();
    let mut io = SimIo::new(master.next_u64(), cfg.io_faults);
    let mut bus: SimBus<Msg> = SimBus::new(master.next_u64(), cfg.bus_faults);
    let mut clock = SimClock::new(1_800_000_000_000_000_000);
    let mut trace = Trace::new(cfg.trace_cap_bytes);

    let ids: Vec<ShardId> = (0..cfg.shards).map(ShardId).collect();

    let mut shards: Vec<Shard> = Vec::with_capacity(cfg.shards as usize);
    for &id in &ids {
        let mut p = Parts {
            clock: &clock,
            rng: &mut rng,
            io: &mut io,
            bus: &mut bus,
            trace: &mut trace,
        };
        let s = Shard::open(id, cfg.sync_every, &mut p).expect("open shard");
        shards.push(s);
    }

    let mut crashes = 0u64;
    let mut violations = 0u64;

    for step in 1..=cfg.steps {
        clock.advance(1_000_000); // one millisecond per step
        bus.tick();

        // Which shard runs is a seeded choice, not the OS scheduler's.
        let which = rng.below(u64::from(cfg.shards)) as usize;
        let peers: Vec<ShardId> = ids.iter().copied().filter(|&i| i != ids[which]).collect();

        {
            let mut p = Parts {
                clock: &clock,
                rng: &mut rng,
                io: &mut io,
                bus: &mut bus,
                trace: &mut trace,
            };
            if let Err(e) = shards[which].tick(&peers, &mut p) {
                trace!(p.trace, "tickerr", "{} err={}", ids[which], e);
            }
        }

        // Deliver whatever is due for that shard.
        loop {
            let next = bus.recv(ids[which]);
            let Some((from, msg)) = next else { break };
            let mut p = Parts {
                clock: &clock,
                rng: &mut rng,
                io: &mut io,
                bus: &mut bus,
                trace: &mut trace,
            };
            shards[which].on_msg(from, msg, &mut p);
        }

        let crash_now =
            cfg.crash_at == Some(step) || (cfg.crash_ppm > 0 && rng.chance_ppm(cfg.crash_ppm));

        if crash_now {
            crashes += 1;
            let promised: Vec<u64> = shards.iter().map(Shard::acked).collect();
            trace!(trace, "crash", "step={} promised={:?}", step, promised);

            io.crash();
            bus.clear();

            for (i, s) in shards.iter_mut().enumerate() {
                let mut p = Parts {
                    clock: &clock,
                    rng: &mut rng,
                    io: &mut io,
                    bus: &mut bus,
                    trace: &mut trace,
                };
                let r = s.recover(&mut p).expect("recover");
                s.note_recovery();

                // The whole contract, checked in one line.
                if r.max_seq < promised[i] {
                    violations += 1;
                    trace!(
                        p.trace,
                        "VIOLATION", "{} promised={} recovered={}", ids[i], promised[i], r.max_seq
                    );
                } else {
                    trace!(
                        p.trace,
                        "recovered",
                        "{} promised={} recovered={} discarded={}",
                        ids[i],
                        promised[i],
                        r.max_seq,
                        r.discarded_bytes
                    );
                }
            }
        }
    }

    Report {
        seed: cfg.seed,
        steps: cfg.steps,
        trace_digest: trace.digest(),
        trace_lines: trace.lines(),
        trace_bytes: trace.bytes().to_vec(),
        crashes,
        durability_violations: violations,
        acked_total: shards.iter().map(Shard::acked).sum(),
        written_total: shards.iter().map(Shard::written).sum(),
        pongs_total: shards.iter().map(Shard::pongs_seen).sum(),
        io: io.stats,
        bus: bus.stats,
    }
}
