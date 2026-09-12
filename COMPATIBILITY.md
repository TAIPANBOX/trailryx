# Compatibility

`TAIPANBOX/trailryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: proposed: this repository is at 0.x (v0.1.2), and the surface named here is what its 1.0 will freeze; the gate holds it from today so that 1.0 is a tag and not a rewrite

## Frozen

### agentevent.consumed (8)

- `delegation_proof`
- `schema`
- `ts`
- `type`
- `severity`
- `agent_id`
- `run_id`
- `on_behalf_of`
- held in: `crates/trailryx-agentevent/src/lib.rs`

### agentevent.schemas (3)

- `taipanbox.dev/agent-event/v0.1`
- `taipanbox.dev/agent-event/v0.2`
- `taipanbox.dev/agent-event/v0.3`
- held in: `crates/trailryx-agentevent/src/lib.rs`

### cli.binaries (10)

- `fed-probe`
- `trailryx-coverage`
- `trailryx-demo`
- `trailryx-ingest`
- `trailryx-jsonl`
- `trailryx-kill`
- `trailryx-node`
- `trailryx-rate`
- `trailryx-sim-run`
- `trailryx-verify`
- held in: `components.json`

### cli.routines (2)

- `trailryx-seal`
- `record-seal`
- held in: `components.json`

### cli.subcommands (3)

- `run`
- `read`
- `events`
- held in: `crates/trailryx-node/src/main.rs`

### env (15)

- `TRAILRYX_S3_ADDRESSING`
- `TRAILRYX_S3_BUCKET`
- `TRAILRYX_S3_ENDPOINT`
- `TRAILRYX_S3_KEY`
- `TRAILRYX_S3_REGION`
- `TRAILRYX_S3_SECRET`
- `TRAILRYX_AZURE_ACCOUNT`
- `TRAILRYX_AZURE_CONTAINER`
- `TRAILRYX_AZURE_ENDPOINT`
- `TRAILRYX_AZURE_KEY`
- `TRAILRYX_DEMO_STORE`
- `TRAILRYX_FUZZ_CASES`
- `TRAILRYX_PYTHON`
- `TRAILRYX_PARQUET_ORACLE`
- `TRAILRYX_FIPS_REQUIRED=1`
- held in: `components.json`, `crates/trailryx-fuzz/tests/parsers.rs`, `crates/trailryx-otlp/tests/jsonenc_is_otlp_json.rs`, `crates/trailryx-projection/tests/oracle.rs`, `.github/workflows/ci.yml`

### http.routes (1)

- `/v1/traces`
- held in: `crates/trailryx-ingest/src/handler.rs`

### journal.wire (2)

- `FRAME_MAGIC: u8=0xA7`
- `FORMAT_VERSION: u16=1`
- held in: `crates/trailryx-journal/src/wire.rs`

## Additive within a major

- a new dev-tool binary, or a new TRAILRYX_ environment name behind a new adapter
- the agent-event schema version this reader accepts, which moves in its own release (agent-passport SPEC 6.2/6.4) rather than this repository's
- the journal's FRAME_VERSION and OLDEST_FRAME_VERSION: invariant 7 requires a field change to be a new frame version plus a reader-side migration rather than a rewrite of what is frozen here, so those two are expected to move and are deliberately not frozen
- a new EventType wire code, appended under invariant 36 and never renumbered
- a new agent-event type this mapper newly accepts (crates/trailryx-agentevent), the way identity_finding and alert_sent were added

## Experimental

- trailryx-sql, the Postgres wire facade: built and tested, wired into no shipped binary yet (section 9 of the service dossier)
- the OTLP GenAI semantic-convention mapper's attribute coverage (crates/trailryx-otlp/src/semconv.rs): the upstream convention is still development-status and its names can change

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
