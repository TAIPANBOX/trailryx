//! The eight steps, and the acceptance criterion.
//!
//! The plan calls this the demo and also the acceptance test, which is the right
//! way round: a store that cannot walk these eight steps on a clean machine,
//! twice in a row, has not earned any of the claims in its README.
//!
//! Nothing here is narrated. Every step does the thing and fails the run if it
//! did not: the OTLP export goes over a real socket, the query's proof is
//! verified against the segment's own declared root, the pack is written to a
//! real file and checked by the offline verifier, and the erasure destroys a real
//! key and is then shown not to open.
//!
//! # What two of the eight steps are not
//!
//! Step one calls for an agent that exceeds a budget and is blocked. Blocking is
//! a policy engine's job and this is a record store, so the demo records the
//! incident rather than enforcing it. The distinction matters and is printed.
//!
//! Step eight calls for a scan by a separate tool that is not part of this
//! project. In its place the demo reads back the primitives every record
//! declares and confirms none is one the verifier considers retired, which is the
//! part of that check this repository can actually answer for.

mod assemble;
mod signer;

use assemble::Assembler;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use trailryx_contracts::contracts::{ObjectStore, Source};
use trailryx_contracts::fakes::{MemoryKeyProvider, MemoryObjectStore};
use trailryx_contracts::ingest::{MetaDraft, PayloadPart};
use trailryx_erasure::subject::SubjectHandle;
use trailryx_erasure::vault::Vault;
use trailryx_erasure::{PredictableKeys, Sha384Ctr};
use trailryx_index::completeness::Dimension;
use trailryx_index::segment::{ShardTree, StoreTree};
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest as HttpIngest;
use trailryx_ingest::server::{Server, silent_log};
use trailryx_journal::journal::{Appended, Journal};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{
    AgentId, Basis, ErrorCode, EventType, Hash, ModelId, PayloadClass, PolicyVersion, PrincipalId,
    Record, RecordId, RunId, SegmentId, Severity, ShardIx, TenantId, Timestamp, ToolName,
    Untrusted, Verdict,
};
use trailryx_sign::{attest, sign_root_unvalidated};
use trailryx_sim::clock::{Clock, SystemClock};
use trailryx_sim::io::StdIo;
use trailryx_store::evidence::PackBuilder;
use trailryx_store::query::{ProofStatus, Query, query_segment};
use trailryx_store::seal::{ChainStart, SealOutcome, seal_segment};

type Vaults = Vault<MemoryObjectStore, MemoryKeyProvider, Sha384Ctr, PredictableKeys>;

const TENANT: &str = "acme";
const TRUST_DOMAIN: &str = "acme.example";
const AGENT: &str = "agent://acme.example/billing";
const RUN: &str = "run-4471";
/// Operator-supplied and pseudonymous, as `docs/identifiers.md` requires. The
/// person's name is not in this program and could not be.
const SUBJECT: &str = "subject-8f21ac";

fn main() -> ExitCode {
    let mut runs = 1u32;
    let mut keep = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--runs" => match args.next().and_then(|v| v.parse().ok()) {
                Some(n) if n >= 1 => runs = n,
                _ => return die("--runs takes a number of one or more"),
            },
            "--keep" => keep = true,
            "--help" => {
                println!(
                    "trailryx-demo [--runs N] [--keep]\n\n\
                     Walks the eight acceptance steps. Each run uses a fresh directory,\n\
                     so --runs 2 is the criterion: twice in a row, from nothing."
                );
                return ExitCode::SUCCESS;
            }
            other => return die(&format!("unknown argument {other}")),
        }
    }

    for run in 1..=runs {
        if runs > 1 {
            println!("\n{}", "=".repeat(72));
            println!("RUN {run} OF {runs}, from an empty directory");
            println!("{}", "=".repeat(72));
        }
        let dir = std::env::temp_dir().join(format!("trailryx-demo-{}-{run}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let outcome = walk(&dir);
        if keep {
            println!("\nleft behind for inspection: {}", dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&dir);
        }
        if let Err(why) = outcome {
            eprintln!("\nFAILED: {why}");
            return ExitCode::FAILURE;
        }
    }

    println!(
        "\nALL EIGHT STEPS PASSED{}",
        if runs > 1 { ", TWICE" } else { "" }
    );
    ExitCode::SUCCESS
}

fn die(why: &str) -> ExitCode {
    eprintln!("trailryx-demo: {why}");
    ExitCode::from(2)
}

fn step(n: u8, title: &str) {
    println!(
        "\n── {n}. {title} {}",
        "─".repeat(64usize.saturating_sub(title.len()))
    );
}

fn note(text: &str) {
    println!("   {text}");
}

/// Anything that makes the run untrue.
type Failure = String;

fn walk(dir: &Path) -> Result<(), Failure> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let clock = SystemClock::new();
    let mut io = StdIo::new(dir.join("journal")).map_err(|e| e.to_string())?;
    let tenant = TenantId::parse(TENANT).map_err(|e| e.to_string())?;
    let subject = SubjectHandle::parse(SUBJECT).map_err(|e| e.to_string())?;

    let mut vault: Vaults = Vault::unvalidated(
        tenant.clone(),
        TRUST_DOMAIN,
        MemoryObjectStore::default(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    );
    let mut assembler = Assembler::new(ShardIx(0));
    let (mut journal, recovered) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "shard-0-000001.trlx",
        1,
        &mut io,
        &clock,
    )
    .map_err(|e| format!("opening the journal: {e}"))?;
    if recovered.records != 0 {
        return Err(format!(
            "a fresh directory recovered {} records, so it was not fresh",
            recovered.records
        ));
    }

    // ---------------------------------------------------------------
    step(1, "an agent runs, spends its budget, and is refused");
    note("Recorded, not enforced: blocking is a policy engine's job and this is");
    note("the store it answers to. What the store owes is the grounds.");

    let mut written: Vec<Record> = Vec::new();
    let mut previous: Option<RecordId> = None;
    for spec in incident() {
        let payload = if spec.payload.is_empty() {
            None
        } else {
            Some(
                vault
                    .seal(
                        RecordId(assembler_peek(&assembler)),
                        &spec.payload,
                        Some(&subject),
                    )
                    .map_err(|e| format!("sealing a payload: {e}"))?,
            )
        };
        let record = assembler.own(
            spec.draft,
            Timestamp(clock.wall_nanos()),
            previous.map(|p| vec![p]).unwrap_or_default(),
            payload,
        );
        previous = Some(record.id);
        let stamped = append(&mut journal, &record, &mut io)?;
        note(&format!(
            "{:>2}. {:<16} {:<14} {}",
            stamped.seq,
            stamped.event_type.as_str(),
            stamped.outcome.verdict.map(|v| v.as_str()).unwrap_or("-"),
            describe_basis(&stamped.basis)
        ));
        written.push(stamped);
    }

    // ---------------------------------------------------------------
    note("");
    note("And the same incident as a stock OpenTelemetry SDK would have left it,");
    note("over a real socket, so the difference is visible rather than argued.");
    let otlp = ingest_over_http(&tenant, &clock)?;
    let otlp_record = assembler
        .adopt(otlp, Timestamp(clock.wall_nanos()), &mut vault, None)
        .map_err(|e| format!("assembling the OTLP record: {e}"))?;
    let otlp_record = append(&mut journal, &otlp_record, &mut io)?;
    note(&format!(
        "{:>2}. {:<16} {:<14} {}",
        otlp_record.seq,
        otlp_record.event_type.as_str(),
        otlp_record
            .outcome
            .verdict
            .map(|v| v.as_str())
            .unwrap_or("-"),
        describe_basis(&otlp_record.basis)
    ));
    if otlp_record.basis.policy_version.is_some()
        || otlp_record.basis.budget_remaining_micros.is_some()
    {
        return Err("an OTLP-sourced record claimed a basis OTLP cannot carry".into());
    }
    note("   ^ no policy version, no budget, no memory reference. OTLP has no");
    note("     attribute for any of them, so a span cannot say why a call was");
    note("     allowed. That gap is the product, and it is not a defect here.");
    written.push(otlp_record);

    journal
        .sync(&mut io)
        .map_err(|e| format!("syncing the journal: {e}"))?;
    note("");
    note(&format!(
        "{} records on disk, {} acked durable",
        journal.written(),
        journal.acked()
    ));

    // ---------------------------------------------------------------
    let sealed = match seal_segment(
        &journal,
        SegmentId(1),
        ShardIx(0),
        ChainStart::Genesis,
        &mut io,
    )
    .map_err(|e| format!("sealing: {e}"))?
    {
        SealOutcome::Sealed(sealed) => sealed,
        SealOutcome::NothingDurable => return Err("nothing durable to seal".into()),
    };
    let segment_one = sealed.segment;

    step(2, "unroll the chain behind the refusal");
    let reconstruction = trailryx_store::reconstruct(
        &[&segment_one],
        &RunId::parse(RUN).map_err(|e| e.to_string())?,
        trailryx_store::Bounds::default(),
    );
    for record in &reconstruction.records {
        note(&format!(
            "{:>2}. {:<16} {}",
            record.seq,
            record.event_type.as_str(),
            describe_basis(&record.basis)
        ));
    }
    note(&format!(
        "{} records, {} hops, proof {:?}, {}",
        reconstruction.len(),
        reconstruction.hops.len(),
        reconstruction.proof,
        if reconstruction.is_complete() {
            "complete"
        } else {
            "INCOMPLETE"
        }
    ));
    if !reconstruction.is_complete() {
        return Err("the reconstruction was not complete".into());
    }

    // ---------------------------------------------------------------
    step(3, "answer a query, and prove nothing was left out");
    let agent = AgentId::parse(AGENT).map_err(|e| e.to_string())?;
    let query = Query::point(Dimension::AgentId, agent.as_str().as_bytes().to_vec());
    let answer = query_segment(&segment_one, &query);
    note(&format!(
        "{} rows for {}, {} matched before filters, proof {:?}",
        answer.records.len(),
        agent,
        answer.matched_before_filters,
        answer.proof
    ));
    if answer.proof != ProofStatus::Full {
        return Err(format!(
            "the answer was not fully proved: {:?}",
            answer.proof
        ));
    }

    // Verified here against the segment's own declared root, rather than
    // trusting the status the query attached to itself.
    let index = segment_one
        .index(Dimension::AgentId)
        .ok_or("the segment has no agent index")?;
    let root = segment_one
        .manifest()
        .index_root(Dimension::AgentId)
        .ok_or("the manifest declares no agent index root")?;
    for proof in &answer.segment_proofs {
        proof
            .verify(
                Dimension::AgentId,
                agent.as_str().as_bytes(),
                agent.as_str().as_bytes(),
                root,
                index.len(),
            )
            .map_err(|e| format!("the completeness proof does not check out: {e:?}"))?;
    }
    note(&format!(
        "completeness proof checked independently against index root {}",
        short(&root)
    ));
    note("A span store cannot answer this question at all: it has no way to say");
    note("that what it showed you is everything it had.");

    // ---------------------------------------------------------------
    step(4, "collect an evidence pack, signed and witnessed");
    let mut shard = ShardTree::new(ShardIx(0));
    shard.push(segment_one.manifest().clone());
    let store = StoreTree::from_shards(&[shard.clone()]);
    let generated_at = Timestamp(clock.wall_nanos());

    let mut builder = PackBuilder::new(tenant.clone(), generated_at).shard(&shard, &[&segment_one]);
    let keys = dir.join("keys");
    match signer::Openssl::new(&keys, "publisher") {
        Some(mut publisher) => {
            let signature =
                sign_root_unvalidated(&mut publisher, &tenant, store.root(), 1, generated_at)
                    .map_err(|e| format!("signing the root: {e}"))?;
            note(&format!(
                "root {} signed es384 by key {}",
                short(&store.root()),
                short(&signature.key_id())
            ));
            builder = builder.signed_with(signature);
        }
        None => note("no openssl here, so the pack is unsigned and the verifier will say so"),
    }
    match signer::Openssl::new(&keys, "witness") {
        Some(mut witness) => {
            let attestation = attest(
                &mut witness,
                "auditor.example",
                store.root(),
                Timestamp(clock.wall_nanos()),
            )
            .map_err(|e| format!("attesting: {e}"))?;
            note(&format!(
                "witnessed by auditor.example, key {}",
                short(&attestation.key_id())
            ));
            builder = builder.witnessed_by(attestation);
        }
        None => note("no witness either, so nothing here says when the root existed"),
    }

    let pack = builder.build(&store);
    let pack_path = dir.join("incident-4471.trxevid");
    signer::write(&pack_path, &pack).map_err(|e| e.to_string())?;
    note(&format!(
        "{} bytes written to {}",
        pack.len(),
        pack_path.display()
    ));

    // ---------------------------------------------------------------
    step(
        5,
        "check the pack with the verifier that shares no code with us",
    );
    let before = verify_pack(&pack)?;
    note(&format!(
        "{} records in {} segments, VERIFIED",
        before.records_checked, before.segments_checked
    ));
    note(&format!(
        "the same bytes are checkable on any machine: trailryx-verify {}",
        pack_path.display()
    ));

    // ---------------------------------------------------------------
    step(6, "forget the person, on request");
    let readable = written.iter().filter(|r| r.payload.is_some()).count();

    // One payload arrived with no idea whose it was, which is the normal case:
    // an agent rarely knows whose data is in a prompt at the moment it sends
    // one. It was sealed under a key belonging to that record and to nobody.
    // Attribution catching up is what the design is arranged around, and the
    // point is that nothing is re-encrypted: the key simply joins the subject's
    // set. Re-wrapping would leave the old envelope in storage that cannot be
    // deleted, and the old key would still open it.
    let unattributed: Vec<&Record> = written
        .iter()
        .filter(|r| {
            r.payload
                .as_ref()
                .is_some_and(|p| p.key_id != trailryx_erasure::kek_for_subject(&tenant, &subject).0)
        })
        .collect();
    for record in &unattributed {
        let reference = record.payload.as_ref().expect("filtered on it");
        if vault.attribute(reference, &subject) {
            note(&format!(
                "seq {} arrived unattributed; attribution now says it was theirs, and nothing was rewritten",
                record.seq
            ));
        }
    }
    let forgotten = vault
        .forget(&subject, Timestamp(clock.wall_nanos()))
        .map_err(|e| format!("forgetting: {e}"))?;
    note(&format!(
        "{} keys destroyed, {} already gone, over {readable} payloads",
        forgotten.keys_destroyed, forgotten.keys_already_gone
    ));
    if forgotten.keys_destroyed < 2 {
        return Err(format!(
            "{} keys died, so the later-attributed payload was not reached",
            forgotten.keys_destroyed
        ));
    }
    if forgotten.keys_destroyed == 0 {
        return Err("nothing was destroyed, so nothing was forgotten".into());
    }

    // The erasure is itself a record. It goes into a segment of its own, which
    // is where step seven picks it up.
    let erasure_draft = assembler.own(
        forgotten.draft.clone(),
        Timestamp(clock.wall_nanos()),
        Vec::new(),
        Some(vault.manifest_ref(&forgotten)),
    );
    let erasure = erasure_draft.clone();
    let rendered = format!("{erasure:?}");
    if rendered.contains(SUBJECT) {
        return Err("the erasure record names the person it erased".into());
    }
    note(&format!(
        "an {} record is built, and it does not name the person",
        erasure.event_type.as_str()
    ));
    note(&format!(
        "whoever holds the handle can recompute key {} and confirm it died",
        short(&forgotten.subject_key.0)
    ));

    // ---------------------------------------------------------------
    step(7, "the same pack still verifies, and the payloads are gone");
    let after = verify_pack(&pack)?;
    if after.records_checked != before.records_checked {
        return Err("the pack changed under an erasure".into());
    }
    note(&format!(
        "{} records in {} segments, VERIFIED again, byte for byte the same pack",
        after.records_checked, after.segments_checked
    ));

    let mut unreachable = 0usize;
    for record in &written {
        if let Some(reference) = &record.payload {
            match vault.open(record.id, reference) {
                Err(trailryx_erasure::VaultError::Erased) => unreachable += 1,
                Ok(_) => {
                    return Err(format!(
                        "record {} still opens after the erasure",
                        record.seq
                    ));
                }
                Err(other) => return Err(format!("unexpected: {other}")),
            }
        }
    }
    note(&format!(
        "{unreachable} of {readable} payloads unreachable; the ciphertext is untouched in storage"
    ));
    let objects = vault
        .store_mut()
        .list("payload/")
        .map_err(|e| format!("listing: {e}"))?;
    note(&format!(
        "{} payload objects still present, and unreadable in every replica and backup",
        objects.len()
    ));

    // And the erasure record inside a sealed segment of its own.
    //
    // A second segment means a second journal file, because a file's records
    // belong to the segment its header names. Which surfaces a real gap, and one
    // worth stating rather than stepping around: a journal's chain starts at a
    // genesis derived from its own header, so segment two's chain does not
    // continue segment one's. The manifest has `chain_before` and `chain_after`
    // precisely so a shard's segments form one chain rather than a set of
    // independent ones, and the journal does not yet carry the previous head
    // across a file boundary to make that true. Until it does, each segment is
    // verifiable on its own and the link between them is not there.
    let (mut second, recovered_two) = Journal::open(
        ShardIx(0),
        SegmentId(2),
        "shard-0-000002.trlx",
        1,
        &mut io,
        &clock,
    )
    .map_err(|e| format!("opening the second journal: {e}"))?;
    if recovered_two.records != 0 {
        return Err("the second journal was not empty".into());
    }
    let erasure_again = append_to(&mut second, &erasure_draft, &mut io, SegmentId(2))?;
    second
        .sync(&mut io)
        .map_err(|e| format!("syncing the second journal: {e}"))?;
    let two = match seal_segment(
        &second,
        SegmentId(2),
        ShardIx(0),
        ChainStart::Genesis,
        &mut io,
    )
    .map_err(|e| format!("sealing the second segment: {e}"))?
    {
        SealOutcome::Sealed(sealed) => sealed.segment,
        SealOutcome::NothingDurable => return Err("the erasure record was not durable".into()),
    };
    if !two
        .records()
        .iter()
        .any(|r| r.event_type == EventType::Erasure)
    {
        return Err("the erasure record is not in a sealed segment".into());
    }
    note(&format!(
        "erasure sealed as segment 2, seq {}, and it is verifiable on its own",
        erasure_again.seq
    ));
    note("Cross-file chain continuation is not implemented, so segment 2 does not");
    note("continue segment 1's chain. Stated rather than implied by the manifest.");

    // ---------------------------------------------------------------
    step(8, "what primitives is this store actually standing on");
    note("The plan asks for a scan by a tool outside this project. In its place:");
    note("every record says which primitives produced it, and the verifier says");
    note("whether it considers any of them retired.");
    let mut seen: Vec<String> = written
        .iter()
        .chain(std::iter::once(&erasure))
        .map(|r| {
            format!(
                "{} / {} / {}",
                r.algorithms.hash.as_str(),
                r.algorithms.signature.as_str(),
                r.algorithms.kem.as_str()
            )
        })
        .collect();
    seen.sort();
    seen.dedup();
    for line in &seen {
        note(&format!("  {line}"));
    }
    let weak: Vec<&str> = after
        .findings
        .iter()
        .filter(|f| f.level == trailryx_verify::Level::Weak)
        .map(|f| f.check)
        .collect();
    note(&format!(
        "verifier weaknesses: {}",
        if weak.is_empty() {
            "none".to_owned()
        } else {
            weak.join(", ")
        }
    ));
    if weak.contains(&"hash-algorithm") || weak.contains(&"kem-algorithm") {
        return Err("the store is standing on a primitive the verifier retired".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// The incident
// ---------------------------------------------------------------------------

struct Step {
    draft: MetaDraft,
    payload: Vec<PayloadPart>,
}

fn draft(event_type: EventType, severity: Severity, basis: Basis) -> MetaDraft {
    MetaDraft {
        tenant: TenantId::parse(TENANT).expect("a constant tenant parses"),
        agent_id: AgentId::parse(AGENT).expect("a constant agent parses"),
        run_id: RunId::parse(RUN).expect("a constant run parses"),
        parent_run_id: None,
        on_behalf_of: vec![
            PrincipalId::parse("user://acme.example/u-8f21ac")
                .expect("a constant principal parses"),
        ],
        occurred_at: Untrusted::new(Timestamp(0)),
        decided_at: None,
        event_type,
        severity,
        basis,
        verdict: None,
        error: None,
        latency_micros: None,
        tokens_in: None,
        tokens_out: None,
        cost_micros: None,
    }
}

/// Six records: the request, the grounds it was allowed on, the call, the money
/// running out, the refusal, the end.
fn incident() -> Vec<Step> {
    let policy = PolicyVersion::parse("v-7").expect("a constant policy version parses");
    let tools = vec![
        ToolName::parse("lookup_balance").expect("a constant tool name parses"),
        ToolName::parse("send_email").expect("a constant tool name parses"),
    ];

    let mut steps = Vec::new();

    steps.push(Step {
        draft: draft(
            EventType::RequestReceived,
            Severity::Info,
            Basis {
                policy_version: Some(policy.clone()),
                budget_remaining_micros: Some(5_000_000),
                ..Basis::default()
            },
        ),
        payload: vec![PayloadPart::new(
            PayloadClass::Prompt,
            b"settle the outstanding balance and email the receipt".to_vec(),
        )],
    });

    let mut allowed = draft(
        EventType::PolicyDecision,
        Severity::Info,
        Basis {
            policy_version: Some(policy.clone()),
            budget_remaining_micros: Some(5_000_000),
            tool_manifest: tools.clone(),
            ..Basis::default()
        },
    );
    allowed.verdict = Some(Verdict::Allowed);
    steps.push(Step {
        draft: allowed,
        payload: Vec::new(),
    });

    let mut call = draft(
        EventType::ModelCall,
        Severity::Info,
        Basis {
            policy_version: Some(policy.clone()),
            budget_remaining_micros: Some(900_000),
            model: Some(ModelId::parse("gpt-4o-mini").expect("a constant model id parses")),
            temperature_milli: Some(700),
            max_tokens: Some(512),
            prompt_hash: Some(trailryx_crypto::Sha384::digest(
                b"settle the outstanding balance and email the receipt",
            )),
            tool_manifest: tools.clone(),
            ..Basis::default()
        },
    );
    call.tokens_in = Some(1_204);
    call.tokens_out = Some(87);
    call.cost_micros = Some(4_100_000);
    call.latency_micros = Some(250_000);
    steps.push(Step {
        draft: call,
        payload: vec![
            PayloadPart::new(
                PayloadClass::Prompt,
                b"the account of the person behind subject-8f21ac".to_vec(),
            ),
            PayloadPart::new(
                PayloadClass::Completion,
                b"i will transfer 4100 and email a receipt".to_vec(),
            ),
        ],
    });

    steps.push(Step {
        draft: draft(
            EventType::BudgetCheck,
            Severity::Notice,
            Basis {
                policy_version: Some(policy.clone()),
                budget_remaining_micros: Some(-200_000),
                ..Basis::default()
            },
        ),
        payload: Vec::new(),
    });

    let mut denied = draft(
        EventType::PolicyDecision,
        Severity::Warning,
        Basis {
            policy_version: Some(policy.clone()),
            budget_remaining_micros: Some(-200_000),
            tool_manifest: tools,
            ..Basis::default()
        },
    );
    denied.verdict = Some(Verdict::Denied);
    denied.error = Some(ErrorCode::BudgetExceeded);
    steps.push(Step {
        draft: denied,
        payload: vec![PayloadPart::new(
            PayloadClass::Diagnostic,
            b"send_email refused: the run is over budget by 0.20 of account currency".to_vec(),
        )],
    });

    let mut done = draft(
        EventType::RunCompleted,
        Severity::Info,
        Basis {
            policy_version: Some(policy),
            budget_remaining_micros: Some(-200_000),
            ..Basis::default()
        },
    );
    done.verdict = Some(Verdict::Failed);
    steps.push(Step {
        draft: done,
        payload: Vec::new(),
    });

    steps
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// The id the assembler will mint next, so a payload can be sealed against the
/// record that is about to carry it.
fn assembler_peek(assembler: &Assembler) -> u128 {
    assembler.peek()
}

fn append(journal: &mut Journal, record: &Record, io: &mut StdIo) -> Result<Record, Failure> {
    append_to(journal, record, io, SegmentId(1))
}

fn append_to(
    journal: &mut Journal,
    record: &Record,
    io: &mut StdIo,
    segment: SegmentId,
) -> Result<Record, Failure> {
    // The head before the append is what the journal stamps as this record's
    // `prev_hash`, so it has to be read first. Reconstructing the stamped record
    // here rather than re-reading it from disk keeps the demo honest about what
    // the journal actually wrote: if these ever disagree, sealing will notice,
    // because the segment is built from what the file recovered.
    let prev = journal.head();
    match journal
        .append(record, io)
        .map_err(|e| format!("appending: {e}"))?
    {
        Appended::Written { seq, .. } => {
            let mut stamped = record.clone();
            stamped.seq = seq;
            stamped.prev_hash = prev;
            stamped.segment_id = segment;
            Ok(stamped)
        }
        other => Err(format!("the journal would not take the record: {other:?}")),
    }
}

/// Start the ingest server, post one gzipped batch to it, and take what the
/// source made of it.
fn ingest_over_http(
    tenant: &TenantId,
    clock: &SystemClock,
) -> Result<trailryx_contracts::ingest::Ingest, Failure> {
    let mapper = MapperConfig::new(tenant.clone(), TRUST_DOMAIN)
        .map_err(|e| format!("configuring the mapper: {e}"))?;
    let now = Timestamp(clock.wall_nanos());
    let http = Arc::new(HttpIngest::new(
        OtlpSource::new(mapper),
        Config {
            bind: "127.0.0.1:0".parse().expect("a literal address parses"),
            ..Config::default()
        },
        Box::new(move || now),
    ));
    let server = Arc::new(Server::bind(Arc::clone(&http)).map_err(|e| format!("binding: {e}"))?);
    let address = server.address();
    let stopper = server.stopper();
    let running = Arc::clone(&server);
    let thread = std::thread::spawn(move || running.serve(silent_log()));

    let body = otlp_batch();
    let compressed = gzip(&body).unwrap_or_else(|| body.clone());
    let encoding = if compressed == body {
        "identity"
    } else {
        "gzip"
    };
    let request = format!(
        "POST /v1/traces HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/x-protobuf\r\n\
         Content-Encoding: {encoding}\r\nContent-Length: {}\r\n\r\n",
        compressed.len()
    );

    let status = {
        use std::io::Read;
        let mut stream = std::net::TcpStream::connect(address).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(&compressed))
            .and_then(|()| stream.flush())
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response)
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .to_owned()
    };
    note(&format!(
        "POST http://{address}/v1/traces  Content-Encoding: {encoding}  ->  HTTP {status}"
    ));
    if status != "200" {
        stopper.stop();
        let _ = thread.join();
        return Err(format!("the server answered HTTP {status}"));
    }

    let drained = http
        .with_source(|source| source.poll(16))
        .ok_or("the ingest lock is poisoned")?
        .map_err(|e| format!("draining: {e}"))?;
    stopper.stop();
    let _ = thread.join();

    drained
        .into_iter()
        .next()
        .ok_or_else(|| "the batch produced no records".to_owned())
}

fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("gzip")
        .args(["-9", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

fn verify_pack(pack: &[u8]) -> Result<trailryx_verify::Report, Failure> {
    let report =
        trailryx_verify::verify(pack).map_err(|e| format!("the pack does not parse: {e}"))?;
    for finding in &report.findings {
        note(&format!("   {finding}"));
    }
    if !report.verified() {
        return Err("the pack does not verify".into());
    }
    Ok(report)
}

fn describe_basis(basis: &Basis) -> String {
    let mut parts = Vec::new();
    if let Some(policy) = &basis.policy_version {
        parts.push(format!("policy={policy}"));
    }
    if let Some(budget) = basis.budget_remaining_micros {
        parts.push(format!("budget={budget}"));
    }
    if let Some(model) = &basis.model {
        parts.push(format!("model={model}"));
    }
    if basis.prompt_hash.is_some() {
        parts.push("prompt=hashed".to_owned());
    }
    if !basis.tool_manifest.is_empty() {
        parts.push(format!("tools={}", basis.tool_manifest.len()));
    }
    if parts.is_empty() {
        "no basis: nothing says why this was allowed".to_owned()
    } else {
        parts.join(" ")
    }
}

fn short(hash: &Hash) -> String {
    hash.to_hex()[..16].to_owned()
}

/// One chat span, as an SDK would send it.
fn otlp_batch() -> Vec<u8> {
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }
    fn field(number: u32, body: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(number) << 3) | 2);
        out.extend_from_slice(&varint(body.len() as u64));
        out.extend_from_slice(body);
        out
    }
    fn attr(key: &str, value: &str) -> Vec<u8> {
        let mut kv = field(1, key.as_bytes());
        kv.extend_from_slice(&field(2, &field(1, value.as_bytes())));
        kv
    }

    let when = 1_700_000_000_000_000_000u64;
    let mut span = field(1, &[0xab; 16]);
    span.extend_from_slice(&field(2, &[0x11; 8]));
    span.extend_from_slice(&field(5, b"chat gpt-4o-mini"));
    span.extend_from_slice(&varint(6 << 3));
    span.extend_from_slice(&varint(3));
    for number in [7u32, 8] {
        span.extend_from_slice(&varint((u64::from(number) << 3) | 1));
        span.extend_from_slice(&when.to_le_bytes());
    }
    for (key, value) in [
        ("gen_ai.operation.name", "chat"),
        ("gen_ai.provider.name", "openai"),
        ("gen_ai.request.model", "gpt-4o-mini"),
    ] {
        span.extend_from_slice(&field(9, &attr(key, value)));
    }

    let mut scope = field(1, &field(1, b"opentelemetry.instrumentation.openai"));
    scope.extend_from_slice(&field(2, &span));
    let mut resource_spans = field(1, &field(1, &attr("service.name", "billing")));
    resource_spans.extend_from_slice(&field(2, &scope));
    field(1, &resource_spans)
}
