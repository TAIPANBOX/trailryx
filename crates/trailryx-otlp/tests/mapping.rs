//! What a stock OpenTelemetry SDK produces, and what it becomes here.

mod common;

use common::*;
use trailryx_contracts::contracts::{Source, Trust};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::TenantId;
use trailryx_record::{ErrorCode, EventType, Severity, Timestamp, Verdict};

const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);

fn source() -> OtlpSource {
    let cfg = MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap();
    OtlpSource::new(cfg)
}

/// The span an instrumented chat call actually emits.
fn chat_span() -> SpanBuilder {
    SpanBuilder::new("chat gpt-4o-mini")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.provider.name", "openai")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
        .attr("gen_ai.request.temperature", any_double(0.7))
        .int_attr("gen_ai.request.max_tokens", 512)
        .int_attr("gen_ai.usage.input_tokens", 1_204)
        .int_attr("gen_ai.usage.output_tokens", 87)
        .str_attr("gen_ai.response.id", "chatcmpl-abc123")
        .attr(
            "gen_ai.input.messages",
            any_array(&[any_map(&[
                ("role", any_string("user")),
                (
                    "content",
                    any_string("what is the balance for Ivan Petrenko"),
                ),
            ])]),
        )
}

#[test]
fn a_stock_chat_span_becomes_a_model_call_record() {
    // The whole criterion for this stage in one test: a foreign agent with
    // ordinary instrumentation, unchanged, and a usable record out of it.
    let mut src = source();
    let batch = request(
        &service("billing-assistant"),
        "openai.instrumentation",
        &[chat_span()],
    );
    assert_eq!(src.accept(&batch, NOW), 1);

    let items = src.poll(10).unwrap();
    assert_eq!(items.len(), 1);
    let meta = &items[0].meta;

    assert_eq!(meta.event_type, EventType::ModelCall);
    assert_eq!(meta.tenant.as_str(), "acme");
    assert_eq!(
        meta.agent_id.as_str(),
        "agent://acme.example/billing-assistant"
    );
    assert_eq!(meta.run_id.as_str(), "abababababababababababababababab");
    assert_eq!(meta.tokens_in, Some(1_204));
    assert_eq!(meta.tokens_out, Some(87));
    assert_eq!(meta.latency_micros, Some(250_000));
    assert_eq!(meta.severity, Severity::Info);

    let basis = &meta.basis;
    assert_eq!(
        basis.model.as_ref().map(|m| m.as_str()),
        Some("gpt-4o-mini")
    );
    assert_eq!(basis.temperature_milli, Some(700));
    assert_eq!(basis.max_tokens, Some(512));
    assert!(basis.prompt_hash.is_some(), "the prompt is bound by hash");
}

#[test]
fn what_otlp_cannot_say_is_left_unsaid() {
    // The honest half of the previous test. Nothing in a span carries the
    // grounds a decision was taken on, so those fields stay empty rather than
    // being filled with something that reads like an answer.
    let mut src = source();
    let batch = request(&service("billing-assistant"), "scope", &[chat_span()]);
    src.accept(&batch, NOW);
    let items = src.poll(10).unwrap();
    let basis = &items[0].meta.basis;

    assert_eq!(basis.policy_version, None, "no policy version in OTLP");
    assert_eq!(
        basis.budget_remaining_micros, None,
        "no budget state in OTLP"
    );
    assert_eq!(basis.memory_ref, None, "no memory reference in OTLP");
    assert!(
        basis.identity_chain.is_empty(),
        "no delegation chain in OTLP"
    );
    assert_eq!(
        items[0].meta.parent_run_id, None,
        "a trace has no parent trace"
    );
}

#[test]
fn a_root_invocation_is_a_request_and_a_nested_one_is_a_delegation() {
    // The same operation name means two different things depending on whether
    // somebody else started it, and the difference is what an auditor follows.
    let root = SpanBuilder::new("invoke_agent triage")
        .str_attr("gen_ai.operation.name", "invoke_agent")
        .span_id(vec![0x01; 8]);
    let nested = SpanBuilder::new("invoke_agent billing")
        .str_attr("gen_ai.operation.name", "invoke_agent")
        .span_id(vec![0x02; 8])
        .parent(vec![0x01; 8]);

    let mut src = source();
    src.accept(&request(&service("triage"), "scope", &[root, nested]), NOW);
    let items = src.poll(10).unwrap();

    assert_eq!(items[0].meta.event_type, EventType::RequestReceived);
    assert_eq!(items[1].meta.event_type, EventType::Delegation);
}

#[test]
fn a_tool_span_becomes_a_tool_call() {
    let span = SpanBuilder::new("execute_tool lookup_balance")
        .str_attr("gen_ai.operation.name", "execute_tool")
        .str_attr("gen_ai.tool.name", "lookup_balance")
        .str_attr("gen_ai.tool.call.arguments", "{\"customer\":\"ivan\"}");

    let mut src = source();
    src.accept(&request(&service("billing"), "scope", &[span]), NOW);
    let items = src.poll(10).unwrap();

    assert_eq!(items[0].meta.event_type, EventType::ToolCall);
    let args = items[0]
        .payload
        .iter()
        .find(|p| p.class == trailryx_record::PayloadClass::ToolArguments)
        .expect("arguments are content and go to the encrypted plane");
    assert!(String::from_utf8_lossy(&args.bytes).contains("ivan"));
}

#[test]
fn retrieval_and_memory_are_both_the_agent_consulting_something() {
    for op in [
        "retrieval",
        "search_memory",
        "upsert_memory",
        "create_memory_store",
    ] {
        let span = SpanBuilder::new(op).str_attr("gen_ai.operation.name", op);
        let mut src = source();
        src.accept(&request(&service("rag"), "scope", &[span]), NOW);
        let items = src.poll(10).unwrap();
        assert_eq!(items[0].meta.event_type, EventType::MemoryAccess, "{op}");
    }
}

#[test]
fn only_failure_is_asserted_as_a_verdict() {
    // A span that succeeded says nothing about a policy having allowed it, so
    // nothing is claimed. An auditor reading "allowed" would believe a decision
    // was taken that nobody took.
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[chat_span()]), NOW);
    assert_eq!(src.poll(1).unwrap()[0].meta.verdict, None);

    let failed = chat_span()
        .status(
            2,
            "upstream returned 429 for customer ivan.petrenko@example.com",
        )
        .str_attr("error.type", "RateLimitError");
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[failed]), NOW);
    let items = src.poll(1).unwrap();
    assert_eq!(items[0].meta.verdict, Some(Verdict::Failed));
    assert_eq!(items[0].meta.error, Some(ErrorCode::RateLimited));
    assert_eq!(items[0].meta.severity, Severity::Error);

    // And the message that carried the address is on the encrypted side, where
    // a status message belongs precisely because it quotes upstream.
    let diagnostic = items[0]
        .payload
        .iter()
        .find(|p| p.class == trailryx_record::PayloadClass::Diagnostic)
        .unwrap();
    assert!(String::from_utf8_lossy(&diagnostic.bytes).contains("ivan.petrenko@example.com"));
}

#[test]
fn an_unknown_operation_is_refused_rather_than_guessed() {
    // The conventions are still moving, so this will happen. A record with a
    // wrong event type is worse than a missing record, because it is believed.
    let span = SpanBuilder::new("summarise").str_attr("gen_ai.operation.name", "summarise_thread");
    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        0
    );
    assert_eq!(src.report().unknown_operation, 1);
    assert_eq!(src.report().lost(), 1);
}

#[test]
fn an_ordinary_span_is_not_turned_into_an_agent_record() {
    // Agent traffic shares a collector with everything else. A database span is
    // not a loss and is not evidence about an agent either.
    let span = SpanBuilder::new("SELECT customers").str_attr("db.system", "postgresql");
    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        0
    );
    assert_eq!(src.report().not_genai, 1);
    assert_eq!(src.report().lost(), 0, "never ours, so never lost");
}

#[test]
fn a_span_that_ends_before_it_starts_has_no_latency() {
    let span = chat_span().times(1_700_000_000_500_000_000, 1_700_000_000_000_000_000);
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();
    assert_eq!(
        items[0].meta.latency_micros, None,
        "a broken clock is not a negative duration"
    );
}

#[test]
fn the_parent_span_travels_as_correlation_and_never_as_a_field() {
    // Causality has to survive the trip, and the span id must not survive into
    // a record: it is the source's name for the event, not ours.
    let child = chat_span().span_id(vec![0x22; 8]).parent(vec![0x11; 8]);
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[child]), NOW);
    let items = src.poll(1).unwrap();

    let correlation = items[0].correlation.expect("a span always has an id");
    assert_eq!(correlation.id.as_bytes(), &[0x22; 8]);
    assert_eq!(correlation.parent.unwrap().as_bytes(), &[0x11; 8]);
}

#[test]
fn the_receiver_declares_what_it_cannot_vouch_for() {
    // Both clocks and identities come from the emitter. Saying so is what lets
    // the store record disagreement instead of papering over it.
    let d = source().descriptor();
    assert_eq!(d.clock_trust, Trust::Untrusted);
    assert_eq!(d.identity_trust, Trust::Untrusted);
}

#[test]
fn the_same_bytes_always_produce_the_same_record() {
    // The payload is hashed, so a rendering that depended on iteration order
    // would make two copies of one span into two different records.
    let batch = request(&service("billing"), "scope", &[chat_span()]);
    let mut a = source();
    let mut b = source();
    a.accept(&batch, NOW);
    b.accept(&batch, NOW);
    assert_eq!(a.poll(10).unwrap(), b.poll(10).unwrap());
}

#[test]
fn a_batch_exported_children_first_still_produces_the_causal_edges() {
    // The end-to-end version, through the real wire path, of the defect the core
    // review measured. A span is exported when it *ends*, and a child ends inside
    // the parent that contains it, so a `BatchSpanProcessor` produces batches in
    // exactly this order. Resolution in arrival order therefore found no parents
    // at all, and the causal graph was empty for every OTLP-sourced trace.
    let mut src = source();
    let child = SpanBuilder::new("delegate")
        .span_id(vec![0x22; 8])
        .parent(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "invoke_agent");
    let parent = SpanBuilder::new("root")
        .span_id(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "invoke_agent");

    assert_eq!(
        src.accept(
            &request(&service("a"), "scope", &[child, parent]),
            Timestamp(1_700_000_000_000_000_000)
        ),
        2
    );
    let batch = src.poll(16).unwrap();
    assert_eq!(batch.len(), 2);

    let mut assembler = trailryx_assemble::Assembler::new(
        trailryx_record::ShardIx(0),
        trailryx_sim::rng::SimRng::new(1),
    );
    let records = assembler.adopt_batch(batch, Timestamp(1_700_000_000_000_000_000));

    let kid = &records[0].record;
    let root = &records[1].record;
    assert_eq!(
        kid.caused_by,
        vec![root.id],
        "the child was exported first and lost its edge"
    );
    assert!(root.caused_by.is_empty());
    assert_eq!(assembler.unresolved_parents(), 0);
}

#[test]
fn an_all_zero_parent_span_id_is_not_a_parent() {
    // OTLP defines an all-zero span id as invalid, and emitters write the field
    // out as zeros rather than omitting it. Treating those eight bytes as a name
    // manufactured edges: two unrelated roots, each naming the invalid parent,
    // became children of whichever span had claimed the all-zero id, and
    // `event_type` flipped from a request arriving to one agent delegating to
    // another, which is the edge an auditor follows.
    let mut src = source();
    let spans = [
        SpanBuilder::new("zero-named")
            .span_id(vec![0x00; 8])
            .str_attr("gen_ai.operation.name", "invoke_agent"),
        SpanBuilder::new("root-a")
            .span_id(vec![0x55; 8])
            .parent(vec![0x00; 8])
            .str_attr("gen_ai.operation.name", "invoke_agent"),
        SpanBuilder::new("root-b")
            .span_id(vec![0x66; 8])
            .parent(vec![0x00; 8])
            .str_attr("gen_ai.operation.name", "invoke_agent"),
    ];
    assert_eq!(
        src.accept(
            &request(&service("a"), "scope", &spans),
            Timestamp(1_700_000_000_000_000_000)
        ),
        3
    );
    let batch = src.poll(16).unwrap();

    // The span that named itself with zeros has no correlation at all, so it
    // cannot be pointed at, and neither root claims a parent.
    assert!(
        batch[0].correlation.is_none(),
        "an invalid id is not a name"
    );
    for unit in &batch[1..] {
        assert!(
            unit.correlation
                .as_ref()
                .is_some_and(|c| c.parent.is_none()),
            "an all-zero parent id became a parent"
        );
        assert_eq!(
            unit.meta.event_type,
            EventType::RequestReceived,
            "an invalid parent id reclassified a root as a delegation"
        );
    }

    let mut assembler = trailryx_assemble::Assembler::new(
        trailryx_record::ShardIx(0),
        trailryx_sim::rng::SimRng::new(2),
    );
    for assembled in assembler.adopt_batch(batch, Timestamp(1_700_000_000_000_000_000)) {
        assert!(assembled.record.caused_by.is_empty());
    }
    assert_eq!(
        assembler.unresolved_parents(),
        0,
        "nothing was even claimed"
    );
}
