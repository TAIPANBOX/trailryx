# Agent-event v1.0 (agent-passport SPEC 6.4.1), paraphrased from the decision that
# asked for it, not copied from the spec's wording. Each scenario is bound to the
# test that holds it by a `# bound:` line; scripts/feature-bindings.sh requires every
# scenario to have exactly one binding and every binding to name a real test.

Feature: The agent-event reader accepts v1.0 without loosening what it refuses

  Scenario: A v1.0 line reads exactly as the same line stamped v0.3
    Given an established agent event in this trust domain
    When the same event is stamped v1.0 and then stamped v0.3
    Then both read to the same record
    # bound: v1_0_is_read_exactly_like_v0_3

  Scenario: A version the reader does not name is refused by its schema
    Given an event stamped with a version beyond the ones accepted, such as v1.1
    When the reader reads it
    Then the schema is refused and no record is written
    # bound: a_version_beyond_the_accepted_ones_is_refused_by_schema

  Scenario: A claimed subject is refused under every accepted version, v1.0 included
    Given an event whose subject a process asserted about itself
    When it is stamped with each accepted version in turn
    Then every one is refused by name as a claimed subject
    # bound: every_accepted_version_refuses_a_claimed_subject_by_name

  Scenario: Under v1.0 the claim prefix is not stripped
    Given the same identifier once bare and once carrying the claim prefix, under v1.0
    When the reader reads both
    Then the bare one is an ordinary subject and the prefixed one is refused
    # bound: under_v1_0_the_claim_prefix_is_not_stripped

  Scenario: The keyryx and agent-conform types under v1.0 are refused by type, not sealed
    Given a witness finding or a chain finding stamped v1.0
    When the reader reads it under any domain, with or without a run
    Then it is refused as an unmapped type and never written as an agent's decision
    # bound: keyryx_and_agent_conform_types_under_v1_0_are_refused_by_type_and_not_sealed

  Scenario: An established subject under v0.3 still maps
    Given an established identity finding stamped v0.3
    When the reader reads it
    Then it maps to an identity finding
    # bound: an_established_subject_under_v0_3_still_maps

  Scenario: A claimed subject under v0.3 is still refused by name
    Given an identity finding whose subject is claimed, stamped v0.3
    When the reader reads it
    Then it is refused as a claimed subject
    # bound: a_claimed_subject_is_refused_by_name_rather_than_by_encoding

  Scenario: The wardryx checkpoint lines, as wardryx wrote them, are refused for want of a run
    Given the two policy-allow lines from wardryx's checkpoint vectors, stamped v1.0
    When the reader reads them
    Then both are refused for want of a run and neither is written
    # bound: wardryx_checkpoint_vectors_as_written_are_refused_for_want_of_a_run

  Scenario: With a run added, the wardryx checkpoint lines are allowed policy decisions
    Given the same two lines with a run identifier added and nothing else changed
    When the reader reads them
    Then both are policy decisions with an allowed verdict, and the prev_hash stays in the payload
    # bound: wardryx_checkpoint_vectors_with_a_run_are_allowed_policy_decisions_under_v1_0

  Scenario: A claimed wardryx line under v1.0 is refused by name
    Given a checkpoint line whose subject a process claimed about itself, stamped v1.0
    When the reader reads it with and without a run
    Then it is refused as a claimed subject both ways
    # bound: a_claimed_real_wardryx_line_under_v1_0_is_refused_by_name_with_or_without_a_run

  Scenario: The agent-conform and keyryx types under v1.0 are refused by type, with or without a run
    Given lines from agent-conform and keyryx for the types the module doc names, stamped v1.0
    When the reader reads each one, with and without a run
    Then every one is refused by type and none is written as an agent's decision
    # bound: real_agent_conform_and_keyryx_lines_under_v1_0_are_refused_by_type
