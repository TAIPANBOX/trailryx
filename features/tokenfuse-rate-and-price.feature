# Two tokenfuse event types registered in agent-passport SPEC 6.2 in November 2026,
# and how the reader writes them down: a call refused because its key went over
# its own rate limit, and a call priced from the fallback rates because its model
# is not in the price book. Each scenario is bound to the test that holds it by a
# `# bound:` line; scripts/feature-bindings.sh requires exactly one binding per
# scenario and a test that exists.

Feature: A rate-limited call and a fallback-priced call each become a record

  Scenario: A call refused for its key's rate reads as a rate-limited denial
    Given tokenfuse answered 429 because a key went over its requests-per-second limit
    When the reader reads the rate_limited event, with and without a severity
    Then the record is a policy decision, denied, with the error rate_limited
    And a missing severity reads as the registry's medium band
    # bound: a_call_refused_for_its_keys_rate_reads_as_a_rate_limited_denial

  Scenario: A call priced from the fallback rates is a budget line with no verdict
    Given tokenfuse priced a call from its fallback rates because the model is not in its price book
    When the reader reads the price_fallback event, with and without a severity
    Then the record is a budget check with no verdict and no error
    And a missing severity reads as the registry's low band
    # bound: a_call_priced_from_the_fallback_rates_is_a_budget_line_with_no_verdict
