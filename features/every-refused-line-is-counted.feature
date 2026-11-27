# Paraphrased from the decision that asked for it. Each scenario is bound to the
# test that holds it by a `# bound:` line (scripts/feature-bindings.sh).

Feature: The count of lines that produced nothing includes every refusal

  Scenario: Every refusal reason, a claimed subject included, adds one lost line
    Given an agent-event stream where each refusal reason occurs once
    When the report says how many lines produced nothing
    Then that number equals the refusals listed by name, claimed subjects included
    # bound: every_rejection_noted_once_is_one_lost_line
