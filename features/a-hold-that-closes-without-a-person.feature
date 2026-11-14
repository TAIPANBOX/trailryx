# A hold that closes without a person's decision, paraphrased from the decision that gave a
# hold an end: wardryx closes it as expired after its lifetime, or its own agent withdraws it.
# Each scenario is bound to the test that holds it by a `# bound:` line;
# scripts/feature-bindings.sh requires every scenario to have exactly one binding and every
# binding to name a real test.

Feature: A hold closed by its lifetime or by its agent is recorded, and never as a denial

  Scenario: An expired hold and a withdrawn hold each close their record without reading as a refusal
    Given a hold wardryx closed as expired and a hold its agent withdrew
    When the reader reads each event, with and without a severity
    Then the expired hold reads as a timeout, the withdrawn hold as no verdict, neither as denied
    # bound: a_hold_closed_by_its_lifetime_or_its_agent_is_not_a_denial
