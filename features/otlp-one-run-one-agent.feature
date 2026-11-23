# How a span that names no agent is filed, from issue #80: one run of one agent
# appeared under two agent ids when the SDK named the agent on some spans and not
# on the root. Each scenario is bound to the test that holds it by a `# bound:`
# line; scripts/feature-bindings.sh requires exactly one binding per scenario and
# a test that exists.

Feature: One run of one agent is filed under one agent id

  Scenario: A root that names no agent takes the agent the rest of its trace names
    Given one trace whose model and invoke_agent spans name the agent billing_helper_gcp
    And whose root span names no agent, from a service called billing-helper-gcp
    When the spans arrive in one batch, children first
    Then all three records are filed under agent://acme.example/billing_helper_gcp
    # bound: a_root_that_names_no_agent_takes_the_agent_its_trace_names

  Scenario: A root exported after its children takes their agent
    Given the same trace
    When the root arrives in a later batch than its children
    Then the root's record is filed under the agent its children named
    # bound: a_root_exported_after_its_children_takes_their_agent

  Scenario: A trace that names two agents lends neither to an unnamed span
    Given one trace whose spans name two agents, triage and billing
    And whose root span names no agent, from a service called front-door
    When the spans are mapped
    Then each named span keeps its own agent, and the root is filed under front-door
    # bound: a_trace_naming_two_agents_lends_neither
