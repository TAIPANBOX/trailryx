# The two keyryx custody types registered in agent-passport SPEC 6.2 in November
# 2026, key_rotated and key_revoked, and what the reader does with them. Each
# scenario is bound to the test that holds it by a `# bound:` line;
# scripts/feature-bindings.sh requires exactly one binding per scenario and a
# test that exists.

Feature: A key change custody announces is refused by name

  Scenario: An operator's rotation or revocation of a custody key is not a record
    Given keyryx custody announced a key rotated and a key revoked under its own subject
    When the reader reads each, under custody's domain and the operator's, with a run and without one
    Then each is refused as an unknown type and never becomes a record
    # bound: keyryx_custodys_key_changes_are_refused_by_name
