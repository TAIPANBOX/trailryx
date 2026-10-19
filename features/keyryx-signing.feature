# How a seal takes a signature from Keyryx, paraphrased from the decision that asked for it:
# the node pins the one Keyryx key it signs under, checks each signature Keyryx returns
# before it keeps it, and does not start with Keyryx configured and no pin. Each scenario is
# bound to the test that holds it by a `# bound:` line; scripts/feature-bindings.sh requires
# exactly one binding per scenario and a test that exists.

Feature: A seal keeps only a Keyryx signature it has checked, under the key it is pinned to

  Scenario: A key set holding a key other than the pinned one is refused before anything is signed
    Given a node pinned to the thumbprint of one Keyryx key
    When Keyryx offers a key set holding a different key
    Then the key set is refused and the signer signs nothing
    # bound: a_key_set_that_is_not_the_pinned_key_is_refused_before_anything_is_signed

  Scenario: A signature that does not verify is not stored, and its root stays queued
    Given a sealed root waiting for its signature
    When Keyryx answers with a signature whose last bit has been altered
    Then the signature is refused, nothing is stored, and the root stays queued
    # bound: a_tampered_signature_is_refused_and_its_root_stays_queued

  Scenario: A signature of zero is not stored, and its root stays queued
    Given a sealed root waiting for its signature
    When Keyryx answers with r and s both zero
    Then the signature is refused, nothing is stored, and the root stays queued
    # bound: a_zero_signature_is_refused_and_its_root_stays_queued

  Scenario: A genuine signature over another statement is not stored under this root
    Given a sealed root waiting for its signature
    When Keyryx answers with a real signature over a statement the seal never made
    Then the signature is refused, nothing is stored, and the root stays queued
    # bound: a_genuine_signature_over_another_statement_is_refused_and_its_root_stays_queued

  Scenario: A node configured for Keyryx with no pinned key does not start
    Given Keyryx is configured for the seal and no key pin is set
    When the node starts
    Then it refuses to start and names the setting it is missing
    # bound: keyryx_without_a_pinned_key_refuses_to_start

  Scenario: The pin is the thumbprint Keyryx publishes as the key's kid
    Given a Keyryx key set with one P-384 key
    When the node computes the thumbprint of that key
    Then it is the value openssl computes over the RFC 7638 canonical JSON
    # bound: the_pin_is_the_thumbprint_keyryx_publishes_as_its_kid

  Scenario: A pin is a Keyryx thumbprint and nothing else
    Given a value offered as the pin
    When the node reads it
    Then only a 43-character base64url thumbprint is read, and anything else is refused
    # bound: a_pin_is_a_keyryx_thumbprint_and_nothing_else
