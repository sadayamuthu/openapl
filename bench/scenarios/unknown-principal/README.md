# unknown-principal

A chain contains an actor that matches no principal in the policy set, either as the caller or as a relay in the middle. The request is DENY (P5, fail closed) even though the grant applies to every link.

Threat: none (tests semantics).
