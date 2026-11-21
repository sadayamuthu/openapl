# approval-bound

A finance lead's approval for a 350 payment on `payment/p1` by `payments-agent` is presented with the request. The same request is ALLOW, while replaying it with other attributes, a different caller, origin or resource, or after `exp` is REQUIRE_APPROVAL.

Threat: none (tests semantics; approval replay is covered by design §4.3 rather than the §8 threat list).
