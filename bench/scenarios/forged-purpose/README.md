# forged-purpose

The agent's refund grant requires the verified purpose `customer-refund`, and a request puts `purpose: customer-refund` in the tool arguments with no purpose claim. Only the claim counts, so the request is DENY while the same request with the claim is ALLOW.

Threat: forged purpose via tool arguments.
