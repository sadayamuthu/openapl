# bench/scenarios/forged-purpose/rego/policy.rego
# OpenAPL policy forged-purpose 1.0.0, in Rego. input is the request as data: input.chain is the
# ordered list of {id, kind, claims} links (origin first, caller last); purpose, task_id,
# iat and approvals are the verified claims; now is the decision time.
# Query: data.openapl.decision.
package openapl

chain := input.chain

origin := chain[0]

caller := chain[count(chain) - 1]

# A group or role claim is a list, or a single string read as a one-item list (SPEC 5.2).
claim_values(link, name) := {v | some v in link.claims[name]} if is_array(link.claims[name])

claim_values(link, name) := {link.claims[name]} if is_string(link.claims[name])

in_group(link, g) if {
	link.kind == "human"
	g in claim_values(link, "groups")
}

# OpenAPL globs: `*` matches any run of characters, including "/" and "." (no delimiters).
matches(pattern, value) if glob.match(pattern, null, value)

# Every link after the origin is reached by a delegation edge that lists the action.
edge_ok(i) if i == 0

edge_ok(i) if edge(i)

edges_ok if {
	every i, _ in chain {
		edge_ok(i)
	}
}

# Grant support-refunds.
granted(link) if {
	in_group(link, "support")
	input.action == "payments.refund"
	matches("order/*", input.resource)
}

# Grant refund-agent-refunds: only under the verified purpose claim (input.purpose), never
# the tool arguments (input.attributes).
granted(link) if {
	link.id == "refund-agent"
	input.action == "payments.refund"
	matches("order/*", input.resource)
	input.purpose == "customer-refund"
}

# Edge: refund-agent acts_for group:support on payments.refund. No may_delegate edges.
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "refund-agent"
	in_group(chain[i - 1], "support")
	input.action == "payments.refund"
}

default decision := "DENY"

decision := "ALLOW" if {
	edges_ok
	granted(origin)
	granted(caller)
	origin.kind == "human" # require_human_origin (default)
}
