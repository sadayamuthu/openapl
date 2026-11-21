# bench/scenarios/threshold-approval/rego/policy.rego
# OpenAPL policy threshold-approval 1.0.0, in Rego. input is the request as data: input.chain is the
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

# Grant finance-pay.
granted(link) if {
	in_group(link, "finance")
	input.action == "payments.pay"
	matches("payment/*", input.resource)
}

# Grant payment-small: when [request.amount <= 200],
# otherwise require_approval(role:finance-lead).
payment_small_applies(link) if {
	link.id == "payments-agent"
	input.action == "payments.pay"
	matches("payment/*", input.resource)
}

# The `when` is true, false, or an error (amount absent or not a number): an error neither
# grants nor makes the link eligible for approval.
amount := input.attributes.amount

payment_small_when_true if {
	is_number(amount)
	amount <= 200
}

payment_small_when_false if {
	is_number(amount)
	amount > 200
}

granted(link) if {
	payment_small_applies(link)
	payment_small_when_true
}

# A bound, unexpired approval item grants the eligible link (SPEC 6.6).
granted(link) if {
	payment_small_applies(link)
	payment_small_when_false
	some a in input.approvals
	a.entitlement_id == "payment-small"
	a.approver == "role:finance-lead"
	a.action == input.action
	a.resource == input.resource
	a.attributes_hash == crypto.sha256(json.marshal(input.attributes))
	a.origin == origin.id
	a.caller == caller.id
	a.exp >= input.now
}

eligible(link) if {
	payment_small_applies(link)
	payment_small_when_false
}

grade(link) := "GRANTED" if {
	granted(link)
} else := "NEEDS_APPROVAL" if {
	eligible(link)
} else := "NONE"

# Edge: payments-agent acts_for group:finance on payments.pay. No may_delegate edges.
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "payments-agent"
	in_group(chain[i - 1], "finance")
	input.action == "payments.pay"
}

valid if {
	edges_ok
	origin.kind == "human" # require_human_origin (default)
}

grades := {grade(origin), grade(caller)}

default decision := "DENY"

decision := "ALLOW" if {
	valid
	grades == {"GRANTED"}
}

decision := "REQUIRE_APPROVAL" if {
	valid
	"NEEDS_APPROVAL" in grades
	not "NONE" in grades
}
