# bench/scenarios/relay-adds-edge/rego/policy.rego
# OpenAPL policy payments-access 1.2.0, in Rego. input is the request as data: input.chain is the
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

# Grant support-staff-refunds.
granted(link) if {
	in_group(link, "support-staff")
	input.action == "payments.refund"
	matches("order/*", input.resource)
}

# Grant refund-small-orders: resource "order/${request.order_id}" (strict interpolation,
# compared exactly so the attribute value is never a pattern), purpose customer-refund,
# expires: task, when [request.amount <= 200, 'support-staff' in chain.origin.groups],
# otherwise require_approval(role:support-manager).
refund_small_applies(link) if {
	link.id == "refund-agent"
	input.action == "payments.refund"
	input.resource == sprintf("order/%v", [input.attributes.order_id])
	input.purpose == "customer-refund"
	is_string(input.task_id)
}

# The `when` list is evaluated in order; an absent or ill-typed operand is an error, which
# neither grants nor makes the link eligible.
amount := input.attributes.amount

origin_groups := origin.claims.groups

refund_small_when := "false" if {
	is_number(amount)
	amount > 200
}

refund_small_when := "true" if {
	is_number(amount)
	amount <= 200
	is_array(origin_groups)
	"support-staff" in origin_groups
}

refund_small_when := "false" if {
	is_number(amount)
	amount <= 200
	is_array(origin_groups)
	not "support-staff" in origin_groups
}

granted(link) if {
	refund_small_applies(link)
	refund_small_when == "true"
}

# A bound, unexpired approval item grants the eligible link (SPEC 6.6).
granted(link) if {
	refund_small_applies(link)
	refund_small_when == "false"
	some a in input.approvals
	a.entitlement_id == "refund-small-orders"
	a.approver == "role:support-manager"
	a.action == input.action
	a.resource == input.resource
	a.attributes_hash == crypto.sha256(json.marshal(input.attributes))
	a.origin == origin.id
	a.caller == caller.id
	a.exp >= input.now
}

eligible(link) if {
	refund_small_applies(link)
	refund_small_when == "false"
}

grade(link) := "GRANTED" if {
	granted(link)
} else := "NEEDS_APPROVAL" if {
	eligible(link)
} else := "NONE"

# Edges: support-agent acts_for group:support-staff; support-agent -> refund-agent.
edge(i) if {
	chain[i - 1].kind == "human"
	chain[i].id == "support-agent"
	in_group(chain[i - 1], "support-staff")
	input.action == "payments.refund"
}

edge(i) if {
	chain[i - 1].id == "support-agent"
	chain[i].id == "refund-agent"
	input.action == "payments.refund"
}

# Denies (grant_to "*"). no-refunds-on-closed-accounts fires when its `when` is true or
# errors (account_status absent).
account_open if input.attributes.account_status != "closed"

denied if {
	input.action == "payments.refund"
	matches("order/*", input.resource)
	not account_open
}

denied if {
	input.action == "payments.refund"
	matches("order/bulk-*", input.resource)
}

valid if {
	not denied
	edges_ok
	count(chain) - 1 <= 3 # delegation.max_depth
	origin.kind == "human" # require_human_origin
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
