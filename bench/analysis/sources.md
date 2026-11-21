# bench/analysis/sources.md

Sources for the written analyses `xacml.md` and `gapl.md`. Every page below was fetched on
2026-11-19; nothing is cited from memory. Each entry gives the URL, title, publisher, version or
date, the access date, and the claims that rely on it. Section numbers (§) refer to the fetched
document. For the downloaded files, the first 16 hex digits of the SHA-256 of the fetched bytes
are given so a reader can check that a later copy is the same text.

## XACML

**X1.** eXtensible Access Control Markup Language (XACML) Version 3.0 Plus Errata 01.
- URL: http://docs.oasis-open.org/xacml/3.0/errata01/os/xacml-3.0-core-spec-errata01-os-complete.html
- Publisher: OASIS XACML TC. Editor: Erik Rissanen.
- Version: OASIS Standard incorporating Approved Errata 01, 12 July 2017. It incorporates the
  errata into the OASIS Standard of 22 January 2013.
- Accessed: 2026-11-19. HTTP 200, 1,255,227 bytes, sha256 `6991f5699faed71f…`.
- Claims that rely on it (all of `xacml.md`):
  - §5.42: more than one `<Attributes>` element with the same Category is a syntax error unless
    the PDP implements the Multiple Decision Profile.
  - §5.44: Categories other than subject, resource, action and environment may be used.
  - §5.29 and §7.3.5: an absent attribute yields an empty bag when `MustBePresent` is false.
  - §7.3.2: a bag's values are not ordered, may hold duplicates, and a bag cannot contain bags.
  - §7.3.3: a single value is a bag of one.
  - §5.53: the four decisions (Permit, Deny, Indeterminate, NotApplicable).
  - §1.1 glossary ("Obligation", "Advice"), §5.34, §5.35, §5.39, §7.2 and §7.18: obligations and
    advice, how they are returned, and what the PEP must do with them.
  - §10.2.1: the conformance status (M/O) of schema elements, including that
    `<AttributeSelector>` and `<Content>` are optional.
  - §10.2.3: the combining algorithms are mandatory, among them deny-overrides,
    first-applicable and deny-unless-permit.
  - §10.2.5: `current-dateTime` and the other environment attributes.
  - §10.2.8: the function list. It includes string-concatenate, string-starts-with,
    string-regexp-match, the type-bag-size, type-is-in and type-subset functions, integer
    arithmetic and comparison, and dateTime-add-dayTimeDuration, all M. The xpath-node-*
    functions and access-permitted are O. No hash or digest function is listed.
  - Appendix A.3.5 (`and` evaluates left to right and stops at the first False), A.3.9, A.3.10,
    A.3.11 and A.3.13 (function semantics).
  - Appendix C.2 (deny-overrides), C.6 (deny-unless-permit) and C.8 (first-applicable).

**X2.** eXtensible Access Control Markup Language (XACML) Version 3.0.
- URL: http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html
- Publisher: OASIS. Version: OASIS Standard, 22 January 2013.
- Accessed: 2026-11-19. HTTP 200, 1,237,087 bytes.
- Fetched to confirm the base standard that X1 corrects. No claim relies on X2 alone; X1 is cited
  throughout because it is the corrected text.

**X3.** XACML v3.0 Administration and Delegation Profile Version 1.0.
- URL: http://docs.oasis-open.org/xacml/3.0/administration/v1.0/xacml-3.0-administration-v1.0.html
  (the "Latest version" URL).
- Publisher: OASIS XACML TC. Editors: Erik Rissanen and Hal Lockhart.
- Version: Committee Specification Draft 04 / Public Review Draft 02, 13 November 2014. This is a
  committee draft, not an OASIS Standard.
- Accessed: 2026-11-19. HTTP 200, 201,305 bytes, sha256 `d5c454668c248ff0…`.
- Claims that rely on it:
  - §3: the profile's purpose is to "express permissions about the right to issue policies", and
    issued policies are reduced to trusted ones.
  - §2.1.2: "Mary can do something on behalf of Jack" is expressed "by means of different
    subject-categories".
  - §2.1.3: dynamically issued policies "might need to be carried in application requests".
  - §4.11: `MaxDelegationDepth` bounds the reduction-graph path. It does not bound the chain of
    actors in a request.
  - Status (committee draft).

**X4.** XACML v3.0 Administration and Delegation Profile Version 1.0, Committee Specification 01.
- URL: http://docs.oasis-open.org/xacml/3.0/xacml-3.0-administration-v1-spec-cs-01-en.html
- Publisher: OASIS XACML TC. Version: Committee Specification 01, 10 August 2010.
- Accessed: 2026-11-19. HTTP 200.
- Claims that rely on it: the profile's status history. It reached Committee Specification in
  2010, and X3 is a later draft. Neither is an OASIS Standard.

## Gravitee GAPL (vendor documentation)

All G entries are Gravitee's own product documentation (documentation.gravitee.io) or its blog
(gravitee.io/blog). The documentation pages are unversioned "current" pages for Gravitee Gamma as
served on the access date. G10 links to Gamma 4.13 pages, and G13 is labelled Access
Management 4.13. The `.md` URL of each page is the Markdown rendition that the site itself
offers ("Markdown versions of documentation pages are available by appending `.md`"). It was
fetched with curl. No Gravitee software was installed or run.

| ID | Title | Publisher | URL | Version or date | Accessed | Claims that rely on it |
|---|---|---|---|---|---|---|
| G1 | Authorization Management overview | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/get-started/authorization-management-overview.md | current; sha256 `1786fb05c48e6a62…` | 2026-11-19 | Policies are written in GAPL, and each has an effect of `permit` or `forbid`. The PDP returns a permit or deny decision. Sample condition snippets |
| G2 | GAPL reference | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference.md | current; `e3b59404f8f3097f…` | 2026-11-19 | GAPL is the language of policies and schema documents. A save checks only that the text parses |
| G3 | Policy statements | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/policy-statements.md | current; `9451d658306a77e6…` | 2026-11-19 | Effects and scope. Action lists and groups (`action in [...]`). `when`/`unless`. `@id`/`@reason` annotations, which appear in the Decisions log and in the AuthZEN response (`context.matchedPolicies[].policyName`, `context.reason`) |
| G4 | Values and types | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/values-and-types.md | current; `64035ee67c7fd80f…` | 2026-11-19 | The types: Bool, Long, String, Entity, Set ("Unordered, without duplicates"), Record and Extension. Set and record equality |
| G5 | Operators and expressions | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/operators-and-expressions.md | current; `a3fcc7d8f7de368f…` | 2026-11-19 | The page says it gives "Every GAPL operator, method, and expression form". Its list: `==` across types is false, not an error; `<`/`<=` on Long; `+ - *` on Long; short-circuit `&&`/`\|\|`; `in` (entity hierarchy); `has`; `like` (`*` matches any sequence); `is`; and the set methods `contains`, `containsAll`, `containsAny` and `isEmpty`. It lists no string concatenation, no set size, no iteration or quantifier, and no hash |
| G6 | Extension functions | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/extension-functions.md | current; `5a5291158b781dc6…` | 2026-11-19 | The only extension functions are `ip`, `decimal`, `datetime` and `duration` |
| G7 | The context record | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/context.md | current; `afe756a025b7475b…` | 2026-11-19 | JSON array → Set, object → Record, `null` → the key is left out. Action properties are added to `context` and replace a key with the same name |
| G8 | How statements are evaluated | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/evaluation.md | current; `de17e08e5be4e19b…` | 2026-11-19 | Any matching forbid → Forbid; else any permit → Permit; else Not applicable, which is denied (AuthZEN `false`). A statement that errors is skipped. Guard optional data with `has` |
| G9 | Schema language | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/gapl-reference/schema-language.md | current; `5fcd0e7b02f82de7…` | 2026-11-19 | Action groups (`action "read", ... in ["manage"]`) |
| G10 | Authorization PEP policy | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/evaluate/ask-for-a-decision/authorization-pep-policy.md | current (links to Gamma 4.13); `4b800df5401ab1f9…` | 2026-11-19 | How the gateway builds `principal`, `action`, `resource` and `context`. `context.agent`, `context.agent_origin`, and `context.agent_chain` ("a `Set` of `AgentIdentity` entities"). Context and action properties are mapped with EL. Only a permit lets a request through |
| G11 | Build principal relationships | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/authorization-management/manage/principals/build-principal-relationships.md | current; `1af0c289c43fcaef…` | 2026-11-19 | Parent groups drive `principal in Group::"..."` |
| G12 | Require human approval for MCP tool calls | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/agent-management/govern/require-human-approval-for-mcp-tool-calls.md | current; `53125a450d40cd9b…` | 2026-11-19 | Human-in-the-Loop approval rules (tool glob plus argument conditions) are an Agent Management gateway feature, configured apart from GAPL policies |
| G13 | OAuth 2.0 Token Exchange Configuration (Access Management 4.13) | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/am/guides/oauth-2.0-token-exchange-concepts/oauth-2.0-token-exchange-configuration-reference.md | AM 4.13; `1b1cfcef34be263b…` | 2026-11-19 | "Maximum Delegation Depth" limits the nesting of `act` claims at token exchange, as a per-domain setting |
| G14 | The Platform to Trust Your Agents (blog, Rory Blundell) | Gravitee.io (blog) | https://www.gravitee.io/blog/the-platform-to-trust-your-agents | published 2 June 2026, last updated 13 November 2026 | 2026-11-19 | Context only. Gamma introduces Authorization Management, and the policy engine runs as a library inside the gateways. No grade relies on it |
| G15 | Redefining Authorization Management for the Modern Agent-First Enterprise (blog, Kay James) | Gravitee.io (blog) | https://www.gravitee.io/blog/redefining-authorization-management-for-the-modern-agent-first-enterprise | published 8 July 2026, last updated 13 November 2026 | 2026-11-19 | Context only. Authorization Management arrived in Gravitee 4.12. No grade relies on it |
| G16 | documentation.gravitee.io llms.txt (documentation index) | Gravitee.io (documentation.gravitee.io) | https://documentation.gravitee.io/llms.txt | current | 2026-11-19 | Used to locate G2–G13. No claim relies on it |

**Not used.** A web search for "Gravitee GAPL" returns many pages under
`gravitee.io/corpus/gen-<n>/<slug>/...` (for example `.../gen-549/going-home-taj-mahal-album/gapl.html`).
These pages are not part of the documentation site or the blog. Their search snippets include
off-topic filler, and the one fetched (gen-549) returned HTTP 404 on 2026-11-19. Several of them
call GAPL "a subset of Cedar". The official pages G1–G13 do not say that, so neither analysis
claims it.

## Name clash: Intuit `identity-authz-apl`

**I1.** intuit/identity-authz-apl, "ABAC Policy Language".
- URL: https://github.com/intuit/identity-authz-apl
- Publisher: Intuit, on GitHub. MIT licence, Java. Created 2021-08-02. Last commit
  `745f2eba4d13` on 2025-04-23. Tags include `0.28`. Maven artifact `com.intuit.apl:apl-core`.
- Accessed: 2026-11-19 through the GitHub API (repository metadata and README).
- What it is: an attribute-based access control (ABAC) policy engine and language. Its README
  says "A policy consists of rules, which have "when" conditions and "then" actions". Rules
  test subject, resource and environment attributes (`sub[...]`, `res[...]`, `env[...]`), and
  each rule has a `salience`.
- The clash: it is also abbreviated "APL" (ABAC Policy Language). It is unrelated to OpenAPL, the
  Access Policy Language for agent delegation chains in this repository: different authors, a
  different model and a different file format. Its model is salience-ordered deny, permit and
  default rules over subject, resource and environment attributes. Its README does not mention
  delegation or chains (a search of the README for "delegat", "chain" and "on behalf" found no
  match). The paper cites it only to tell the two apart. It is not graded.
