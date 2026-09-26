"""FastAPI application exposing POST /normalize, /evaluate, /compare,
/audit-rules, /minimize-policy, /allocate, /anonymize and
/reverse-delegations."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.policy import (
    allocate,
    anonymize,
    audit_rules,
    compare,
    evaluate,
    minimize_policy,
    normalize,
    reverse_delegations,
)
from app.schemas import (
    AddressDecision,
    AllocateRequest,
    AllocateResponse,
    AnonymizeRequest,
    AnonymizeResponse,
    AuditRulesRequest,
    AuditRulesResponse,
    CompareRequest,
    CompareResponse,
    EvaluateRequest,
    MinimizePolicyRequest,
    MinimizePolicyResponse,
    NormalizeResponse,
    PolicyRequest,
    ReverseDelegationsRequest,
    ReverseDelegationsResponse,
)

app = FastAPI(
    title="CIDR Policy Normalizer",
    description=(
        "Compute allow-minus-deny for IPv4/IPv6 CIDR lists, returning the "
        "equivalent, non-overlapping, minimum-count CIDR set; evaluate "
        "individual addresses against the same lists via longest-prefix "
        "match; diff two policy sets (baseline vs candidate) over a "
        "scope CIDR; audit each allow/deny rule for its real impact inside "
        "one scope; minimize an allow/deny list to the smallest subset "
        "equivalent inside one scope; allocate non-overlapping subnets "
        "for a list of requests inside one scope, avoiding already-occupied "
        "CIDRs; prefix-preservingly anonymize bare IPv4/IPv6 addresses "
        "and strict CIDRs with an HMAC-SHA256 key for safe list sharing; "
        "and plan reverse-DNS delegations for the IPv4 networks of one /24 "
        "(direct in-addr.arpa NS for a /24, RFC 2317 range-label subzones "
        "plus per-address CNAMEs for /25-/32)."
    ),
    version="1.7.0",
)


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/normalize",
    response_model=NormalizeResponse,
    tags=["policy"],
    summary="Normalize allow/deny CIDR lists into allow minus deny",
)
def normalize_policy(request: PolicyRequest) -> dict:
    return normalize(request.allow, request.deny)


@app.post(
    "/evaluate",
    response_model=list[AddressDecision],
    tags=["policy"],
    summary="Evaluate addresses by longest-prefix match against allow/deny",
    openapi_extra={
        # FastAPI drops Body(examples=...) for model-typed parameters, so the
        # named request examples are attached via openapi_extra; FastAPI merges
        # them into the generated requestBody alongside the schema $ref.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins equal-length ties",
                            "value": {
                                "allow": [
                                    "10.0.0.0/24", "10.0.0.0/25",
                                    "2001:db8::/32",
                                ],
                                "deny": ["10.0.0.0/25"],
                                "addresses": [
                                    "10.0.0.1", "10.0.0.200",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                            },
                        },
                        "invalid_address": {
                            "summary": "CIDR notation in addresses -> HTTP 422",
                            "value": {
                                "allow": ["10.0.0.0/8"],
                                "deny": [],
                                "addresses": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": "One decision per input address, in input order.",
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins ties",
                            "value": [
                                {"decision": "deny",
                                 "matched_cidr": "10.0.0.0/25",
                                 "matched_side": "deny"},
                                {"decision": "allow",
                                 "matched_cidr": "10.0.0.0/24",
                                 "matched_side": "allow"},
                                {"decision": "unmatched",
                                 "matched_cidr": None,
                                 "matched_side": None},
                                {"decision": "allow",
                                 "matched_cidr": "2001:db8::/32",
                                 "matched_side": "allow"},
                            ],
                        },
                    },
                },
            },
        },
        422: {"description": "An address or CIDR in the request is invalid."},
    },
)
def evaluate_policy(request: EvaluateRequest) -> list[dict]:
    return evaluate(request.allow, request.deny, request.addresses)


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["policy"],
    summary="Diff baseline vs candidate decisions within a scope CIDR",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": (
                                "Candidate denies a /26 inside the baseline "
                                "allow; deny wins the equal-length tie below"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {
                                    "allow": ["10.0.0.0/24"],
                                    "deny": [],
                                },
                                "candidate": {
                                    "allow": ["10.0.0.0/25"],
                                    "deny": ["10.0.0.128/26"],
                                },
                            },
                        },
                        "identical_policies": {
                            "summary": "Identical sets -> no differences",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {"allow": ["10.0.0.0/24"]},
                                "candidate": {"allow": ["10.0.0.0/24"]},
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Differing regions within scope, sibling-merged per "
                "transition type, plus per-transition address totals."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": "Two allow->deny regions",
                            "value": {
                                "differences": [
                                    {"cidr": "10.0.0.128/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "deny"},
                                    {"cidr": "10.0.0.192/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "unmatched"},
                                ],
                                "transition_counts": {
                                    "allow->deny": "64",
                                    "allow->unmatched": "64",
                                    "deny->allow": "0",
                                    "deny->unmatched": "0",
                                    "unmatched->allow": "0",
                                    "unmatched->deny": "0",
                                },
                            },
                        },
                    },
                },
            },
        },
        422: {"description": "The scope or a CIDR entry is invalid."},
    },
)
def compare_policies(request: CompareRequest) -> dict:
    return compare(
        request.scope,
        request.baseline.allow,
        request.baseline.deny,
        request.candidate.allow,
        request.candidate.deny,
    )


@app.post(
    "/audit-rules",
    response_model=AuditRulesResponse,
    tags=["policy"],
    summary="Classify each allow/deny rule by its real impact inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": (
                                "A broad allow wins where no deny reaches; an "
                                "equal-length allow is shadowed by the deny; "
                                "a disjoint rule is out of scope; duplicate "
                                "allows keep the earliest copy"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                    "10.0.0.0/25",
                                ],
                                "deny": [
                                    "10.0.0.0/25",
                                    "10.1.0.0/16",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One audit result per input rule, grouped by input side and "
                "kept in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "effective_shadowed_and_out_of_scope": {
                            "summary": "Witness IPs and shadower index sets",
                            "value": {
                                "allow": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "status": "effective",
                                     "witness": "10.0.0.128"},
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                    {"side": "allow", "index": 2,
                                     "cidr": "10.0.0.0/25",
                                     "status": "shadowed",
                                     "shadowed_by": [
                                         {"side": "deny", "index": 0}]},
                                ],
                                "deny": [
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.0/25",
                                     "status": "effective",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 1,
                                     "cidr": "10.1.0.0/16",
                                     "status": "out_of_scope"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, or a rule whose address family does "
                "not match the scope."
            ),
        },
    },
)
def audit_policy_rules(request: AuditRulesRequest) -> dict:
    return audit_rules(request.scope, request.allow, request.deny)


@app.post(
    "/minimize-policy",
    response_model=MinimizePolicyResponse,
    tags=["policy"],
    summary=(
        "Reduce allow/deny rules to the minimum subset equivalent in a scope"
    ),
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": (
                                "Two overlapping allows are redundant; "
                                "lexicographically smallest (side, index) "
                                "set is retained with witnesses"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/24",
                                    "10.0.0.0/25",
                                ],
                                "deny": ["10.0.0.128/25"],
                            },
                        },
                        "too_many_rules": {
                            "summary": "More than 16 rules total -> HTTP 422",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "allow": [
                                    "10.0.0.0/26", "10.0.0.64/26",
                                    "10.0.0.128/26", "10.0.0.192/26",
                                    "10.0.0.0/27", "10.0.0.32/27",
                                    "10.0.0.64/27", "10.0.0.96/27",
                                    "10.0.0.128/27",
                                ],
                                "deny": [
                                    "10.0.0.160/27", "10.0.0.192/27",
                                    "10.0.0.224/27", "10.0.0.0/28",
                                    "10.0.0.16/28", "10.0.0.32/28",
                                    "10.0.0.48/28", "10.0.0.80/28",
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "The unique minimum-cardinality rule subset, with retained "
                "and removed references in original input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "minimum_subset_with_witnesses": {
                            "summary": "allow index 0 covers the lower half",
                            "value": {
                                "retained": [
                                    {"side": "allow", "index": 0,
                                     "cidr": "10.0.0.0/24",
                                     "witness": "10.0.0.0"},
                                    {"side": "deny", "index": 0,
                                     "cidr": "10.0.0.128/25",
                                     "witness": "10.0.0.128"},
                                ],
                                "removed": [
                                    {"side": "allow", "index": 1,
                                     "cidr": "10.0.0.0/25"},
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "Invalid scope/rule CIDR, a rule whose address family does "
                "not match the scope, or more than 16 allow/deny rules in "
                "total."
            ),
        },
    },
)
def minimize_policy_rules(request: MinimizePolicyRequest) -> dict:
    return minimize_policy(request.scope, request.allow, request.deny)


@app.post(
    "/allocate",
    response_model=AllocateResponse,
    tags=["policy"],
    summary="Allocate non-overlapping subnets for requests inside a scope",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": (
                                "Greedy first-fit for 'small' would block "
                                "'big'; backtracking finds the lexicographically"
                                " smallest complete plan"
                            ),
                            "value": {
                                "scope": "10.0.0.0/23",
                                "occupied": ["10.0.1.0/25"],
                                "requests": [
                                    {"id": "small", "prefix_length": 25},
                                    {"id": "big", "prefix_length": 24},
                                ],
                            },
                        },
                        "infeasible": {
                            "summary": "Two /25s do not fit beside the occupied /25 -> HTTP 409",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "occupied": ["10.0.0.0/25"],
                                "requests": [
                                    {"id": "x", "prefix_length": 25},
                                    {"id": "y", "prefix_length": 25},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Allocations in request order plus the remaining free space "
                "as a minimal CIDR set with its decimal address count."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "lexicographic_with_backtracking": {
                            "summary": "Lexicographically smallest complete plan",
                            "value": {
                                "allocations": [
                                    {"id": "small", "cidr": "10.0.1.128/25"},
                                    {"id": "big", "cidr": "10.0.0.0/24"},
                                ],
                                "remaining": [],
                                "remaining_addresses": "0",
                            },
                        },
                    },
                },
            },
        },
        409: {
            "description": (
                "No complete assignment exists; no partial allocation is "
                "returned."
            ),
        },
        422: {
            "description": (
                "Invalid scope/occupied CIDR, occupied entry outside the "
                "scope or of the wrong family, overlapping occupied CIDRs, "
                "duplicate request id, or invalid prefix length."
            ),
        },
    },
)
def allocate_subnets(request: AllocateRequest) -> dict:
    result = allocate(
        request.scope,
        request.occupied,
        [(item.id, item.prefix_length) for item in request.requests],
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"no complete allocation satisfies all requests within "
                f"scope {request.scope!r}; no partial allocation returned"
            ),
        )
    return result


@app.post(
    "/anonymize",
    response_model=AnonymizeResponse,
    tags=["policy"],
    summary="Prefix-preserving keyed anonymization of addresses and CIDRs",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "prefix_preserving_v4_and_v6": {
                            "summary": (
                                "Stable one-to-one mapping; the /24 keeps its "
                                "anonymized network address prefix and length"
                            ),
                            "value": {
                                "key_hex": (
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                    "0123456789abcdef"
                                ),
                                "addresses": [
                                    "10.0.0.1", "10.0.0.2",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                                "cidrs": ["10.0.0.0/24", "2001:db8::/32"],
                            },
                        },
                        "host_bits_set": {
                            "summary": "Non-zero host bits in a CIDR -> HTTP 422",
                            "value": {
                                "key_hex": "0" * 64,
                                "addresses": [],
                                "cidrs": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One anonymized entry per input address and per input CIDR, "
                "each list in input order."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "prefix_preserving_v4_and_v6": {
                            "summary": (
                                "Stable one-to-one outputs; the two /24-mates "
                                "keep their /30 longest common prefix and stay "
                                "inside the anonymized 77.249.170.0/24"
                            ),
                            "value": {
                                "addresses": [
                                    "77.249.170.48",
                                    "77.249.170.51",
                                    "236.60.54.68",
                                    "d5af:46c8:beb3:e56d:c681:ca26:c4a4:9e2a",
                                ],
                                "cidrs": [
                                    "77.249.170.0/24",
                                    "d5af:46c8::/32",
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "key_hex is not 64 hexadecimal characters, an address is "
                "invalid, or a CIDR is invalid, lacks a prefix length, or "
                "has non-zero host bits."
            ),
        },
    },
)
def anonymize_addresses(request: AnonymizeRequest) -> dict:
    return anonymize(request.key_hex, request.addresses, request.cidrs)


@app.post(
    "/reverse-delegations",
    response_model=ReverseDelegationsResponse,
    tags=["policy"],
    summary="Plan reverse-DNS delegations for IPv4 /24-/32 networks in one /24",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "direct_slash24": {
                            "summary": (
                                "A /24 delegates its in-addr.arpa zone "
                                "directly with NS records"
                            ),
                            "value": {
                                "delegations": [
                                    {"cidr": "192.0.2.0/24",
                                     "nameservers": ["ns1.example.net",
                                                     "ns2.example.net"]},
                                ],
                            },
                        },
                        "rfc2317_subzones": {
                            "summary": (
                                "Disjoint /25-/32 networks in one /24 use RFC "
                                "2317 range labels, each with NS records and "
                                "per-address parent-zone CNAMEs"
                            ),
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.128/30",
                                     "nameservers": ["ns1.cust.example",
                                                     "ns2.cust.example"]},
                                    {"cidr": "10.0.0.5/32",
                                     "nameservers": ["host-5.example.org"]},
                                ],
                            },
                        },
                        "overlapping_cidrs_rejected": {
                            "summary": "Intersecting CIDRs -> HTTP 422, whole batch rejected",
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.0/25",
                                     "nameservers": ["ns1.example.net"]},
                                    {"cidr": "10.0.0.64/26",
                                     "nameservers": ["ns2.example.net"]},
                                ],
                            },
                        },
                        "different_parent_24_rejected": {
                            "summary": "CIDRs from two /24s -> HTTP 422",
                            "value": {
                                "delegations": [
                                    {"cidr": "10.0.0.0/25",
                                     "nameservers": ["ns1.example.net"]},
                                    {"cidr": "10.0.1.0/25",
                                     "nameservers": ["ns2.example.net"]},
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "One delegated zone per input CIDR plus the NS/CNAME records, "
                "sorted by network address; each record carries its source "
                "input CIDR."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "direct_slash24": {
                            "summary": "Direct in-addr.arpa NS delegation for a /24",
                            "value": {
                                "zones": [{
                                    "zone": "2.0.192.in-addr.arpa.",
                                    "method": "direct",
                                    "parent_zone": None,
                                    "cidr": "192.0.2.0/24",
                                    "nameservers": [
                                        "ns1.example.net.",
                                        "ns2.example.net.",
                                    ],
                                }],
                                "records": [
                                    {
                                        "zone": "2.0.192.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "2.0.192.in-addr.arpa.",
                                        "target": "ns1.example.net.",
                                        "cidr": "192.0.2.0/24",
                                    },
                                    {
                                        "zone": "2.0.192.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "2.0.192.in-addr.arpa.",
                                        "target": "ns2.example.net.",
                                        "cidr": "192.0.2.0/24",
                                    },
                                ],
                            },
                        },
                        "rfc2317_subzones": {
                            "summary": "Two RFC 2317 subzones (/32 and /30) in one /24",
                            "value": {
                                "zones": [
                                    {
                                        "zone": "5/32.0.0.10.in-addr.arpa.",
                                        "method": "rfc2317",
                                        "parent_zone": "0.0.10.in-addr.arpa.",
                                        "cidr": "10.0.0.5/32",
                                        "nameservers": ["host-5.example.org."],
                                    },
                                    {
                                        "zone": "128/30.0.0.10.in-addr.arpa.",
                                        "method": "rfc2317",
                                        "parent_zone": "0.0.10.in-addr.arpa.",
                                        "cidr": "10.0.0.128/30",
                                        "nameservers": [
                                            "ns1.cust.example.",
                                            "ns2.cust.example.",
                                        ],
                                    },
                                ],
                                "records": [
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "5/32.0.0.10.in-addr.arpa.",
                                        "target": "host-5.example.org.",
                                        "cidr": "10.0.0.5/32",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "5.0.0.10.in-addr.arpa.",
                                        "target": "5.5/32.0.0.10.in-addr.arpa.",
                                        "cidr": "10.0.0.5/32",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "128/30.0.0.10.in-addr.arpa.",
                                        "target": "ns1.cust.example.",
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "NS",
                                        "name": "128/30.0.0.10.in-addr.arpa.",
                                        "target": "ns2.cust.example.",
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "128.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "128.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "129.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "129.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "130.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "130.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                    {
                                        "zone": "0.0.10.in-addr.arpa.",
                                        "type": "CNAME",
                                        "name": "131.0.0.10.in-addr.arpa.",
                                        "target": (
                                            "131.128/30.0.0.10.in-addr.arpa."
                                        ),
                                        "cidr": "10.0.0.128/30",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        422: {
            "description": (
                "A CIDR is not a strict IPv4 /24-/32 network, a nameserver is "
                "not a valid domain name, two CIDRs intersect, or the CIDRs "
                "do not share one parent /24."
            ),
        },
    },
)
def plan_reverse_delegations(request: ReverseDelegationsRequest) -> dict:
    return reverse_delegations(
        [(item.cidr, item.nameservers) for item in request.delegations]
    )
