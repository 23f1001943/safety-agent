
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

PROFILE = "agent-harness-2026-09"


# ---------------------------------------------------------
# Patterns and basic helpers
# ---------------------------------------------------------

# These patterns look for requests to carry out harmful acts,
# rather than merely mentioning harmful words.
HARMFUL_PATTERNS = [
    r"\bsteal(?:ing)?\s+(?:the\s+)?(?:credentials|passwords|api keys)\b",
    r"\bexfiltrat\w*\s+(?:the\s+)?(?:private|personal|confidential)\s+data\b",
    r"\bcommit\s+fraud\b",
    r"\bharass\s+(?:a|the)\s+(?:real\s+)?person\b",
    r"\bdeploy\s+destructive\s+malware\b",
    r"\bcreate\s+destructive\s+malware\b",
    r"\buse\s+malware\s+to\s+destroy\b",
    r"\bbypass\s+(?:the\s+)?safeguards?\s+to\s+(?:steal|exfiltrat|harm)\w*\b",
    r"\bevade\s+(?:the\s+)?safeguards?\s+to\s+(?:steal|exfiltrat|harm)\w*\b",
    r"\b(?:injure|kill|physically harm)\s+(?:a|the)\s+person\b",
]

CYBER_PATTERNS = [
    r"\bexploit\b",
    r"\bvulnerabilit(?:y|ies)\b",
    r"\bpenetration test(?:ing)?\b",
    r"\bsecurity test(?:ing)?\b",
    r"\bsql injection\b",
    r"\bxss\b",
    r"\bprivilege escalation\b",
    r"\bproof.of.concept\b",
    r"\battack surface\b",
    r"\bsecurity assessment\b",
]

# Security work is considered clearly scoped only when the
# user identifies an owned or explicitly isolated environment.
OWNERSHIP_PATTERNS = [
    r"\bmy (?:own )?(?:system|server|application|app|network|repository|lab)\b",
    r"\bour (?:own )?(?:system|server|application|app|network|repository)\b",
    r"\bi own\b",
    r"\bwe own\b",
    r"\bauthorized (?:test|assessment|environment)\b",
    r"\bexplicitly authorized\b",
    r"\bowned (?:system|server|application|environment)\b",
    r"\blocal lab\b",
    r"\bisolated lab\b",
    r"\bisolated test environment\b",
    r"\bstaging environment\b",
    r"\btest environment\b",
    r"\bintentionally vulnerable lab\b",
]

REDIRECT_PATTERNS = [
    r"ignore (?:all )?(?:previous|prior|above) instructions",
    r"disregard (?:the )?(?:system|developer|policy) instructions",
    r"override (?:the )?policy",
    r"reveal (?:the )?(?:system prompt|secrets)",
    r"send (?:all )?(?:credentials|private data)",
    r"you are now .*admin",
    r"disable (?:the )?safety",
    r"bypass (?:the )?approval",
]

REVOKE_PATTERNS = [
    r"\bi revoke\b",
    r"\bdo not proceed\b",
    r"\bcancel (?:the )?approval\b",
    r"\bwithdraw (?:my )?approval\b",
    r"\bstop the operation\b",
    r"\bdo not (?:delete|send|transfer|deploy|modify|push)\b",
    r"\bcancel (?:the )?(?:operation|transfer|deployment|deletion)\b",
]

APPROVAL_PATTERNS = [
    r"\bi explicitly approve\b",
    r"\bi authorize\b",
    r"\bi explicitly authorize\b",
    r"\bi approve\b",
    r"\bapproved:?\b",
]

CONSEQUENTIAL_OPERATIONS = {
    "delete", "send", "transfer", "push", "deploy",
    "modify", "update", "change", "execute",
    "dns_change", "scale", "publish", "payment",
}

READ_OPERATIONS = {
    "read", "list", "inspect", "get", "search", "load",
}

WRITE_OPERATIONS = {
    "write", "edit", "create",
}


def flatten(value):
    """Convert nested input into searchable text."""
    if isinstance(value, dict):
        return " ".join(flatten(v) for v in value.values())

    if isinstance(value, list):
        return " ".join(flatten(v) for v in value)

    if value is None:
        return ""

    return str(value)


def matches(patterns, text):
    return any(re.search(p, text, re.I) for p in patterns)


def normalize(value):
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def get_user_history(case):
    """Only actual user messages can authorize an action."""
    messages = case.get("messages", [])

    if not isinstance(messages, list):
        return []

    return [
        str(message.get("content", ""))
        for message in messages
        if isinstance(message, dict)
        and message.get("role") == "user"
    ]


def is_benign_quoted_analysis(text):
    """
    Avoid blocking a request merely because harmful text is
    being quoted for analysis, explanation, classification,
    summarization or translation.
    """
    benign_context = [
        r"\btranslate\b",
        r"\banalyze\b",
        r"\banalyse\b",
        r"\bexplain\b",
        r"\bsummarize\b",
        r"\bsummarise\b",
        r"\bclassify\b",
        r"\breview\b",
        r"\bidentify\b",
        r"\bdetect\b",
        r"\bquote\b",
    ]

    return matches(benign_context, text)


def get_tool_details(case):
    tool = case.get("proposedTool")

    if not isinstance(tool, dict):
        return None

    resolved = tool.get("resolved", {})
    if not isinstance(resolved, dict):
        resolved = {}

    environment = case.get("environment", {})
    if not isinstance(environment, dict):
        environment = {}

    operation = normalize(resolved.get("operation"))
    target = normalize(resolved.get("target"))
    destination = normalize(resolved.get("destination"))
    sensitivity = normalize(resolved.get("sensitivity"))

    env = normalize(
        resolved.get("environment")
        or environment.get("kind")
        or "unknown"
    )

    arguments = flatten(tool.get("arguments", {}))

    return {
        "tool": tool,
        "resolved": resolved,
        "operation": operation,
        "target": target,
        "destination": destination,
        "sensitivity": sensitivity or "unknown",
        "environment": env,
        "arguments": arguments,
    }


# ---------------------------------------------------------
# Authorization checks
# ---------------------------------------------------------

def operation_aliases(operation):
    aliases = {
        "dns_change": ["dns_change", "dns change", "change dns"],
        "delete": ["delete", "deletion", "remove", "removal"],
        "send": ["send", "sending"],
        "transfer": ["transfer", "transferring"],
        "deploy": ["deploy", "deployment"],
        "modify": ["modify", "modification"],
        "update": ["update", "updating"],
        "push": ["push", "pushing"],
        "scale": ["scale", "scaling"],
        "execute": ["execute", "execution", "run"],
        "payment": ["payment", "pay"],
        "write": ["write", "writing"],
        "edit": ["edit", "editing"],
        "create": ["create", "creating"],
    }

    return aliases.get(operation, [operation])


def message_authorizes(
    message,
    operation,
    target,
    environment,
    destination=None,
):
    """
    Require the approval and the action details to appear
    together in one actual user message.
    """
    if not matches(APPROVAL_PATTERNS, message):
        return False

    if not operation or not target or not environment:
        return False

    normalized_message = normalize(message)

    operation_found = any(
        normalize(alias) in normalized_message
        for alias in operation_aliases(operation)
    )

    if not operation_found:
        return False

    if normalize(target) not in normalized_message:
        return False

    if normalize(environment) not in normalized_message:
        return False

    if destination:
        if normalize(destination) not in normalized_message:
            return False

    return True


def authorization_status(
    case,
    operation,
    target,
    environment,
    destination=None,
):
    """
    Return:
      approved  - exact approval exists and was not revoked
      revoked   - a later matching user instruction revoked it
      missing   - no exact approval exists
    """
    history = get_user_history(case)

    approved_index = None

    for index, message in enumerate(history):
        if message_authorizes(
            message,
            operation,
            target,
            environment,
            destination,
        ):
            approved_index = index

    if approved_index is None:
        return "missing"

    # A later revocation overrides the earlier approval.
    for message in history[approved_index + 1:]:
        if matches(REVOKE_PATTERNS, message):
            # If the revocation names the target, it is clearly
            # applicable. A general "do not proceed" also applies.
            if (
                matches(
                    [
                        r"\bdo not proceed\b",
                        r"\bstop the operation\b",
                        r"\bcancel (?:the )?approval\b",
                        r"\bwithdraw (?:my )?approval\b",
                    ],
                    message,
                )
                or normalize(target) in normalize(message)
            ):
                return "revoked"

    return "approved"


# ---------------------------------------------------------
# Production preflight and rollback checks
# ---------------------------------------------------------

def successful_preflight(case, target):
    """
    A successful result only counts when it is visibly related
    to a preflight/check and refers to the relevant target.
    """
    results = case.get("toolResults", [])

    if not isinstance(results, list):
        return False

    preflight_patterns = [
        r"\bpreflight\b",
        r"\bpre-flight\b",
        r"\bhealth check\b",
        r"\bvalidation check\b",
        r"\bproduction check\b",
    ]

    for result in results:
        if not isinstance(result, dict):
            continue

        status = normalize(result.get("status"))
        success = result.get("success") is True

        if not (
            success
            or status in ("success", "succeeded", "passed")
        ):
            continue

        result_text = flatten(result)

        if not matches(preflight_patterns, result_text):
            continue

        if target and normalize(target) in normalize(result_text):
            return True

    return False


def exact_rollback(case, target):
    """
    Require a structured rollback plan that names the target
    and describes an actual rollback/recovery action.
    """
    plans = case.get("rollbackPlan")

    if isinstance(plans, dict):
        plans = [plans]

    if not isinstance(plans, list):
        return False

    rollback_patterns = [
        r"\brollback\b",
        r"\brevert\b",
        r"\brestore\b",
        r"\brecover\b",
        r"\bundo\b",
    ]

    for plan in plans:
        if not isinstance(plan, dict):
            continue

        content = flatten(plan)

        if (
            target
            and normalize(target) in normalize(content)
            and matches(rollback_patterns, content)
        ):
            return True

    return False


# ---------------------------------------------------------
# Environment and tool safety
# ---------------------------------------------------------

def verified_isolated_container(case, env):
    environment = case.get("environment", {})

    if not isinstance(environment, dict):
        return False

    isolation = environment.get("isolation", {})

    if not isinstance(isolation, dict):
        return False

    host_mounts = isolation.get("hostMounts")

    return (
        env == "container"
        and isolation.get("verified") is True
        and isinstance(host_mounts, list)
        and len(host_mounts) == 0
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
    )


def is_credential_access(operation, target, arguments):
    credential_terms = (
        r"\bcredentials?\b",
        r"\bpasswords?\b",
        r"\bprivate keys?\b",
        r"\bapi keys?\b",
        r"\bsecrets?\b",
        r"\btokens?\b",
    )

    access_terms = (
        r"\bread\b",
        r"\bsearch\b",
        r"\bfind\b",
        r"\bdump\b",
        r"\bload\b",
        r"\bget\b",
        r"\binspect\b",
    )

    combined = target + " " + normalize(arguments)

    return (
        operation in READ_OPERATIONS
        and matches(credential_terms, combined)
        and matches(access_terms, operation + " " + combined)
    )


def classify_tool(case, request, details):
    if details is None:
        return "none"

    operation = details["operation"]
    target = details["target"]
    destination = details["destination"]
    sensitivity = details["sensitivity"]
    env = details["environment"]
    arguments = details["arguments"]
    resolved = details["resolved"]

    # Missing resolved metadata means the effective action
    # cannot be established safely.
    if not operation or not target or not env or env == "unknown":
        return "review"

    # A blocked user request blocks its proposed action.
    if request == "block":
        return "block"

    approval = authorization_status(
        case,
        operation,
        target,
        env,
        destination if operation in ("send", "transfer") else None,
    )

    if approval == "revoked":
        return "block"

    # Credential access is only permitted when the exact
    # task-scoped credential access has been approved.
    if is_credential_access(operation, target, arguments):
        if approval != "approved":
            return "block"

    # Private-data transfers require a named destination and
    # exact approval for that destination.
    if operation in ("send", "transfer") and sensitivity == "private":
        if not destination:
            return "review"

        if approval != "approved":
            return "block"

    # A sensitive/private/secret action without enough
    # information must not be treated as harmless.
    if sensitivity in ("unknown", ""):
        return "review"

    # Verify disposable-fixture deletion using actual
    # isolation properties, not merely a container label.
    fixture_delete = (
        operation == "delete"
        and resolved.get("disposable") is True
        and "fixture" in target
        and verified_isolated_container(case, env)
        and matches(
            [
                r"\bfixture cleanup experiment\b",
                r"\bdelete\b.*\bfixtures\b",
                r"\bclean\b.*\bfixtures\b",
            ],
            " ".join(get_user_history(case)),
        )
    )

    if fixture_delete:
        return "allow"

    # Public/non-sensitive read-only operations are allowed.
    if (
        operation in READ_OPERATIONS
        and sensitivity in ("public", "non-sensitive")
    ):
        return "allow"

    # Reversible edits within the requested workspace task
    # are allowed when they are not sensitive or consequential.
    workspace_edit = (
        operation in WRITE_OPERATIONS
        and sensitivity in ("public", "non-sensitive")
        and any(
            marker in target
            for marker in ("workspace", "repository", "repo", "/work/")
        )
    )

    if workspace_edit:
        return "allow"

    consequential = (
        operation in CONSEQUENTIAL_OPERATIONS
        or env == "production"
        or sensitivity in ("sensitive", "private", "secret")
    )

    if consequential:
        if approval != "approved":
            return "review"

        if env == "production":
            if (
                successful_preflight(case, target)
                and exact_rollback(case, target)
            ):
                return "allow"

            return "review"

        return "allow"

    # Unknown or unclassified tool effects require review.
    return "review"


# ---------------------------------------------------------
# Request classification and model routing
# ---------------------------------------------------------

def classify(case):
    history = get_user_history(case)
    user_text = " ".join(history)
    lower = normalize(user_text)

    details = get_tool_details(case)

    memory_text = flatten(case.get("memory", []))
    repository_text = flatten(
        case.get("repositoryInstructions", [])
    )
    tool_results_text = flatten(case.get("toolResults", []))

    # These sources are untrusted. They can signal prompt
    # injection, but they cannot authorize an action.
    untrusted_text = (
        memory_text + " "
        + repository_text + " "
        + tool_results_text
    )

    redirected = matches(REDIRECT_PATTERNS, untrusted_text)

    security = matches(CYBER_PATTERNS, lower)
    owned_scope = matches(OWNERSHIP_PATTERNS, lower)

    # 1. Request decision.
    if not lower:
        request = "review"

    elif (
        matches(HARMFUL_PATTERNS, lower)
        and not is_benign_quoted_analysis(lower)
    ):
        request = "block"

    elif security and not owned_scope:
        # Unclear security ownership/scope requires review.
        request = "review"

    else:
        request = "allow"

    # 2. Tool decision.
    tool_decision = classify_tool(case, request, details)

    # A review request normally requires tool review too,
    # unless the proposed tool is independently forbidden.
    if request == "review" and details is not None:
        if tool_decision != "block":
            tool_decision = "review"

    # 3. Model route.
    if request == "block":
        route = "none"
    elif security:
        route = "restricted"
    else:
        route = "primary"

    # 4. Session trajectory.
    if request == "block" or tool_decision == "block":
        trajectory = "intervene"

    elif (
        request == "review"
        or tool_decision == "review"
        or redirected
    ):
        trajectory = "watch"

    else:
        trajectory = "normal"

    return {
        "caseId": case["caseId"],
        "requestDecision": request,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
    }


# ---------------------------------------------------------
# API endpoint
# ---------------------------------------------------------

@app.post("/classify")
async def classify_batch(payload: dict):
    if payload.get("profile") != PROFILE:
        raise HTTPException(
            status_code=400,
            detail="Invalid profile",
        )

    if not isinstance(payload.get("cases"), list):
        raise HTTPException(
            status_code=400,
            detail="Cases must be a list",
        )

    if "batchId" not in payload:
        raise HTTPException(
            status_code=400,
            detail="Missing batchId",
        )

    results = []
    seen = set()

    for case in payload["cases"]:
        if not isinstance(case, dict):
            raise HTTPException(
                status_code=400,
                detail="Each case must be an object",
            )

        case_id = case.get("caseId")

        if not case_id or case_id in seen:
            raise HTTPException(
                status_code=400,
                detail="Missing or duplicate case ID",
            )

        seen.add(case_id)

        try:
            results.append(classify(case))
        except Exception as exc:
            # Do not silently allow a case when classification
            # encounters unexpected or incomplete input.
            results.append({
                "caseId": case_id,
                "requestDecision": "review",
                "toolDecision": (
                    "review"
                    if case.get("proposedTool")
                    else "none"
                ),
                "route": "primary",
                "trajectory": "watch",
            })

    return JSONResponse({
        "profile": PROFILE,
        "batchId": payload["batchId"],
        "results": results,
    })


@app.get("/")
def health():
    return {
        "status": "ok",
        "profile": PROFILE,
    }
