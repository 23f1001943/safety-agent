
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

PROFILE = "agent-harness-2026-09"

HARMFUL_PATTERNS = [
    r"steal credentials",
    r"exfiltrat\w+.*private data",
    r"commit fraud",
    r"harass .*person",
    r"destructive malware",
    r"evade safeguards",
    r"bypass safeguards.*(?:steal|exfiltrat|harm)",
    r"harm (?:a|the) person",
]

CYBER_PATTERNS = [
    r"\bexploit\b", r"\bvulnerability\b",
    r"\bpenetration test\b", r"\bsecurity test\b",
    r"\bsql injection\b", r"\bxss\b",
    r"\bprivilege escalation\b", r"\bproof.of.concept\b",
]

REDIRECT_PATTERNS = [
    r"ignore (?:all )?(?:previous|prior|above) instructions",
    r"disregard (?:the )?(?:system|developer|policy) instructions",
    r"override (?:the )?policy",
    r"reveal (?:the )?(?:system prompt|secrets)",
    r"send (?:all )?(?:credentials|private data)",
    r"you are now .*admin",
]

REVOKE_PATTERNS = [
    r"\bI revoke\b",
    r"\bdo not proceed\b",
    r"\bcancel (?:the )?approval\b",
    r"\bwithdraw (?:my )?approval\b",
    r"\bstop the operation\b",
]

APPROVAL_PATTERNS = [
    r"\bI explicitly approve\b",
    r"\bI authorize\b",
    r"\bI explicitly authorize\b",
    r"\bapproved:?\b",
]


def flatten(value):
    if isinstance(value, dict):
        return " ".join(flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten(v) for v in value)
    return str(value) if value is not None else ""


def matches(patterns, text):
    return any(re.search(p, text, re.I) for p in patterns)


def get_user_history(case):
    return [
        str(m.get("content", ""))
        for m in case.get("messages", [])
        if m.get("role") == "user"
    ]


def explicit_approval(case, operation, target, environment):
    history = get_user_history(case)

    if not history:
        return False

    # A later revocation overrides earlier approval.
    latest_relevant = " ".join(history)

    revoke_positions = [
        m.start()
        for p in REVOKE_PATTERNS
        for m in re.finditer(p, latest_relevant, re.I)
    ]

    approval_positions = [
        m.start()
        for p in APPROVAL_PATTERNS
        for m in re.finditer(p, latest_relevant, re.I)
    ]

    if not approval_positions:
        return False

    if revoke_positions and max(revoke_positions) > max(approval_positions):
        return False

    # Approval must identify the exact operation, target and environment.
    combined = " ".join(history).lower()

    required = [
        str(operation).lower(),
        str(target).lower(),
        str(environment).lower(),
    ]

    return all(x and x in combined for x in required)


def successful_preflight(case):
    for result in case.get("toolResults", []):
        if not isinstance(result, dict):
            continue

        # Only structured observations count.
        status = str(result.get("status", "")).lower()
        success = result.get("success") is True

        if success or status in ("success", "succeeded", "passed"):
            return True

    return False


def exact_rollback(case, target):
    for plan in case.get("rollbackPlan", []) if isinstance(
        case.get("rollbackPlan"), list
    ) else [case.get("rollbackPlan")]:
        if isinstance(plan, dict):
            content = flatten(plan).lower()
            if target.lower() in content and content.strip():
                return True
    return False


def classify(case):
    history = get_user_history(case)
    user_text = " ".join(history)
    lower = user_text.lower()

    tool = case.get("proposedTool")
    environment = case.get("environment", {})

    # Detect untrusted attempts to redirect the session.
    untrusted = flatten(
        case.get("memory", [])
    ) + flatten(
        case.get("repositoryInstructions", [])
    ) + flatten(
        case.get("toolResults", [])
    )

    redirected = matches(REDIRECT_PATTERNS, untrusted)

    security = matches(CYBER_PATTERNS, lower)

    # 1. Request classification.
    if matches(HARMFUL_PATTERNS, lower):
        request = "block"
    elif not user_text.strip():
        request = "review"
    elif security:
        request = "allow"
    else:
        request = "allow"

    # 2. No proposed tool.
    if not tool:
        tool_decision = "none"
    else:
        resolved = tool.get("resolved", {})
        operation = str(resolved.get("operation", "")).lower()
        target = str(resolved.get("target", ""))
        destination = str(resolved.get("destination", ""))
        sensitivity = str(
            resolved.get("sensitivity", "unknown")
        ).lower()
        env = str(
            resolved.get("environment", environment.get("kind", "unknown"))
        ).lower()

        args = flatten(tool.get("arguments", {})).lower()

        # Inspect credentials and forbidden transfers.
        credential_read = (
            matches([r"read", r"search", r"find", r"dump"], operation)
            and matches([
                r"credentials", r"passwords", r"private keys",
                r"unrelated secrets", r"api keys"
            ], target + " " + args)
        )

        forbidden_transfer = (
            sensitivity == "private"
            and destination
            and not explicit_approval(
                case, operation, target, env
            )
        )

        forbidden = (
            request == "block"
            or credential_read
            or forbidden_transfer
        )

        if forbidden:
            tool_decision = "block"

        elif not operation or not target or env == "unknown":
            tool_decision = "review"

        else:
            iso = environment.get("isolation", {})
            isolated = (
                env == "container"
                and iso.get("verified") is True
                and not iso.get("hostMounts")
                and iso.get("credentials") is False
                and iso.get("externalNetwork") is False
            )

            fixture_delete = (
                operation == "delete"
                and resolved.get("disposable") is True
                and isolated
                and "fixture" in target.lower()
                and matches([
                    r"fixture.cleanup experiment",
                    r"delete.*fixtures",
                    r"clean.*fixtures"
                ], lower)
            )

            readonly = operation in (
                "read", "list", "inspect", "get", "search"
            )

            workspace_edit = (
                operation in ("write", "edit", "create")
                and sensitivity != "private"
                and any(x in target.lower() for x in (
                    "workspace", "repository", "repo", "/work/"
                ))
            )

            consequential = (
                operation in (
                    "delete", "send", "transfer", "push",
                    "deploy", "modify", "update", "change",
                    "execute", "dns_change", "scale"
                )
                or env == "production"
                or sensitivity in ("sensitive", "private", "secret")
            )

            approved = explicit_approval(
                case, operation, target, env
            )

            if fixture_delete:
                tool_decision = "allow"

            elif readonly and sensitivity in ("public", "non-sensitive"):
                tool_decision = "allow"

            elif workspace_edit and not consequential:
                tool_decision = "allow"

            elif consequential:
                if not approved:
                    tool_decision = "review"

                elif env == "production":
                    if (
                        successful_preflight(case)
                        and exact_rollback(case, target)
                    ):
                        tool_decision = "allow"
                    else:
                        tool_decision = "review"
                else:
                    tool_decision = "allow"

            else:
                tool_decision = "review"

    # 3. A blocked request always blocks its proposed tool.
    if request == "block" and tool:
        tool_decision = "block"

    # 4. Model route.
    if request == "block":
        route = "none"
    elif security:
        route = "restricted"
    else:
        route = "primary"

    # 5. Trajectory.
    if request == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif (
        request == "review"
        or tool_decision == "review"
        or security and "unclear" in lower
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
        "trajectory": trajectory
    }


@app.post("/classify")
async def classify_batch(payload: dict):
    if payload.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="Invalid profile")

    if not isinstance(payload.get("cases"), list):
        raise HTTPException(status_code=400, detail="Cases must be a list")

    results = []
    seen = set()

    for case in payload["cases"]:
        case_id = case.get("caseId")

        if not case_id or case_id in seen:
            raise HTTPException(
                status_code=400,
                detail="Missing or duplicate case ID"
            )

        seen.add(case_id)
        results.append(classify(case))

    return JSONResponse({
        "profile": PROFILE,
        "batchId": payload["batchId"],
        "results": results
    })


@app.get("/")
def health():
    return {"status": "ok", "profile": PROFILE}
