import os, json, re, subprocess, requests
from dataclasses import dataclass, field
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool
from core.repo_manager import RepoManager
from core.nvd_client import get_cve
from core.logger import get_logger


@dataclass
class GuardrailResult:
    status: str
    gate: str
    reason: str
    evidence: dict = field(default_factory=dict)
    audit_id: str = ""


def _result(
    status: str,
    gate: str,
    reason: str,
    evidence: dict | None = None,
    audit_id: str = "",
) -> GuardrailResult:
    return GuardrailResult(
        status=status,
        gate=gate,
        reason=reason,
        evidence=evidence or {},
        audit_id=audit_id,
    )


def _diff_touched_files(diff: str) -> list[str]:
    files = []
    for line in diff.splitlines():
        if not line.startswith("diff --git "):
            continue

        parts = line.split()
        if len(parts) >= 4:
            files.append(parts[3].removeprefix("b/"))
    return files


def _diff_only_touches_package_files(diff: str) -> bool:
    allowed_files = {"package.json", "package-lock.json"}
    touched_files = _diff_touched_files(diff)
    return all(path in allowed_files for path in touched_files)


def gate_1_validate_alert(alert: dict) -> GuardrailResult:
    gate = "gate_1_validate_alert"

    if not alert.get("package_name"):
        return _result("block", gate, "Missing package_name", {"alert": alert})

    if not alert.get("patched_version"):
        return _result("block", gate, "No safe version known", {"alert": alert})

    cve_id = alert.get("cve_id") or ""
    ghsa_id = alert.get("ghsa_id") or ""
    if not re.fullmatch(r"CVE-\d{4}-\d{5,}", cve_id) and not ghsa_id:
        return _result(
            "block",
            gate,
            "Missing valid CVE or GHSA identifier",
            {"cve_id": cve_id, "ghsa_id": ghsa_id},
        )

    return _result("pass", gate, "Alert is valid", {"alert": alert})


def gate_2_validate_analysis(analyst_output: str, alert: dict) -> GuardrailResult:
    gate = "gate_2_validate_analysis"
    output = analyst_output or ""
    package_name = alert.get("package_name") or ""

    if len(output) < 200:
        return _result(
            "block",
            gate,
            "Analysis output is empty or too short",
            {"length": len(output)},
        )

    if package_name.lower() not in output.lower():
        return _result(
            "retry",
            gate,
            "Analysis does not mention affected package",
            {"package_name": package_name},
        )

    if not re.search(r"(CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9-]+)", output):
        return _result(
            "warn",
            gate,
            "No CVE/GHSA ID found in analysis",
            {"package_name": package_name},
        )

    return _result("pass", gate, "Analysis is valid", {"package_name": package_name})


def gate_3_validate_fix(
    diff: str, package_json_content: str, alert: dict
) -> GuardrailResult:
    gate = "gate_3_validate_fix"
    package_name = alert.get("package_name") or ""
    patched_version = alert.get("patched_version") or ""

    if not diff:
        return _result("block", gate, "Diff is empty")

    if patched_version not in (package_json_content or ""):
        return _result(
            "block",
            gate,
            "Patched version not found in package.json",
            {"patched_version": patched_version},
        )

    try:
        response = requests.get(
            f"https://registry.npmjs.org/{package_name}/{patched_version}",
            timeout=10,
        )
    except requests.RequestException as error:
        return _result(
            "warn",
            gate,
            "npm registry check failed with network error",
            {"error": str(error)},
        )

    if response.status_code == 404:
        return _result(
            "block",
            gate,
            "Version does not exist on npm - agent hallucinated",
            {"package_name": package_name, "patched_version": patched_version},
        )

    if not _diff_only_touches_package_files(diff):
        return _result(
            "warn",
            gate,
            "Diff touches files other than package.json or package-lock.json",
            {"touched_files": _diff_touched_files(diff)},
        )

    return _result(
        "pass",
        gate,
        "Fix is valid",
        {"package_name": package_name, "patched_version": patched_version},
    )


def gate_4_validate_verification(verifier_output: str) -> GuardrailResult:
    gate = "gate_4_validate_verification"
    output = verifier_output or ""
    score = None

    score_match = re.search(r"(\d+)\s*/\s*100", output)
    if score_match is None:
        score_match = re.search(r"confidence.*?(\d+)", output, re.IGNORECASE)

    if score_match is not None:
        score = int(score_match.group(1))

    lower_output = output.lower()
    if score is not None and score < 70:
        return _result(
            "human_required",
            gate,
            "Verification confidence below threshold",
            {"score": score},
        )

    if "failed" in lower_output and "passed" not in lower_output:
        return _result(
            "human_required",
            gate,
            "Verification output reports failure",
            {"score": score},
        )

    if score is None:
        return _result("warn", gate, "No confidence score found")

    return _result("pass", gate, "Verification is valid", {"score": score})


def gate_5_validate_before_push(
    branch_name: str, diff: str, pr_body: str, audit_id: str
) -> GuardrailResult:
    gate = "gate_5_validate_before_push"

    if not branch_name.startswith("patchmind/"):
        return _result(
            "block",
            gate,
            "Branch name must start with patchmind/",
            {"branch_name": branch_name},
            audit_id,
        )

    if len(pr_body or "") < 100:
        return _result(
            "block",
            gate,
            "PR body is too short",
            {"length": len(pr_body or "")},
            audit_id,
        )

    touched_files = _diff_touched_files(diff)
    if not _diff_only_touches_package_files(diff):
        return _result(
            "block",
            gate,
            "Diff touches files other than package.json or package-lock.json",
            {"touched_files": touched_files},
            audit_id,
        )

    return _result(
        "human_required",
        gate,
        "Push requires human approval",
        {"branch_name": branch_name, "touched_files": touched_files},
        audit_id,
    )


def log_guardrail(result: GuardrailResult, log) -> None:
    message = (
        f"{result.gate}: {result.status} - {result.reason} "
        f"evidence={json.dumps(result.evidence)} audit_id={result.audit_id}"
    )

    if result.status in ("pass", "warn"):
        log.info(message)
    elif result.status == "block":
        log.error(message)
    else:
        log.warning(message)


if __name__ == "__main__":
    alert = {
        "package_name": "pbkdf2",
        "patched_version": "3.1.2",
        "cve_id": "CVE-2025-6547",
        "ghsa_id": "GHSA-test",
        "severity": "CRITICAL",
        "manifest_path": "package.json",
    }
    sample_diff = """diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,3 @@
-    "pbkdf2": "3.1.1"
+    "pbkdf2": "3.1.2"
"""
    sample_package_json = '{"dependencies": {"pbkdf2": "3.1.2"}}'
    sample_analysis = (
        "CVE-2025-6547 / GHSA-test affects the pbkdf2 package. "
        "The vulnerable dependency should be upgraded to the patched version. "
        "This analysis confirms the package impact, remediation target, "
        "expected manifest change, and verification plan for dependency-only "
        "remediation in package.json."
    )
    sample_verification = "Verification passed with confidence 92"
    sample_pr_body = (
        "This PatchMind remediation updates pbkdf2 to the safe patched version. "
        "The change is limited to dependency manifests and should be reviewed "
        "before pushing."
    )

    print(gate_1_validate_alert(alert))
    print(gate_2_validate_analysis(sample_analysis, alert))
    print(gate_3_validate_fix(sample_diff, sample_package_json, alert))
    print(gate_4_validate_verification(sample_verification))
    print(
        gate_5_validate_before_push(
            "patchmind/pbkdf2-cve-2025-6547",
            sample_diff,
            sample_pr_body,
            "PATCHMIND-0198",
        )
    )
