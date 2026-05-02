import os, json, re, subprocess, requests
from dataclasses import dataclass, field
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool
from core.repo_manager import RepoManager
from core.nvd_client import get_cve
from core.logger import get_logger


claude = LLM(
    model="claude-sonnet-4-20250514",
    api_key=os.environ.get("ANTHROPIC_API_KEY"),
    temperature=0.2,
)


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


def make_tools(repo, alert, log) -> list:
    @tool
    def read_repo_file(file_path: str) -> str:
        """Read any file from the cloned repository by its relative path (e.g. 'package.json')"""
        log.info(f"[tool:read] {file_path}")
        content = repo.read_file(file_path)
        return content[:6000] if content else f"File not found: {file_path}"

    @tool
    def list_repo_files(directory: str) -> str:
        """List source files in a directory excluding node_modules and .git. Pass '.' for root directory."""
        result = subprocess.run(
            [
                "find",
                directory,
                "-type",
                "f",
                "-not",
                "-path",
                "*/node_modules/*",
                "-not",
                "-path",
                "*/.git/*",
            ],
            cwd=repo.clone_dir,
            capture_output=True,
            text=True,
        )
        return "\n".join(result.stdout.strip().split("\n")[:80])

    @tool
    def nvd_cve_lookup(cve_id: str) -> str:
        """Look up real CVE details from the National Vulnerability Database. Always call this before drawing any conclusions about a vulnerability."""
        log.info(f"[tool:nvd] {cve_id}")
        result = get_cve(cve_id)
        return json.dumps(result, indent=2) if result else "CVE not found in NVD"

    @tool
    def apply_package_fix(fix_json: str) -> str:
        """Apply a dependency version fix to package.json in the cloned repo.
        Input must be a JSON string with keys:
          package (str): the npm package name
          version (str): safe version constraint e.g. '>=3.1.2'
          add_overrides (bool): true to add npm overrides for transitive deps
        Example: {"package": "pbkdf2", "version": ">=3.1.2", "add_overrides": true}
        """
        log.info(f"[tool:fix] input: {fix_json}")
        try:
            fix = json.loads(fix_json)
        except json.JSONDecodeError as error:
            return json.dumps({"status": "error", "reason": str(error)})

        package_name = fix.get("package")
        version = fix.get("version")
        add_overrides = fix.get("add_overrides", False)

        pkg = repo.get_package_json()
        if pkg is None:
            return json.dumps({"status": "error", "reason": "package.json not found"})

        changes = []
        for section in ["dependencies", "devDependencies"]:
            if package_name in pkg.get(section, {}):
                old = pkg[section][package_name]
                pkg[section][package_name] = version
                changes.append(f"{section}.{package_name}: {old} -> {version}")

        if add_overrides:
            pkg.setdefault("overrides", {})[package_name] = version
            changes.append(f"overrides.{package_name} = {version}")

        repo.write_file("package.json", json.dumps(pkg, indent=2) + "\n")
        log.info(f"[tool:fix] applied changes: {changes}")
        return json.dumps({"status": "applied", "changes": changes})

    @tool
    def run_tests_tool(label: str) -> str:
        """Run the repository test suite and return real pass/fail with output. Pass label='post-fix' to test after applying fix."""
        log.info(f"[tool:test] starting: {label}")
        passed, output = repo.run_tests(label=label)
        log.info(f"[tool:test] {label}: {'PASS' if passed else 'FAIL'}")
        return json.dumps(
            {
                "passed": passed,
                "label": label,
                "output_tail": output[-2000:],
            }
        )

    @tool
    def get_diff_tool(unused: str) -> str:
        """Get the complete git diff of all changes made to the repository so far. Pass any string as argument e.g. 'show'"""
        diff = repo.get_diff()
        return diff if diff else "No changes yet"

    return [
        read_repo_file,
        list_repo_files,
        nvd_cve_lookup,
        apply_package_fix,
        run_tests_tool,
        get_diff_tool,
    ]


def make_agents(tools: list, log) -> list:
    read_file, list_files, nvd_lookup, apply_fix, run_tests, get_diff = tools

    analyst = Agent(
        role="Security Vulnerability Analyst",
        goal="""Produce a complete threat assessment for this specific vulnerability
        in this specific codebase. Real findings from real files - not generic advice.""",
        backstory="""You are Priya, a senior AppSec engineer with 12 years experience
        in financial services at institutions like RBC and Scotiabank. You have reviewed
        thousands of CVEs and your reports have been used in regulatory audits.
        Your process is always: (1) look up the CVE in NVD first, (2) read the actual
        manifest file, (3) list the project structure, (4) map every exposure path.
        You never draw conclusions without evidence from the actual repository.""",
        tools=[read_file, list_files, nvd_lookup],
        llm=claude,
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )

    fixer = Agent(
        role="Secure Remediation Engineer",
        goal="""Apply the single smallest correct fix that eliminates the vulnerability.
        Verify it applied correctly. Never modify source files. Never invent versions.""",
        backstory="""You are Marcus, a staff engineer who has remediated over 2,000
        dependency vulnerabilities across npm, Maven, and pip ecosystems.
        Your rules: (1) minimum version bump only,
        (2) always add npm overrides for transitive paths,
        (3) always verify by reading the file back after writing,
        (4) never touch .ts, .js, or any source file - package.json only.
        You have zero tolerance for invented version numbers.""",
        tools=[read_file, apply_fix, get_diff],
        llm=claude,
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )

    verifier = Agent(
        role="Red Team Security Verifier",
        goal="""Verify the fix is complete and tests still pass. Report honestly.
        Confidence score is calculated from explicit criteria - not optimism.""",
        backstory="""You are Dana, a red team engineer who has spent 8 years breaking
        security fixes at financial institutions. You have caught 47 incomplete patches
        that would have passed standard review. Your confidence score is calculated:
        version eliminated (30pts) + overrides present (20pts) +
        tests passed (30pts) + no source files touched (20pts).
        If tests fail, you say so clearly. You never assume anything passed.""",
        tools=[read_file, run_tests, get_diff],
        llm=claude,
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )

    pr_writer = Agent(
        role="Security PR Documentation Specialist",
        goal="""Write a complete audit-ready PR body using only real data.
        No invented CVE scores. No assumed test results. Real data only.""",
        backstory="""You are James, a compliance engineer who spent 6 years at OSFI
        before moving to the private sector. You know exactly what regulators look for.
        Your PRs reference OSFI B-13, PCI-DSS, and FFIEC explicitly.
        You always call get_diff_tool to get exact changes - never paraphrase diffs.
        You never write anything you cannot back up with evidence from the pipeline.""",
        tools=[get_diff],
        llm=claude,
        verbose=True,
        allow_delegation=False,
        max_iter=3,
    )

    return [analyst, fixer, verifier, pr_writer]


if __name__ == "__main__":
    import logging

    # -- Guardrail tests ----------------------------------
    print("=" * 50)
    print("GUARDRAIL TESTS")
    print("=" * 50)

    test_alert = {
        "package_name": "pbkdf2",
        "patched_version": "3.1.2",
        "cve_id": "CVE-2025-6547",
        "ghsa_id": "GHSA-test",
        "severity": "CRITICAL",
        "manifest_path": "package.json",
    }

    print(gate_1_validate_alert(test_alert))
    print(
        gate_2_validate_analysis(
            "pbkdf2 CVE-2025-6547 analysis complete " * 20, test_alert
        )
    )
    print(
        gate_3_validate_fix(
            "diff --git a/package.json", '{"pbkdf2": ">=3.1.2"}', test_alert
        )
    )
    print(gate_4_validate_verification("confidence 92/100 tests passed"))
    print(
        gate_5_validate_before_push(
            "patchmind/pbkdf2-fix",
            "diff --git a/package.json b/package.json",
            "## Title\n" + "x" * 200,
            "PATCHMIND-0198",
        )
    )

    # -- Tools + Agents instantiation test ----------------
    print()
    print("=" * 50)
    print("TOOLS + AGENTS INSTANTIATION TEST")
    print("=" * 50)

    class MockRepo:
        clone_dir = None
        ecosystem = "npm"

        def read_file(self, p):
            return None

        def get_package_json(self):
            return {}

        def write_file(self, p, c):
            pass

        def get_diff(self):
            return ""

        def run_tests(self, label=""):
            return (True, "mock output")

    mock_log = logging.getLogger("test")
    mock_repo = MockRepo()
    mock_alert = {
        "package_name": "pbkdf2",
        "patched_version": "3.1.2",
        "cve_id": "CVE-2025-6547",
        "number": 198,
    }

    tools = make_tools(mock_repo, mock_alert, mock_log)
    agents = make_agents(tools, mock_log)

    print(f"Tools created: {len(tools)}")
    print(f"Agents created: {len(agents)}")
    for a in agents:
        print(f"  - {a.role}")
    print()
    print("5b COMPLETE")
