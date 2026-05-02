import base64
import os

import requests


GITHUB_API_BASE_URL = "https://api.github.com"


def _get_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("github_token")
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN is required. Set GITHUB_TOKEN or github_token in the environment."
        )
    return token


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_github_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _first_identifier(identifiers: list[dict], identifier_type: str) -> str | None:
    for identifier in identifiers:
        if identifier.get("type") == identifier_type:
            return identifier.get("value")
    return None


def _normalize_alert(alert: dict) -> dict:
    security_advisory = alert.get("security_advisory") or {}
    security_vulnerability = alert.get("security_vulnerability") or {}
    dependency = alert.get("dependency") or {}
    package = security_vulnerability.get("package") or {}
    first_patched_version = security_vulnerability.get("first_patched_version") or {}
    identifiers = security_advisory.get("identifiers") or []
    cvss = security_advisory.get("cvss") or {}

    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "severity": (security_advisory.get("severity") or "").upper(),
        "summary": security_advisory.get("summary"),
        "description": security_advisory.get("description"),
        "package_name": package.get("name"),
        "ecosystem": package.get("ecosystem"),
        "vulnerable_range": security_vulnerability.get("vulnerable_version_range"),
        "patched_version": first_patched_version.get("identifier"),
        "cve_id": _first_identifier(identifiers, "CVE"),
        "ghsa_id": _first_identifier(identifiers, "GHSA"),
        "cvss_score": cvss.get("score"),
        "cwes": [
            cwe["cwe_id"]
            for cwe in security_advisory.get("cwes", [])
            if cwe.get("cwe_id")
        ],
        "references": [
            reference["url"]
            for reference in security_advisory.get("references", [])
            if reference.get("url")
        ],
        "manifest_path": dependency.get("manifest_path"),
        "created_at": alert.get("created_at"),
        "html_url": alert.get("html_url"),
    }


def get_dependabot_alerts(owner: str, repo: str) -> list[dict]:
    response = requests.get(
        f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/alerts",
        headers=_headers(),
        params={"state": "open", "per_page": 50},
    )
    response.raise_for_status()
    return [_normalize_alert(alert) for alert in response.json()]


def get_file_content(
    owner: str, repo: str, path: str, ref: str = "main"
) -> str | None:
    response = requests.get(
        f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/contents/{path}",
        headers=_headers(),
        params={"ref": ref},
    )
    if response.status_code == 404:
        return None

    response.raise_for_status()
    content = response.json().get("content", "")
    return base64.b64decode(content).decode()


def get_default_branch(owner: str, repo: str) -> str:
    response = requests.get(
        f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}",
        headers=_headers(),
    )
    response.raise_for_status()
    return response.json().get("default_branch") or "main"


def create_pull_request(
    owner: str, repo: str, title: str, body: str, head: str, base: str
) -> dict:
    response = requests.post(
        f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/pulls",
        headers=_headers(),
        json={
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        },
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    alerts = get_dependabot_alerts("zmax1360", "angular")
    print(f"Found {len(alerts)} alerts")
    for alert in alerts:
        print(
            alert["number"],
            alert["severity"],
            alert["package_name"],
            alert["cve_id"],
        )
