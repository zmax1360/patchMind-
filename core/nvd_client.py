import requests


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_english_description(descriptions: list[dict]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def _get_cvss_data(metrics: dict) -> dict:
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_values = metrics.get(metric_key) or []
        if metric_values:
            return metric_values[0].get("cvssData") or {}
    return {}


def _get_weaknesses(weaknesses: list[dict]) -> list:
    values = []
    for weakness in weaknesses:
        for description in weakness.get("description", []):
            if description.get("lang") == "en":
                values.append(description.get("value", ""))
                break
    return values


def get_cve(cve_id: str) -> dict:
    if not cve_id:
        return {}

    try:
        response = requests.get(
            NVD_CVE_API_URL,
            params={"cveId": cve_id},
            timeout=10,
        )
    except (requests.Timeout, requests.ConnectionError):
        return {}

    if response.status_code != 200:
        return {}

    vulnerabilities = response.json()["vulnerabilities"]
    if not vulnerabilities:
        return {}

    cve = vulnerabilities[0]["cve"]
    cvss_data = _get_cvss_data(cve.get("metrics", {}))

    return {
        "id": cve.get("id"),
        "description": _get_english_description(cve.get("descriptions", [])),
        "cvss_score": cvss_data.get("baseScore"),
        "cvss_severity": cvss_data.get("baseSeverity"),
        "cvss_vector": cvss_data.get("vectorString"),
        "weaknesses": _get_weaknesses(cve.get("weaknesses", [])),
    }


if __name__ == "__main__":
    for cve in ("CVE-2021-23337", "CVE-2025-6547", "CVE-2025-9288"):
        print(get_cve(cve))
