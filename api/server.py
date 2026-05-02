import os, json, asyncio
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime
import traceback


app = FastAPI(title="PatchMind API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store
# Key: job_id, Value: dict with status, result, logs list
jobs: dict = {}


class RemediateRequest(BaseModel):
    owner: str = "zmax1360"
    repo: str = "angular"


class JobStatus(BaseModel):
    job_id: str
    status: str
    audit_id: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    gate_results: Optional[dict] = None
    requires_human_approval: Optional[bool] = None
    pr_body: Optional[str] = None
    diff: Optional[str] = None
    branch_name: Optional[str] = None
    error: Optional[str] = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": "1.0.0"}


@app.get("/alerts/{owner}/{repo}")
def get_alerts(owner: str, repo: str) -> list:
    try:
        from core.github_client import get_dependabot_alerts

        return get_dependabot_alerts(owner, repo)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/remediate/{owner}/{repo}/{alert_number}")
def remediate(
    owner: str,
    repo: str,
    alert_number: int,
    background_tasks: BackgroundTasks,
    request: Optional[RemediateRequest] = None,
) -> dict:
    try:
        from core.github_client import get_dependabot_alerts

        alerts = get_dependabot_alerts(owner, repo)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    alert = next((item for item in alerts if item.get("number") == alert_number), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "queued",
        "alert": alert,
        "owner": owner,
        "repo": repo,
        "logs": [],
        "created_at": datetime.now().isoformat(),
    }

    background_tasks.add_task(run_pipeline_job, job_id)
    return {
        "job_id": job_id,
        "status": "queued",
        "audit_id": f"PATCHMIND-{alert_number:04d}",
    }


@app.get("/job/{job_id}", response_model=JobStatus)
def get_job(job_id: str) -> JobStatus:
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]
    return JobStatus(
        job_id=job_id,
        status=job["status"],
        audit_id=job.get("audit_id"),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        gate_results=job.get("gate_results"),
        requires_human_approval=job.get("requires_human_approval"),
        pr_body=job.get("pr_body"),
        diff=job.get("diff"),
        branch_name=job.get("branch_name"),
        error=job.get("error"),
    )


@app.get("/job/{job_id}/stream")
def stream_job(job_id: str) -> StreamingResponse:
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        sent = 0
        while True:
            logs = jobs[job_id]["logs"]
            while sent < len(logs):
                yield f"data: {json.dumps(logs[sent])}\n\n"
                sent += 1
            if jobs[job_id]["status"] in ["completed", "error", "blocked"]:
                yield (
                    "data: "
                    f"{json.dumps({'type': 'done', 'status': jobs[job_id]['status']})}"
                    "\n\n"
                )
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/job/{job_id}/approve")
def approve_job(job_id: str) -> dict:
    try:
        if job_id not in jobs:
            raise HTTPException(status_code=404, detail="Job not found")

        job = jobs[job_id]
        if job["status"] not in ["completed", "approved"]:
            raise HTTPException(status_code=400, detail="Job not ready for approval")

        gate_results = job.get("gate_results") or {}
        if gate_results.get("g5") != "human_required":
            raise HTTPException(status_code=400, detail="No approval needed")

        from core.github_client import create_pull_request, get_default_branch

        owner = job["owner"]
        repo = job["repo"]
        alert = job["alert"]
        audit_id = job.get("audit_id") or f"PATCHMIND-{alert['number']:04d}"
        package_name = alert["package_name"]
        safe_version = alert["patched_version"]
        branch_name = job["branch_name"]
        pr_body = job["pr_body"]

        repo_mgr = job.get("repo_mgr")
        if repo_mgr is None or repo_mgr.clone_dir is None:
            raise HTTPException(
                status_code=500,
                detail="Repo no longer available - re-run pipeline",
            )

        default_branch = get_default_branch(owner, repo)
        commit_message = (
            f"fix(security): upgrade {package_name} to {safe_version}\n\n"
            f"{audit_id}\n"
            f"Addresses {alert.get('cve_id') or alert.get('ghsa_id', '')}"
        )

        branch_ok = repo_mgr.create_branch_and_commit(branch_name, commit_message)
        if not branch_ok:
            raise HTTPException(status_code=500, detail="Failed to create branch or commit")

        push_ok, push_err = repo_mgr.push_branch(branch_name)
        if not push_ok:
            raise HTTPException(status_code=500, detail=f"Failed to push branch: {push_err}")

        pr = create_pull_request(
            owner,
            repo,
            f"fix(security): upgrade {package_name} to {safe_version}",
            pr_body,
            branch_name,
            default_branch,
        )

        repo_mgr.cleanup()
        job["repo_mgr"] = None

        job["status"] = "approved"
        return {
            "approved": True,
            "branch_name": branch_name,
            "base_branch": default_branch,
            "pr_body": pr_body,
            "pull_request": pr,
            "message": "Branch pushed and pull request created.",
        }
    except HTTPException:
        raise
    except Exception as e:
        error_detail = traceback.format_exc()
        print(f"APPROVE ERROR: {error_detail}")
        raise HTTPException(500, f"Approval failed: {str(e)}")


async def run_pipeline_job(job_id: str):
    job = jobs[job_id]
    job["status"] = "running"

    def add_log(type: str, message: str):
        job["logs"].append(
            {
                "type": type,
                "message": message,
                "ts": datetime.now().isoformat(),
            }
        )

    try:
        add_log("info", f"Pipeline starting - {job['owner']}/{job['repo']}")
        add_log(
            "info",
            f"Alert: #{job['alert']['number']} "
            f"{job['alert']['package_name']} {job['alert']['severity']}",
        )

        # Import here to avoid circular imports
        from agents.crew import run_pipeline

        add_log("info", "Cloning repository and installing dependencies...")

        # Run pipeline in thread pool because it is synchronous.
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: run_pipeline(job["owner"], job["repo"], job["alert"]),
        )

        job["status"] = result["status"]
        job["completed_at"] = datetime.now().isoformat()
        job["audit_id"] = result.get("audit_id")
        job["gate_results"] = result.get("gate_results")
        job["pr_body"] = result.get("pr_body")
        job["diff"] = result.get("diff", "")[:50000]
        job["branch_name"] = result.get("branch_name")
        job["repo_mgr"] = result.get("repo_mgr")
        job["requires_human_approval"] = result.get("requires_human_approval", True)
        job["baseline_passed"] = result.get("baseline_passed")

        if result["status"] == "completed":
            add_log("success", f"Pipeline complete - audit ID: {result.get('audit_id')}")
            add_log("success", f"Gates: {result.get('gate_results')}")
            add_log("success", "Awaiting human approval before push")
        else:
            add_log(
                "error",
                f"Pipeline {result['status']}: "
                f"{result.get('error', result.get('reason', ''))}",
            )

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        job["completed_at"] = datetime.now().isoformat()
        add_log("error", f"Pipeline error: {str(e)}")


@app.get("/job/{job_id}/reject")
async def reject_job(job_id: str):
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")
    job = jobs[job_id]
    repo_mgr = job.get("repo_mgr")
    if repo_mgr:
        repo_mgr.cleanup()
        job["repo_mgr"] = None
    job["status"] = "rejected"
    return {"rejected": True, "job_id": job_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
