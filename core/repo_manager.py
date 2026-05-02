import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def detect_ecosystem(manifest_path: str) -> str:
    if manifest_path.endswith(("package.json", "package-lock.json")):
        return "npm"
    if manifest_path.endswith("pom.xml"):
        return "maven"
    if manifest_path.endswith(("build.gradle", "build.gradle.kts")):
        return "gradle"
    if manifest_path.endswith(("requirements.txt", "Pipfile", "pyproject.toml")):
        return "pip"
    if manifest_path.endswith("Gemfile"):
        return "ruby"
    if manifest_path.endswith("go.mod"):
        return "go"
    return "unknown"


class RepoManager:
    def __init__(self, owner: str, repo: str, manifest_path: str = "package.json"):
        self.owner = owner
        self.repo = repo
        self.ecosystem = detect_ecosystem(manifest_path)
        self.clone_dir = None
        self.baseline_passed = False

    def _get_token(self) -> str:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("github_token")
        if not token:
            raise RuntimeError(
                "GITHUB_TOKEN is required. Set GITHUB_TOKEN or github_token in the environment."
            )
        return token

    def _require_clone_dir(self) -> Path:
        if self.clone_dir is None:
            raise RuntimeError("Repository has not been cloned yet.")
        return self.clone_dir

    def clone(self) -> Path:
        token = self._get_token()
        clone_url = f"https://{token}@github.com/{self.owner}/{self.repo}.git"
        tmpdir = tempfile.mkdtemp(prefix=f"patchmind_{self.repo}_")

        result = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        self.clone_dir = Path(tmpdir)
        return self.clone_dir

    def install_deps(self) -> tuple[bool, str]:
        commands = {
            "npm": ["npm", "install", "--legacy-peer-deps"],
            "maven": ["mvn", "dependency:resolve", "-q"],
            "gradle": ["./gradlew", "dependencies"],
            "pip": ["pip", "install", "-r", "requirements.txt"],
            "ruby": ["bundle", "install"],
            "go": ["go", "mod", "download"],
        }
        command = commands.get(self.ecosystem)
        if command is None:
            return (False, "Unknown ecosystem")

        result = subprocess.run(
            command,
            cwd=self._require_clone_dir(),
            capture_output=True,
            text=True,
            timeout=300,
        )
        return (result.returncode == 0, result.stdout + result.stderr)

    def run_tests(self, label: str = "check") -> tuple[bool, str]:
        command = self._get_test_command()
        if isinstance(command, str):
            return (False, command)

        env = {**os.environ, "CI": "true"}
        result = subprocess.run(
            command,
            cwd=self._require_clone_dir(),
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        output = result.stdout[-3000:] + result.stderr[-2000:]
        passed = result.returncode == 0

        if label == "baseline":
            self.baseline_passed = passed

        return (passed, output)

    def _get_test_command(self) -> list[str] | str:
        if self.ecosystem == "npm":
            package_json = self.get_package_json()
            if package_json is None:
                return "No package.json"

            scripts = package_json.get("scripts", {})
            test_script = scripts.get("test", "")

            if "test:ci" in scripts:
                return ["npm", "run", "test:ci"]
            if "karma" in test_script or "ng test" in test_script:
                return [
                    "npx",
                    "ng",
                    "test",
                    "--watch=false",
                    "--browsers=ChromeHeadless",
                    "--no-progress",
                ]
            if "test" in scripts:
                return ["npm", "test", "--", "--watchAll=false"]
            if "build" in scripts:
                return ["npm", "run", "build"]
            return "No runnable script found"

        commands = {
            "maven": ["mvn", "test", "-q"],
            "gradle": ["./gradlew", "test"],
            "pip": ["python", "-m", "pytest"],
            "ruby": ["bundle", "exec", "rspec"],
            "go": ["go", "test", "./..."],
        }
        return commands.get(self.ecosystem, "Unknown ecosystem")

    def read_file(self, relative_path: str) -> str | None:
        path = self._require_clone_dir() / relative_path
        if not path.exists():
            return None
        return path.read_text()

    def write_file(self, relative_path: str, content: str):
        path = self._require_clone_dir() / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def get_package_json(self) -> dict | None:
        content = self.read_file("package.json")
        if content is None:
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def get_diff(self) -> str:
        result = subprocess.run(
            ["git", "diff"],
            cwd=self._require_clone_dir(),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return ""
        return result.stdout or ""

    def create_branch_and_commit(self, branch_name: str, message: str) -> bool:
        commands = [
            ["git", "config", "user.email", "patchmind@ai.local"],
            ["git", "config", "user.name", "PatchMind AI"],
            ["git", "checkout", "-b", branch_name],
            ["git", "add", "-A"],
            ["git", "commit", "-m", message],
        ]
        for command in commands:
            result = subprocess.run(
                command,
                cwd=self._require_clone_dir(),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
        return True

    def push_branch(self, branch_name: str) -> tuple[bool, str]:
        token = self._get_token()
        remote_url = f"https://{token}@github.com/{self.owner}/{self.repo}.git"
        result = subprocess.run(
            ["git", "push", remote_url, f"HEAD:{branch_name}"],
            cwd=self._require_clone_dir(),
            capture_output=True,
            text=True,
        )
        return (result.returncode == 0, result.stderr)

    def cleanup(self):
        if self.clone_dir is not None and self.clone_dir.exists():
            shutil.rmtree(self.clone_dir)


if __name__ == "__main__":
    manager = RepoManager("zmax1360", "angular", "package.json")
    print(f"Detected ecosystem: {manager.ecosystem}")
    try:
        clone_dir = manager.clone()
        print(f"Cloned to: {clone_dir}")

        deps_ok, _ = manager.install_deps()
        print(f"Dependency install: {'success' if deps_ok else 'fail'}")

        tests_ok, output = manager.run_tests(label="baseline")
        print(f"Baseline tests: {'passed' if tests_ok else 'fail'}")
        print(output[-500:])

        diff = manager.get_diff()
        if not diff:
            print("No changes yet (expected)")
        else:
            print(diff)
    finally:
        manager.cleanup()
        print("Cleaned up")
