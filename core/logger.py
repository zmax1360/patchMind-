import logging
import os
import json
from datetime import datetime
from pathlib import Path


LOG_DIR = Path("logs")


def get_logger(name: str, audit_id: str = None) -> logging.Logger:
    """
    Returns a logger that writes to:
      1. Terminal (stdout) with colored output
      2. logs/{audit_id}_{timestamp}.log as plain text
      3. logs/{audit_id}_{timestamp}.jsonl as structured JSON lines
         (one JSON object per log entry - easy to parse later)

    If audit_id is None, use "patchmind"
    """
    LOG_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    audit_id = audit_id or "patchmind"
    base_name = f"{audit_id}_{timestamp}"

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # 1. Terminal handler - colored by level
    class ColorFormatter(logging.Formatter):
        COLORS = {
            "DEBUG": "\033[36m",  # cyan
            "INFO": "\033[32m",  # green
            "WARNING": "\033[33m",  # yellow
            "ERROR": "\033[31m",  # red
            "CRITICAL": "\033[35m",  # magenta
        }
        RESET = "\033[0m"

        def format(self, record):
            color = self.COLORS.get(record.levelname, "")
            prefix = f"{color}[{record.levelname}]{self.RESET}"
            ts = datetime.now().strftime("%H:%M:%S")
            return f"{prefix} {ts} {record.getMessage()}"

    console = logging.StreamHandler(os.fdopen(os.dup(1), "w"))
    console.setFormatter(ColorFormatter())
    logger.addHandler(console)

    # 2. Plain text file handler
    txt_handler = logging.FileHandler(LOG_DIR / f"{base_name}.log")
    txt_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(txt_handler)

    # 3. JSONL structured handler
    class JsonlHandler(logging.FileHandler):
        def emit(self, record):
            entry = {
                "ts": datetime.now().isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "audit_id": audit_id,
            }
            self.stream.write(json.dumps(entry) + "\n")
            self.flush()

    jsonl_handler = JsonlHandler(LOG_DIR / f"{base_name}.jsonl")
    logger.addHandler(jsonl_handler)

    logger.info(f"PatchMind logger initialized - audit_id={audit_id}")
    logger.info(f"Log files: logs/{base_name}.log and logs/{base_name}.jsonl")

    return logger


# Convenience - module level logger
log = get_logger("patchmind")


if __name__ == "__main__":
    logger = get_logger("patchmind", audit_id="PATCHMIND-0198")
    logger.info("Pipeline started")
    logger.info("Cloning repository zmax1360/angular")
    logger.warning("Baseline tests failed - continuing with build check")
    logger.info("Agent 1 (Analyst) starting")
    logger.debug("CVE lookup: CVE-2025-6547")
    logger.info("Agent 2 (Fixer) applying patch")
    logger.info("Agent 3 (Verifier) running post-fix tests")
    logger.critical("CRITICAL vulnerability patched: pbkdf2")
    logger.info("Agent 4 (PR Writer) generating PR body")
    logger.info("Pipeline complete")
    print("\nCheck the logs/ directory for output files")
