"""
DungeonMaster AI Engine
FastAPI service providing TTP suggestions, evasion advice, and report generation.

Routes:
  POST /suggest    — ranked TTP suggestions given a session context
  POST /evasion    — alternative techniques when a technique fails
  POST /report     — generate a full engagement report draft
"""

import os
import json
from contextlib import asynccontextmanager
from typing import Optional

import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .ttp_ranker import TTPRanker, SessionContext, TTPSuggestion

# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

ranker: Optional[TTPRanker] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ranker
    model_path = os.getenv("MODEL_PATH", "")
    ranker = TTPRanker(model_path=model_path if model_path else None)
    await ranker.load()
    yield
    # cleanup

app = FastAPI(
    title="DungeonMaster AI Engine",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tightened in production via env
    allow_methods=["POST"],
    allow_headers=["Authorization"],
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SuggestRequest(BaseModel):
    context:   SessionContext
    max_count: int = Field(default=5, ge=1, le=10)

class SuggestResponse(BaseModel):
    suggestions: list[TTPSuggestion]
    model_used:  str

class EvasionRequest(BaseModel):
    failed_technique:    str
    evasion_description: str
    context:             SessionContext

class EvasionResponse(BaseModel):
    alternatives: list[TTPSuggestion]
    explanation:  str

class ReportRequest(BaseModel):
    campaign_id:     str
    report_template: str = "technical"
    # Campaign data passed from the team server (summary — no raw target data)
    campaign_name:   str
    client_name:     str
    objective:       str
    duration_days:   int
    ttps_executed:   list[dict]
    key_findings:    list[str]
    evidence_count:  int

class ReportResponse(BaseModel):
    report_markdown: str

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/suggest", response_model=SuggestResponse)
async def suggest_ttps(req: SuggestRequest) -> SuggestResponse:
    if ranker is None:
        raise HTTPException(503, "AI engine not ready")

    suggestions = await ranker.suggest(req.context, req.max_count)
    return SuggestResponse(
        suggestions=suggestions,
        model_used=ranker.model_name,
    )


@app.post("/evasion", response_model=EvasionResponse)
async def suggest_evasion(req: EvasionRequest) -> EvasionResponse:
    if ranker is None:
        raise HTTPException(503, "AI engine not ready")

    alternatives, explanation = await ranker.suggest_evasion(
        failed_technique=req.failed_technique,
        evasion_description=req.evasion_description,
        context=req.context,
    )
    return EvasionResponse(alternatives=alternatives, explanation=explanation)


@app.post("/report", response_model=ReportResponse)
async def generate_report(req: ReportRequest) -> ReportResponse:
    """
    Report generation uses Claude API (post-engagement data only — no live target info).
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(503, "Claude API key not configured")

    client = anthropic.Anthropic(api_key=api_key)

    prompt = _build_report_prompt(req)

    message = client.messages.create(
        model="claude-opus-4-8",
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )

    return ReportResponse(report_markdown=message.content[0].text)


# ---------------------------------------------------------------------------
# Report prompt builder
# ---------------------------------------------------------------------------

def _build_report_prompt(req: ReportRequest) -> str:
    ttps_text = "\n".join(
        f"- {t.get('technique_id', '?')} {t.get('technique_name', '')} "
        f"({t.get('tactic', '')})"
        for t in req.ttps_executed
    )
    findings_text = "\n".join(f"- {f}" for f in req.key_findings)

    template_instruction = {
        "executive": "Write an executive summary suitable for a C-suite audience. "
                     "Focus on business risk and strategic recommendations. "
                     "Keep technical jargon minimal.",
        "technical": "Write a detailed technical report suitable for a security engineering audience. "
                     "Include technique descriptions, evidence references, and specific remediation steps.",
        "full":      "Write a complete engagement report including both an executive summary and "
                     "full technical findings sections.",
    }.get(req.report_template, "Write a technical security report.")

    return f"""You are writing a red team engagement report for a cybersecurity firm.

{template_instruction}

Engagement details:
- Campaign: {req.campaign_name}
- Client: {req.client_name}
- Objective: {req.objective}
- Duration: {req.duration_days} days
- Evidence items collected: {req.evidence_count}

Techniques executed (MITRE ATT&CK):
{ttps_text}

Key findings:
{findings_text}

Write the report in Markdown. Use clear sections with headers. Be specific about impact.
Do not invent details not provided above. Where evidence would normally be referenced,
use placeholder markers like [EVIDENCE-001] that the operator will fill in.
"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8090, reload=False)
