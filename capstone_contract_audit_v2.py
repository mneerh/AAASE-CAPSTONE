"""
Automated Contract Audit and Vendor Compliance Pipeline -- v2
-----------------------------------------------------------------
Matches the team architecture:

  User -> FastAPI -> Input Security Guard -(blocked/approved)->
  MinIO Object Storage -> LangGraph Orchestrator
      -> PDF Parser -> Policy Retriever (ChromaDB) -> Audit Logger
      -> Compliance Analysis Agent -> Reviewer/Evaluator
         -(retry)-> back to Compliance Analysis Agent
         -(good enough)-> Generate Report -> PostgreSQL + Report File
  -> Prometheus metrics

Run locally:
    MOCK=1 uvicorn capstone_contract_audit_v2:app --reload --port 8080

Run as a script:
    MOCK=1 python capstone_contract_audit_v2.py audit sample_contract.pdf
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing_extensions import TypedDict

from pypdf import PdfReader
from langgraph.graph import StateGraph, START, END

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

MOCK = os.getenv("MOCK", "0") == "1"
QUALITY_THRESHOLD = int(os.getenv("QUALITY_THRESHOLD", "7"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
PRICE_IN = 0.0000005
PRICE_OUT = 0.0000015


# ============================================================
# OBSERVABILITY -- structured logs + Prometheus metrics
# ============================================================
logger = logging.getLogger("contract_audit")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


def log_event(run_id: str, event: str, **fields):
    record = {"ts": datetime.now(timezone.utc).isoformat(), "run_id": run_id, "event": event, **fields}
    logger.info(json.dumps(record))


from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

AUDITS_TOTAL = Counter("audits_total", "Total audit requests received")
AUDITS_BLOCKED = Counter("audits_blocked_total", "Audits blocked by the input security guard")
AUDITS_RETRIED = Counter("audits_retried_total", "Times the reviewer sent an audit back for retry")
AUDIT_LATENCY = Histogram("audit_latency_seconds", "End-to-end audit latency")
AUDIT_COST = Counter("audit_cost_usd_total", "Total simulated LLM cost across all audits")


# ============================================================
# SECURITY -- Input Security Guard (blocked / approved)
# ============================================================
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"system prompt",
]

import re


def input_security_guard(name_or_path: str) -> tuple[bool, str]:
    if not name_or_path or not os.path.exists(name_or_path):
        return False, "File does not exist"
    if not name_or_path.lower().endswith(".pdf"):
        return False, "Only PDF files are accepted"
    if os.path.getsize(name_or_path) > 20 * 1024 * 1024:
        return False, "File exceeds 20MB limit"
    return True, "approved"


# ============================================================
# OBJECT STORAGE -- MinIO (S3-compatible)
# ============================================================
# NOTE: this talks to a real MinIO server over the network (S3 API).
# It needs a running MinIO instance -- see docker-compose.yml, which
# starts one locally alongside this app. If MinIO isn't reachable
# (e.g. running this file standalone without docker-compose), storage
# calls are skipped with a logged warning rather than crashing --
# this keeps local/CLI testing possible without requiring MinIO.
from minio import Minio
from minio.error import S3Error

MINIO_ENABLED = os.getenv("MINIO_ENABLED", "0") == "1"
_minio_client = None


def get_minio_client():
    global _minio_client
    if _minio_client is not None:
        return _minio_client
    _minio_client = Minio(
        os.getenv("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
        secure=False,
    )
    bucket = os.getenv("MINIO_BUCKET", "contracts")
    if not _minio_client.bucket_exists(bucket):
        _minio_client.make_bucket(bucket)
    return _minio_client


def store_contract_in_minio(run_id: str, file_path: str) -> str | None:
    if not MINIO_ENABLED:
        log_event(run_id, "minio_skipped", reason="MINIO_ENABLED=0, using local disk only")
        return None
    bucket = os.getenv("MINIO_BUCKET", "contracts")
    object_name = f"{run_id}/{os.path.basename(file_path)}"
    try:
        client = get_minio_client()
        client.fput_object(bucket, object_name, file_path)
        log_event(run_id, "minio_stored", bucket=bucket, object_name=object_name)
        return f"{bucket}/{object_name}"
    except S3Error as e:
        log_event(run_id, "minio_error", error=str(e))
        return None


# ============================================================
# DATABASE -- PostgreSQL (immutable audit trail) + local report files
# ============================================================
import psycopg2
from psycopg2.extras import RealDictCursor

PG_DSN = dict(
    host=os.getenv("PGHOST", "localhost"),
    dbname=os.getenv("PGDATABASE", "compliance_audit"),
    user=os.getenv("PGUSER", "postgres"),
    password=os.getenv("PGPASSWORD", "postgres"),
    port=os.getenv("PGPORT", "5432"),
)


def _init_audit_db():
    conn = psycopg2.connect(**PG_DSN)
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id UUID PRIMARY KEY,
                run_id TEXT,
                ts TIMESTAMPTZ,
                contract_file TEXT,
                policy_id TEXT,
                status TEXT,
                risk_level TEXT,
                contract_evidence TEXT,
                reason TEXT,
                recommendation TEXT,
                human_review_required BOOLEAN,
                latency_ms REAL,
                cost_usd REAL
            )
        """)
    conn.commit()
    return conn


def write_audit_entry(conn, run_id, contract_file, policy_result, latency_ms, cost_usd):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO audit_trail VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (str(uuid.uuid4()), run_id, datetime.now(timezone.utc), contract_file,
             policy_result["policy_id"], policy_result["status"], policy_result["risk_level"],
             policy_result["contract_evidence"], policy_result["reason"], policy_result["recommendation"],
             policy_result["human_review_required"], latency_ms, cost_usd),
        )
    conn.commit()


def read_audit_trail(run_id: str) -> list[dict]:
    conn = psycopg2.connect(**PG_DSN, cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM audit_trail WHERE run_id = %s", (run_id,))
        rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def write_report_file(run_id: str, result: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{run_id}.json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    return path


# ============================================================
# COMPLIANCE POLICY DATABASE (ChromaDB) -- policies only, never
# customer contract data (data isolation)
# ============================================================
import chromadb

POLICIES_FILE = os.getenv("POLICIES_FILE", "policies.json")
with open(POLICIES_FILE) as f:
    _policies_data = json.load(f)
POLICIES = {p["policy_id"]: p for p in _policies_data["policies"] if p.get("active", True)}

_policy_store = None


def get_policy_store():
    global _policy_store
    if _policy_store is not None:
        return _policy_store
    client = chromadb.PersistentClient(path=os.getenv("POLICY_DB_PATH", "./compliance_policies_db"))
    collection = client.get_or_create_collection(name="compliance_policies")
    if collection.count() == 0:
        collection.add(
            documents=[p["embedding_text_en"] for p in POLICIES.values()],
            ids=list(POLICIES.keys()),
            metadatas=[{"policy_id": pid, "name": p["name_en"]} for pid, p in POLICIES.items()],
        )
    _policy_store = collection
    return collection


# ============================================================
# THE MODEL
# ============================================================
class FakeResponse:
    def __init__(self, content):
        self.content = content
        self.usage_metadata = {"input_tokens": 220, "output_tokens": 90}


class FakeChatModel:
    """Offline model. For policy evaluation prompts, it does simple keyword
    matching against the policy's own non-compliance indicators inside the
    contract text -- good enough to exercise the full pipeline realistically
    without a real API key."""

    def __init__(self):
        self.review_calls = 0

    def invoke(self, prompt: str, **kw):
        p = prompt.lower()

        if "policy id:" in p and "indicators of non-compliance:" in p:
            return FakeResponse(self._fake_policy_eval(prompt))

        if "quality" in p and "score" in p:
            self.review_calls += 1
            score = 5 if self.review_calls == 1 else 9
            return FakeResponse(json.dumps({"score": score, "feedback": "Cross-check retention and cross-border clauses more explicitly."}))

        return FakeResponse("No issues found.")

    def _fake_policy_eval(self, prompt: str) -> str:
        """Offline approximation of the LLM's judgement.

        The v1 dataset gives four labelled example sets per policy: acceptable
        clauses, missing-clause indicators, non-compliance indicators and
        ambiguity indicators. This mock scores the contract's word overlap
        against ALL FOUR and picks the best-matching category -- which lets it
        distinguish compliant drafting from violations far better than only
        looking for violations. It is still a crude stand-in: it has no notion
        of negation or context, so a real LLM call (MOCK=0) will always be
        more accurate.
        """
        def field(label):
            m = re.search(re.escape(label) + r":\s*(.+)", prompt)
            return [x.strip() for x in m.group(1).split(";") if x.strip()] if m else []

        policy_id_match = re.search(r"Policy ID:\s*(\S+)", prompt)
        policy_id = policy_id_match.group(1) if policy_id_match else "UNKNOWN"

        risk_match = re.search(r"Default risk level:\s*(\S+)", prompt)
        default_risk = risk_match.group(1) if risk_match else "medium"

        contract_match = re.search(r"Contract text:\s*(.+?)\s*Evaluate", prompt, re.DOTALL)
        contract_text = contract_match.group(1).lower() if contract_match else ""
        contract_words = set(re.findall(r"[a-z]{4,}", contract_text))

        categories = {
            "compliant": field("Examples of ACCEPTABLE/compliant clauses"),
            "missing": field("Indicators the clause is MISSING entirely"),
            "non_compliant": field("Indicators of NON-COMPLIANCE"),
            "ambiguous": field("Indicators the situation is AMBIGUOUS"),
        }

        best = {"status": None, "score": 0.0, "example": None}
        compliant_score = 0.0
        for status, examples in categories.items():
            for ex in examples:
                ex_words = set(re.findall(r"[a-z]{4,}", ex.lower()))
                if not ex_words:
                    continue
                score = len(ex_words & contract_words) / len(ex_words)
                if status == "compliant":
                    compliant_score = max(compliant_score, score)
                if score > best["score"]:
                    best = {"status": status, "score": score, "example": ex}

        # A full contract contains clauses for every policy, so unrelated
        # clauses can share vocabulary with an indicator by accident. Require a
        # violation to clearly beat the compliant match before flagging it.
        MARGIN = 0.15
        flagged = (
            best["status"] not in (None, "compliant")
            and best["score"] >= 0.35
            and best["score"] >= compliant_score + MARGIN
        )

        if not flagged:
            return json.dumps({
                "policy_id": policy_id,
                "status": "compliant",
                "risk_level": "low",
                "contract_evidence": best["example"] if best["status"] == "compliant" else "",
                "reason": "The contract's drafting on this point is consistent with the policy requirement.",
                "recommendation": "No action needed; confirm during legal review.",
                "human_review_required": False,
                "confidence": round(min(0.95, 0.6 + best["score"]), 2),
            })

        status = best["status"]
        risk = default_risk if status == "non_compliant" else (
            "medium" if status == "ambiguous" else default_risk)
        reasons = {
            "non_compliant": f"Contract language appears consistent with a known non-compliance pattern: '{best['example']}'.",
            "missing": f"The contract appears to lack the required clause: '{best['example']}'.",
            "ambiguous": f"The relevant clause is present but unclear: '{best['example']}'.",
        }
        recos = {
            "non_compliant": "Revise this clause to align with the documented policy requirement.",
            "missing": "Add an express clause addressing this policy requirement.",
            "ambiguous": "Clarify this clause so the obligation is unambiguous.",
        }
        return json.dumps({
            "policy_id": policy_id,
            "status": status,
            "risk_level": risk,
            "contract_evidence": best["example"],
            "reason": reasons[status],
            "recommendation": recos[status],
            "human_review_required": (risk in ("high", "critical")) or status == "ambiguous",
            "confidence": round(min(0.95, 0.6 + best["score"]), 2),
        })



def get_model():
    if MOCK:
        return FakeChatModel()
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"),
        temperature=0.2,
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
    )


model = get_model()


def call_llm(prompt: str, state: "AuditState") -> str:
    response = model.invoke(prompt)
    usage = getattr(response, "usage_metadata", None) or {}
    ti, to = usage.get("input_tokens", 0), usage.get("output_tokens", 0)
    state["tokens_in"] = state.get("tokens_in", 0) + ti
    state["tokens_out"] = state.get("tokens_out", 0) + to
    cost = ti * PRICE_IN + to * PRICE_OUT
    state["cost_usd"] = state.get("cost_usd", 0.0) + cost
    AUDIT_COST.inc(cost)
    return response.content


# ============================================================
# STATE
# ============================================================
class AuditState(TypedDict, total=False):
    run_id: str
    contract_file: str
    contract_text: str
    policy_results: list
    contract_verdict: dict
    report_path: str
    quality_score: int
    review_feedback: str
    retry_count: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    status: str


# ============================================================
# GRAPH NODES
# ============================================================
def pdf_parser(state: AuditState):
    log_event(state["run_id"], "node", node="pdf_parser")
    reader = PdfReader(state["contract_file"])
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return {"contract_text": text, "status": "parsed"}


def compliance_analysis_agent(state: AuditState):
    """Checks the contract against every policy in the loaded policy set
    (data isolation: policies never contain customer data, only the
    company's own compliance rules -- see module docstring)."""
    log_event(state["run_id"], "node", node="compliance_analysis_agent")

    feedback_line = f"\n\nAdditional reviewer feedback to consider: {state['review_feedback']}" if state.get("review_feedback") else ""

    conn = _init_audit_db()
    results = []

    for policy_id, policy in POLICIES.items():
        start = time.time()
        cost_before = state.get("cost_usd", 0.0)

        applicability = "; ".join(policy.get("applicability_conditions", [])) or "Not specified -- assume applicable."
        not_applicable = "; ".join(policy.get("not_applicable_conditions", [])) or "None specified."
        acceptable_examples = "; ".join(policy.get("acceptable_clause_examples", [])) or "None provided."
        missing_indicators = "; ".join(policy.get("missing_clause_indicators", [])) or "None provided."
        non_compliance_indicators = "; ".join(policy.get("non_compliance_indicators", [])) or "None provided."
        ambiguity_indicators = "; ".join(policy.get("ambiguity_indicators", [])) or "None provided."
        human_review_triggers = "; ".join(policy.get("human_review_triggers", [])) or "None provided."
        dataset_recommendation = policy.get("recommendation_en", "")

        prompt = f"""You are a compliance auditor evaluating a contract against a specific policy.

Policy ID: {policy['policy_id']}
Policy Name: {policy['name_en']}
Requirement: {policy['contract_requirement_en']}

Applies when: {applicability}
Does NOT apply when: {not_applicable}
Examples of ACCEPTABLE/compliant clauses: {acceptable_examples}
Indicators the clause is MISSING entirely: {missing_indicators}
Indicators of NON-COMPLIANCE: {non_compliance_indicators}
Indicators the situation is AMBIGUOUS: {ambiguity_indicators}
Default risk level: {policy['default_risk_level']}
Human review triggers: {human_review_triggers}
Suggested recommendation if non-compliant (adapt to the actual contract, don't just copy verbatim): {dataset_recommendation}

Contract text:
{state['contract_text']}{feedback_line}

Evaluate this contract against the policy. If the "does not apply" conditions are met, use
status "not_applicable". Respond with ONLY a JSON object in exactly this format:
{{
  "policy_id": "{policy['policy_id']}",
  "status": "compliant" | "non_compliant" | "missing" | "ambiguous" | "not_applicable",
  "risk_level": "low" | "medium" | "high" | "critical",
  "contract_evidence": "<exact or paraphrased quote from the contract, or empty string if missing/not_applicable>",
  "reason": "<one sentence explaining the status>",
  "recommendation": "<one sentence recommendation, adapted to this specific contract>",
  "human_review_required": true | false,
  "confidence": <number between 0 and 1 indicating how confident you are in this assessment>
}}"""

        response = call_llm(prompt, state)
        try:
            result = json.loads(response)
        except json.JSONDecodeError:
            result = {
                "policy_id": policy_id, "status": "ambiguous", "risk_level": policy["default_risk_level"],
                "contract_evidence": "", "reason": "Model response could not be parsed as JSON.",
                "recommendation": "Retry this policy check or route to human review.", "human_review_required": True,
            }

        latency_ms = round((time.time() - start) * 1000, 2)
        clause_cost = round(state.get("cost_usd", 0.0) - cost_before, 8)
        write_audit_entry(conn, state["run_id"], state["contract_file"], result, latency_ms, clause_cost)
        # enrich with policy metadata the UI displays
        result["policy_name"] = policy.get("name_en", policy_id)
        refs = policy.get("source_references", [])
        if refs:
            articles = sorted({r["article"] for r in refs if r.get("article")})
            result["source_reference"] = "Saudi PDPL -- Article " + ", ".join(articles)
        else:
            result["source_reference"] = ""

        results.append(result)

        log_event(state["run_id"], "policy_checked", policy_id=policy_id, status=result["status"],
                   risk_level=result["risk_level"], latency_ms=latency_ms, cost_usd=clause_cost)

    conn.close()
    return {
        "policy_results": results, "status": "analysis_complete",
        "tokens_in": state["tokens_in"], "tokens_out": state["tokens_out"], "cost_usd": state["cost_usd"],
    }


def reviewer_evaluator(state: AuditState):
    """Judges whether the compliance analysis is thorough enough."""
    log_event(state["run_id"], "node", node="reviewer_evaluator")
    summary = "\n".join(
        f"- {r['policy_id']}: {r['status']} ({r['risk_level']})" for r in state.get("policy_results", [])
    )
    prompt = f"Rate the quality of this compliance analysis 1-10 as JSON {{score, feedback}}:\n{summary or 'No policies evaluated.'}"
    response = call_llm(prompt, state)
    try:
        data = json.loads(response)
        score, feedback = int(data["score"]), data.get("feedback", "")
    except Exception:
        score, feedback = 7, "unparseable review"

    retry_count = state.get("retry_count", 0) + 1
    log_event(state["run_id"], "review_verdict", score=score, retry_count=retry_count)
    return {
        "quality_score": score, "review_feedback": feedback, "retry_count": retry_count,
        "tokens_in": state["tokens_in"], "tokens_out": state["tokens_out"], "cost_usd": state["cost_usd"],
    }


def review_gate(state: AuditState) -> str:
    if state["quality_score"] >= QUALITY_THRESHOLD or state["retry_count"] > MAX_RETRIES:
        return "generate_report"
    AUDITS_RETRIED.inc()
    return "retry"


def determine_contract_verdict(policy_results: list) -> dict:
    """Three-state verdict. Strict rules, in priority order:

      Not Approved          -- any non-compliant or missing finding, i.e. a
                               concrete policy failure the contract must fix.
      Human Review Required -- no hard failure, but something still blocks a
                               clean approval: an ambiguous finding, any
                               CRITICAL-risk finding (never auto-approved,
                               regardless of status), or a policy flagged as
                               needing specialist review.
      Approved              -- every policy compliant or not applicable, no
                               critical risk, and nothing flagged for review.

    The justification is deliberately short -- a one-line summary for the
    reader. The specific policy IDs are returned separately so the UI can
    show them in the findings list rather than in a wall of text.
    """
    hard_fail = [r for r in policy_results if r["status"] in ("non_compliant", "missing")]
    ambiguous = [r for r in policy_results if r["status"] == "ambiguous"]
    critical = [r for r in policy_results if r["risk_level"] == "critical"]
    needs_human = [r for r in policy_results if r.get("human_review_required")]

    total = len(policy_results)
    blocking_ids = [r["policy_id"] for r in hard_fail]
    critical_ids = [r["policy_id"] for r in critical]
    human_ids = [r["policy_id"] for r in needs_human]

    def plural(n, word):
        return f"{n} {word}" + ("" if n == 1 else "s")

    if hard_fail:
        verdict = "Not Approved"
        bits = [f"{plural(len(hard_fail), 'policy requirement')} not met"]
        if critical:
            bits.append(f"{len(critical)} at critical risk")
        justification = (
            f"{', including '.join(bits) if len(bits) > 1 else bits[0]}. "
            f"The contract must be revised before it can be approved."
        )
    elif critical or ambiguous or needs_human:
        verdict = "Human Review Required"
        attention = len({r["policy_id"] for r in critical + ambiguous + needs_human})
        if critical:
            verb = "carries" if len(critical) == 1 else "carry"
            justification = (
                f"No outright failures, but {plural(len(critical), 'finding')} {verb} critical risk "
                f"and cannot be auto-approved. A privacy specialist should review before signing."
            )
        else:
            justification = (
                f"No outright failures, but {plural(attention, 'finding')} need interpretation "
                f"before approval. A privacy specialist should review before signing."
            )
    else:
        verdict = "Approved"
        justification = (
            f"All {total} policies assessed as compliant, with no critical risks "
            f"and nothing flagged for specialist review."
        )

    return {
        "verdict": verdict,
        "justification": justification,
        "blocking_policies": blocking_ids,
        "critical_policies": critical_ids,
        "human_review_policies": human_ids,
    }


def generate_report(state: AuditState):
    log_event(state["run_id"], "node", node="generate_report")
    verdict = determine_contract_verdict(state.get("policy_results", []))
    log_event(state["run_id"], "contract_verdict", verdict=verdict["verdict"],
               blocking_count=len(verdict["blocking_policies"]),
               critical_count=len(verdict["critical_policies"]))

    full_state = {**dict(state), "contract_verdict": verdict}
    report_path = write_report_file(state["run_id"], full_state)
    log_event(state["run_id"], "report_written", path=report_path)
    return {"status": "audit_complete", "report_path": report_path, "contract_verdict": verdict}


def build_graph():
    g = StateGraph(AuditState)
    g.add_node("pdf_parser", pdf_parser)
    g.add_node("compliance_analysis_agent", compliance_analysis_agent)
    g.add_node("reviewer_evaluator", reviewer_evaluator)
    g.add_node("generate_report", generate_report)

    g.add_edge(START, "pdf_parser")
    g.add_edge("pdf_parser", "compliance_analysis_agent")
    g.add_edge("compliance_analysis_agent", "reviewer_evaluator")
    g.add_conditional_edges("reviewer_evaluator", review_gate,
                             {"retry": "compliance_analysis_agent", "generate_report": "generate_report"})
    g.add_edge("generate_report", END)
    return g.compile()


# ============================================================
# CORE ENTRYPOINT
# ============================================================
def run_audit(contract_file: str) -> dict:
    run_id = uuid.uuid4().hex[:12]
    AUDITS_TOTAL.inc()
    log_event(run_id, "request", contract_file=contract_file)

    with AUDIT_LATENCY.time():
        allowed, reason = input_security_guard(contract_file)
        if not allowed:
            AUDITS_BLOCKED.inc()
            log_event(run_id, "blocked", reason=reason)
            return {"run_id": run_id, "status": "blocked", "reason": reason}

        store_contract_in_minio(run_id, contract_file)

        graph = build_graph()
        state = {"run_id": run_id, "contract_file": contract_file, "retry_count": 0,
                  "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}
        final = graph.invoke(state)

    log_event(run_id, "response", status="ok", cost_usd=round(final.get("cost_usd", 0), 6))
    return {"run_id": run_id, **final}


# ============================================================
# FASTAPI SERVICE
# ============================================================
from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.responses import HTMLResponse

app = FastAPI(title="Contract Audit & Compliance Agent v2")

UPLOAD_PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Contract Compliance Audit</title>
<style>
  :root {
    --bg: #f5f6f8; --card: #ffffff; --text: #232935;
    --text-muted: #6b7280; --text-soft: #8a909c;
    --border: #e6e8ec; --border-soft: #eef0f3;
    --accent: #33507e; --accent-soft: #eef2f9;
    --green-bg: #ebf6ef; --green-text: #1f7a4d; --green-border: #d3e9dd;
    --red-bg: #fbedec; --red-text: #b23b32; --red-border: #f0d5d3;
    --orange-bg: #fbf0e6; --orange-text: #b0691f; --orange-border: #f0ddc8;
    --amber-bg: #fbf6e3; --amber-text: #93761a; --amber-border: #eee5c1;
    --review-bg: #eef1fb; --review-text: #4a4f93; --review-border: #dde1f5;
    --radius-lg: 16px; --radius-md: 12px; --radius-sm: 9px;
    --shadow: 0 1px 3px rgba(23,30,46,.05), 0 1px 2px rgba(23,30,46,.03);
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 16px; line-height: 1.6; -webkit-font-smoothing: antialiased;
  }
  .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

  .app-header { display: flex; justify-content: space-between; align-items: flex-start;
    gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .app-header h1 { font-size: 24px; font-weight: 600; margin: 0 0 6px; letter-spacing: -.01em; }
  .app-meta { display: flex; flex-wrap: wrap; gap: 6px 18px; color: var(--text-muted); font-size: 15px; }
  .app-meta span strong { color: var(--text); font-weight: 500; }
  .ai-tag { display: inline-flex; align-items: center; gap: 7px; background: var(--accent-soft);
    color: var(--accent); font-size: 13px; font-weight: 500; padding: 7px 13px;
    border-radius: 999px; white-space: nowrap; }
  .ai-tag .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }

  .card { background: var(--card); border: 1px solid var(--border);
    border-radius: var(--radius-lg); box-shadow: var(--shadow); }

  .upload-card { padding: 26px 28px; margin-bottom: 22px; }
  #dropzone { border: 2px dashed #ccd2de; border-radius: var(--radius-md); padding: 38px 20px;
    text-align: center; cursor: pointer; transition: all .15s; }
  #dropzone.dragover { border-color: var(--accent); background: var(--accent-soft); }
  #dropzone p { margin: 4px 0; color: var(--text-muted); }
  #dropzone .filename { font-weight: 600; color: var(--text); }
  .primary-btn { background: var(--accent); color: #fff; border: none; padding: 11px 24px;
    border-radius: var(--radius-sm); font: inherit; font-size: 15px; font-weight: 600;
    cursor: pointer; margin-top: 16px; }
  .primary-btn:disabled { background: #aeb5c2; cursor: default; }
  #status { margin-top: 12px; font-size: 14px; color: var(--text-muted); }
  #status.error { color: var(--red-text); font-weight: 600; }
  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #ccc;
    border-top-color: var(--accent); border-radius: 50%; animation: spin .7s linear infinite;
    vertical-align: middle; margin-right: 8px; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .overall { padding: 28px 32px; margin-bottom: 20px; display: flex; gap: 32px;
    align-items: center; flex-wrap: wrap; }
  .ring-wrap { flex-shrink: 0; }
  .ring { position: relative; width: 132px; height: 132px; }
  .ring svg { transform: rotate(-90deg); }
  .ring-label { position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center; }
  .ring-pct { font-size: 30px; font-weight: 600; letter-spacing: -.02em; }
  .ring-cap { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
  .overall-body { flex: 1; min-width: 260px; }
  .decision-badge { display: inline-flex; align-items: center; gap: 9px; font-size: 15px;
    font-weight: 600; padding: 9px 16px; border-radius: 999px; margin-bottom: 14px; border: 1px solid; }
  .decision-badge .ic { width: 18px; height: 18px; }
  .overall-explain { font-size: 16px; margin: 0 0 16px; max-width: 620px; }
  .overall-facts { display: flex; flex-wrap: wrap; gap: 10px 28px; color: var(--text-muted); font-size: 14px; }
  .overall-facts span strong { color: var(--text); font-weight: 600; }

  .summary-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
  .summary-item { background: var(--card); border: 1px solid var(--border);
    border-radius: var(--radius-md); padding: 16px 18px; box-shadow: var(--shadow); }
  .summary-num { font-size: 26px; font-weight: 600; line-height: 1.1; }
  .summary-lbl { font-size: 14px; color: var(--text-muted); margin-top: 4px;
    display: flex; align-items: center; gap: 7px; }
  .summary-lbl .swatch { width: 9px; height: 9px; border-radius: 3px; }

  .section-title { font-size: 17px; font-weight: 600; margin: 0 0 14px; }
  .finding { background: var(--card); border: 1px solid var(--border);
    border-radius: var(--radius-md); box-shadow: var(--shadow); margin-bottom: 14px; overflow: hidden; }

  /* the whole finding header is a button */
  .finding-head { padding: 18px 20px; width: 100%; text-align: left; background: none;
    border: none; font: inherit; color: inherit; cursor: pointer; display: block; transition: background .15s; }
  .finding-head:hover { background: #fafbfc; }
  .finding-head:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

  .finding-top { display: flex; justify-content: space-between; gap: 14px;
    align-items: flex-start; flex-wrap: wrap; }
  .finding-id { font-size: 13px; color: var(--text-soft); font-weight: 500;
    letter-spacing: .02em; margin-bottom: 3px; }
  .finding-name { font-size: 17px; font-weight: 600; margin: 0; }
  .finding-badges { display: flex; gap: 8px; align-items: center; flex-shrink: 0; flex-wrap: wrap; }
  .badge { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 500;
    padding: 5px 12px; border-radius: 999px; border: 1px solid transparent; white-space: nowrap; }
  .badge .swatch { width: 8px; height: 8px; border-radius: 50%; }
  .risk-label { font-size: 13px; color: var(--text-muted); font-weight: 500; }
  .finding-reason { margin: 12px 0 0; color: var(--text-muted); font-size: 15px; }
  .review-note { display: inline-flex; align-items: center; gap: 7px; margin-top: 12px;
    font-size: 14px; color: var(--review-text); font-weight: 500; }
  .review-note .ic { width: 16px; height: 16px; }
  .expand-hint { margin-top: 14px; font-size: 14px; font-weight: 500; color: var(--accent);
    display: inline-flex; align-items: center; gap: 7px; }
  .expand-hint .chev { transition: transform .18s; width: 15px; height: 15px; }
  .finding-head[aria-expanded="true"] .chev { transform: rotate(180deg); }

  .finding-details { border-top: 1px solid var(--border-soft); padding: 20px;
    display: grid; gap: 18px; background: #fcfcfd; }
  .detail-block .detail-label { font-size: 12px; font-weight: 600; color: var(--text-soft);
    letter-spacing: .04em; text-transform: uppercase; margin-bottom: 7px; }
  .detail-block p { margin: 0; font-size: 15px; }
  .quote { background: #f4f5f7; border-radius: var(--radius-sm); padding: 16px 18px 16px 46px;
    position: relative; font-size: 15.5px; line-height: 1.6; }
  .quote::before { content: "\201C"; position: absolute; left: 14px; top: 4px; font-size: 40px;
    line-height: 1; color: #c3c8d2; font-family: Georgia, serif; }
  .reco { background: var(--green-bg); border: 1px solid var(--green-border);
    border-radius: var(--radius-sm); padding: 15px 17px; display: flex; gap: 12px; align-items: flex-start; }
  .reco .ic { width: 20px; height: 20px; color: var(--green-text); flex-shrink: 0; margin-top: 1px; }
  .reco .reco-label { font-size: 12px; font-weight: 600; color: var(--green-text);
    letter-spacing: .03em; text-transform: uppercase; margin-bottom: 4px; }
  .reco p { margin: 0; font-size: 15px; color: #1c4632; }
  .detail-meta { display: flex; flex-wrap: wrap; gap: 10px 32px; font-size: 14px; color: var(--text-muted); }
  .detail-meta span strong { color: var(--text); font-weight: 600; }

  .more-btn { width: 100%; border: 1px solid var(--border); background: var(--card);
    color: var(--accent); font: inherit; font-size: 15px; font-weight: 600;
    padding: 14px; border-radius: var(--radius-md); cursor: pointer; box-shadow: var(--shadow);
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    margin-bottom: 14px; transition: background .15s; }
  .more-btn:hover { background: #f7f8fa; }
  .more-btn .chev { transition: transform .18s; width: 16px; height: 16px; }
  .more-btn[aria-expanded="true"] .chev { transform: rotate(180deg); }

  .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }
  .btn { border: 1px solid var(--border); background: var(--card); color: var(--text); font: inherit;
    font-size: 14px; font-weight: 500; padding: 9px 16px; border-radius: var(--radius-sm);
    cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: var(--shadow); }
  .btn:hover { background: #f7f8fa; border-color: #d7dae0; }
  .btn .ic { width: 16px; height: 16px; }

  @media (max-width: 720px) {
    .page { padding: 22px 16px 48px; }
    .summary-row { grid-template-columns: repeat(2, 1fr); }
    .overall { padding: 22px; gap: 22px; }
    .finding-top { flex-direction: column; }
  }
  @media print {
    html, body { background: #fff; }
    .page { max-width: 100%; padding: 0; }
    .actions, .upload-card, .expand-hint, .more-btn { display: none !important; }
    .finding-details { display: grid !important; }
    .rest-findings { display: block !important; }
    .card, .finding, .summary-item { box-shadow: none; break-inside: avoid; }
    .quote, .reco { background: #fff !important; }
  }
</style>
</head>
<body>
  <div class="page">
    <div class="app-header">
      <div>
        <h1>Contract Compliance Audit</h1>
        <div class="app-meta">
          <span>Automated PDPL / SDAIA policy review for vendor data processing agreements</span>
        </div>
      </div>
      <div class="ai-tag"><span class="dot"></span>AI-Assisted Contract Review</div>
    </div>

    <div class="card upload-card">
      <div id="dropzone" onclick="document.getElementById('fileInput').click()">
        <input type="file" id="fileInput" accept="application/pdf" style="display:none" onchange="fileChosen()">
        <p style="font-size:15px;">Drop a PDF contract here, or click to choose a file</p>
        <p class="filename" id="filenameLabel"></p>
      </div>
      <button id="uploadBtn" class="primary-btn" onclick="uploadFile()" disabled>Run Compliance Audit</button>
      <div id="status"></div>
    </div>

    <div id="audit-root"></div>
  </div>

<script>
"use strict";

var STATUS_WEIGHT = { compliant: 1.0, not_applicable: 1.0, ambiguous: 0.5, missing: 0.25, non_compliant: 0.0 };

function calculateComplianceScore(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return 100;
  var total = 0;
  findings.forEach(function (f) {
    var w = STATUS_WEIGHT[f.status];
    total += (typeof w === "number") ? w : 0;
  });
  return Math.round((total / findings.length) * 100);
}

function calculateFindingCounts(findings) {
  var c = { compliant: 0, non_compliant: 0, missing: 0, ambiguous: 0, not_applicable: 0,
            needs_attention: 0, human_review: 0, critical: 0 };
  if (!Array.isArray(findings)) return c;
  findings.forEach(function (f) {
    if (c.hasOwnProperty(f.status)) c[f.status] += 1;
    if (f.status === "non_compliant" || f.status === "missing" || f.status === "ambiguous") c.needs_attention += 1;
    if (f.human_review_required) c.human_review += 1;
    if (f.risk_level === "critical") c.critical += 1;
  });
  return c;
}

var STATUS_META = {
  compliant:      { label: "Compliant",      bg: "--green-bg",  text: "--green-text",  border: "--green-border" },
  non_compliant:  { label: "Non-Compliant",  bg: "--red-bg",    text: "--red-text",    border: "--red-border" },
  missing:        { label: "Missing",        bg: "--orange-bg", text: "--orange-text", border: "--orange-border" },
  ambiguous:      { label: "Ambiguous",      bg: "--amber-bg",  text: "--amber-text",  border: "--amber-border" },
  not_applicable: { label: "Not Applicable", bg: "--accent-soft", text: "--accent",    border: "--border" }
};

var DECISION_META = {
  "Approved":              { color: "--green-text",  bg: "--green-bg",  border: "--green-border",  icon: "check" },
  "Human Review Required": { color: "--review-text", bg: "--review-bg", border: "--review-border", icon: "eye" },
  "Not Approved":          { color: "--red-text",    bg: "--red-bg",    border: "--red-border",    icon: "x" }
};

function cssv(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function isRTLText(s) { return typeof s === "string" && /[\u0600-\u06FF\u0750-\u077F]/.test(s); }

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) {
    n.textContent = text;
    if (isRTLText(text)) n.setAttribute("dir", "rtl");
  }
  return n;
}

function icon(name) {
  var ns = "http://www.w3.org/2000/svg";
  var paths = {
    check: "M20 6L9 17l-5-5", x: "M18 6L6 18M6 6l12 12",
    eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 15a3 3 0 100-6 3 3 0 000 6z",
    chevron: "M6 9l6 6 6-6",
    bulb: "M9 18h6 M10 21h4 M12 3a6 6 0 00-4 10c.7.7 1 1.3 1 2h6c0-.7.3-1.3 1-2a6 6 0 00-4-10z",
    printer: "M6 9V3h12v6 M6 18H4v-6h16v6h-2 M8 14h8v7H8z",
    expand: "M4 8V4h4 M20 8V4h-4 M4 16v4h4 M20 16v4h-4",
    collapse: "M9 4v4H5 M15 4v4h4 M9 20v-4H5 M15 20v-4h4",
    user: "M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2 M12 11a4 4 0 100-8 4 4 0 000 8z"
  };
  var svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "ic"); svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2"); svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  (paths[name] || "").split(" M").forEach(function (seg, i) {
    var p = document.createElementNS(ns, "path");
    p.setAttribute("d", (i === 0 ? "" : "M") + seg);
    svg.appendChild(p);
  });
  return svg;
}

function formatType(t) {
  if (!t) return "";
  return String(t).replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

function renderRing(score, decision) {
  var size = 132, stroke = 11, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  var offset = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  var m = DECISION_META[decision] || DECISION_META["Human Review Required"];
  var color = cssv(m.color);

  var wrap = el("div", "ring-wrap"), ring = el("div", "ring");
  var ns = "http://www.w3.org/2000/svg";
  var svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", size); svg.setAttribute("height", size);
  svg.setAttribute("viewBox", "0 0 " + size + " " + size);

  var track = document.createElementNS(ns, "circle");
  track.setAttribute("cx", size/2); track.setAttribute("cy", size/2); track.setAttribute("r", r);
  track.setAttribute("fill", "none"); track.setAttribute("stroke", "#eceef2");
  track.setAttribute("stroke-width", stroke);

  var prog = document.createElementNS(ns, "circle");
  prog.setAttribute("cx", size/2); prog.setAttribute("cy", size/2); prog.setAttribute("r", r);
  prog.setAttribute("fill", "none"); prog.setAttribute("stroke", color);
  prog.setAttribute("stroke-width", stroke); prog.setAttribute("stroke-linecap", "round");
  prog.setAttribute("stroke-dasharray", c); prog.setAttribute("stroke-dashoffset", offset);

  svg.appendChild(track); svg.appendChild(prog); ring.appendChild(svg);
  var label = el("div", "ring-label");
  label.appendChild(el("div", "ring-pct", score + "%"));
  label.appendChild(el("div", "ring-cap", "Compliance"));
  ring.appendChild(label); wrap.appendChild(ring);
  return wrap;
}

function buildBrief(decision, findings, counts) {
  var total = findings.length;
  if (decision === "Approved") {
    return "All " + total + " policies passed with no critical risks and nothing flagged for review.";
  }
  if (decision === "Not Approved") {
    var bits = [counts.non_compliant + " policy failure" + (counts.non_compliant === 1 ? "" : "s")];
    if (counts.missing) bits.push(counts.missing + " missing clause" + (counts.missing === 1 ? "" : "s"));
    if (counts.critical) bits.push(counts.critical + " at critical risk");
    return "This contract cannot be approved: " + bits.join(", ") + " out of " + total + " policies checked.";
  }
  var reasons = [];
  if (counts.ambiguous) reasons.push(counts.ambiguous + " clause" + (counts.ambiguous === 1 ? "" : "s") + " need interpretation");
  if (counts.critical) reasons.push(counts.critical + " carry critical risk");
  if (!reasons.length && counts.human_review) reasons.push(counts.human_review + " flagged for specialist review");
  return "No outright failures, but " + reasons.join(" and ") + " before this contract can be approved.";
}

var STATUS_PRIORITY = { non_compliant: 0, missing: 1, ambiguous: 2, not_applicable: 3, compliant: 4 };
var RISK_PRIORITY = { critical: 0, high: 1, medium: 2, low: 3 };

function sortByImportance(findings) {
  return findings.slice().sort(function (a, b) {
    var s = (STATUS_PRIORITY[a.status] ?? 9) - (STATUS_PRIORITY[b.status] ?? 9);
    if (s !== 0) return s;
    var r = (RISK_PRIORITY[a.risk_level] ?? 9) - (RISK_PRIORITY[b.risk_level] ?? 9);
    if (r !== 0) return r;
    return (b.human_review_required ? 1 : 0) - (a.human_review_required ? 1 : 0);
  });
}

function renderOverall(data, findings) {
  var score = calculateComplianceScore(findings);
  var v = data.contract_verdict || {};
  var decision = v.verdict || "Human Review Required";
  var counts = calculateFindingCounts(findings);
  var meta = DECISION_META[decision] || DECISION_META["Human Review Required"];

  var card = el("div", "card overall");
  card.appendChild(renderRing(score, decision));
  var body = el("div", "overall-body");

  var badge = el("div", "decision-badge");
  badge.style.background = cssv(meta.bg);
  badge.style.color = cssv(meta.color);
  badge.style.borderColor = cssv(meta.border);
  badge.appendChild(icon(meta.icon));
  badge.appendChild(document.createTextNode(decision));
  body.appendChild(badge);

  body.appendChild(el("p", "overall-explain", buildBrief(decision, findings, counts)));

  var facts = el("div", "overall-facts");
  function stat(label, value) {
    var s = el("span");
    s.appendChild(el("strong", null, String(value)));
    s.appendChild(document.createTextNode(" " + label));
    return s;
  }
  facts.appendChild(stat("policies checked", findings.length));
  facts.appendChild(stat("need attention", counts.needs_attention));
  facts.appendChild(stat("critical risk", counts.critical));
  var hr = el("span");
  hr.appendChild(el("strong", null, counts.human_review > 0 ? "Yes" : "No"));
  hr.appendChild(document.createTextNode(" human review"));
  facts.appendChild(hr);
  body.appendChild(facts);

  card.appendChild(body);
  return card;
}

function renderSummary(findings) {
  var counts = calculateFindingCounts(findings);
  var row = el("div", "summary-row");
  [{ num: counts.compliant, label: "Compliant", color: "--green-text" },
   { num: counts.non_compliant, label: "Non-Compliant", color: "--red-text" },
   { num: counts.needs_attention, label: "Needs Attention", color: "--orange-text" },
   { num: counts.human_review, label: "Human Review", color: "--review-text" }
  ].forEach(function (it) {
    var box = el("div", "summary-item");
    box.appendChild(el("div", "summary-num", String(it.num)));
    var lbl = el("div", "summary-lbl");
    var sw = el("span", "swatch"); sw.style.background = cssv(it.color);
    lbl.appendChild(sw); lbl.appendChild(document.createTextNode(it.label));
    box.appendChild(lbl); row.appendChild(box);
  });
  return row;
}

function renderFinding(f, index) {
  var meta = STATUS_META[f.status] ||
    { label: formatType(f.status), bg: "--amber-bg", text: "--amber-text", border: "--amber-border" };
  var card = el("div", "finding");

  var detailsId = "details-" + (f.policy_id || index);

  // the entire header is a single button that toggles the details
  var head = document.createElement("button");
  head.className = "finding-head";
  head.type = "button";
  head.setAttribute("aria-expanded", "false");
  head.setAttribute("aria-controls", detailsId);

  var top = el("div", "finding-top");
  var titleWrap = el("div");
  titleWrap.appendChild(el("div", "finding-id", f.policy_id || ""));
  titleWrap.appendChild(el("p", "finding-name", f.policy_name || f.policy_id || "Policy"));
  top.appendChild(titleWrap);

  var badges = el("div", "finding-badges");
  var statusBadge = el("span", "badge");
  statusBadge.style.background = cssv(meta.bg);
  statusBadge.style.color = cssv(meta.text);
  statusBadge.style.borderColor = cssv(meta.border);
  var sw = el("span", "swatch"); sw.style.background = cssv(meta.text);
  statusBadge.appendChild(sw);
  statusBadge.appendChild(document.createTextNode(meta.label));
  badges.appendChild(statusBadge);
  if (f.risk_level) badges.appendChild(el("span", "risk-label", formatType(f.risk_level) + " risk"));
  top.appendChild(badges);
  head.appendChild(top);

  if (f.reason) head.appendChild(el("p", "finding-reason", f.reason));

  if (f.human_review_required) {
    var note = el("div", "review-note");
    note.appendChild(icon("user"));
    note.appendChild(document.createTextNode("Privacy specialist review recommended"));
    head.appendChild(note);
  }

  var hint = el("div", "expand-hint");
  var hintLabel = document.createTextNode("View details");
  hint.appendChild(hintLabel);
  var chev = icon("chevron"); chev.setAttribute("class", "ic chev");
  hint.appendChild(chev);
  head.appendChild(hint);
  card.appendChild(head);

  var details = el("div", "finding-details");
  details.id = detailsId;
  details.hidden = true;

  if (f.contract_evidence) {
    var ev = el("div", "detail-block");
    ev.appendChild(el("div", "detail-label", "Contract evidence"));
    ev.appendChild(el("div", "quote", f.contract_evidence));
    details.appendChild(ev);
  }
  if (f.reason) {
    var rb = el("div", "detail-block");
    rb.appendChild(el("div", "detail-label",
      f.status === "compliant" ? "Assessment" : "Why it failed"));
    rb.appendChild(el("p", null, f.reason));
    details.appendChild(rb);
  }
  if (f.recommendation) {
    var reco = el("div", "reco");
    reco.appendChild(icon("bulb"));
    var rt = el("div");
    rt.appendChild(el("div", "reco-label", "Recommended action"));
    rt.appendChild(el("p", null, f.recommendation));
    reco.appendChild(rt);
    details.appendChild(reco);
  }

  var metaRow = el("div", "detail-meta");
  if (f.source_reference) {
    var src = el("span");
    src.appendChild(document.createTextNode("Policy source: "));
    src.appendChild(el("strong", null, f.source_reference));
    metaRow.appendChild(src);
  }
  if (typeof f.confidence === "number") {
    var conf = el("span");
    conf.appendChild(document.createTextNode("Confidence: "));
    conf.appendChild(el("strong", null, Math.round(f.confidence * 100) + "%"));
    metaRow.appendChild(conf);
  }
  var hrv = el("span");
  hrv.appendChild(document.createTextNode("Human review: "));
  hrv.appendChild(el("strong", null, f.human_review_required ? "Required" : "Not required"));
  metaRow.appendChild(hrv);
  details.appendChild(metaRow);
  card.appendChild(details);

  head.addEventListener("click", function () {
    var open = details.hidden;
    details.hidden = !open;
    head.setAttribute("aria-expanded", open ? "true" : "false");
    hintLabel.textContent = open ? "Hide details" : "View details";
  });

  return card;
}

function renderActions() {
  var wrap = el("div", "actions");
  function mk(ic, label, fn) {
    var b = document.createElement("button");
    b.className = "btn"; b.type = "button";
    b.appendChild(icon(ic)); b.appendChild(document.createTextNode(label));
    b.addEventListener("click", fn);
    return b;
  }
  wrap.appendChild(mk("printer", "Print Report", function () { window.print(); }));
  wrap.appendChild(mk("expand", "Expand All", function () { setAllDetails(true); }));
  wrap.appendChild(mk("collapse", "Collapse All", function () { setAllDetails(false); }));
  return wrap;
}

function setAllDetails(open) {
  // expanding should also reveal any findings hidden behind "View more"
  if (open) {
    document.querySelectorAll(".rest-findings").forEach(function (r) { r.hidden = false; });
    document.querySelectorAll(".more-btn").forEach(function (b) {
      b.setAttribute("aria-expanded", "true");
      if (b.firstChild) b.firstChild.textContent = "Show fewer findings";
    });
  }
  document.querySelectorAll(".finding-details").forEach(function (d) { d.hidden = !open; });
  document.querySelectorAll(".finding-head").forEach(function (h) {
    h.setAttribute("aria-expanded", open ? "true" : "false");
    var hint = h.querySelector(".expand-hint");
    if (hint && hint.firstChild) hint.firstChild.textContent = open ? "Hide details" : "View details";
  });
}

/* Rank findings so the three shown first are genuinely the most serious:
   a real failure outranks an ambiguity, higher risk outranks lower, and
   anything flagged for specialist review outranks anything that isn't. */
var STATUS_RANK = { non_compliant: 0, missing: 1, ambiguous: 2, compliant: 3, not_applicable: 4 };
var RISK_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function sortByImportance(findings) {
  return findings.slice().sort(function (a, b) {
    var sa = STATUS_RANK[a.status], sb = STATUS_RANK[b.status];
    sa = (sa === undefined) ? 9 : sa; sb = (sb === undefined) ? 9 : sb;
    if (sa !== sb) return sa - sb;

    var ra = RISK_RANK[a.risk_level], rb = RISK_RANK[b.risk_level];
    ra = (ra === undefined) ? 9 : ra; rb = (rb === undefined) ? 9 : rb;
    if (ra !== rb) return ra - rb;

    var ha = a.human_review_required ? 0 : 1, hb = b.human_review_required ? 0 : 1;
    if (ha !== hb) return ha - hb;

    return String(a.policy_id).localeCompare(String(b.policy_id));
  });
}

window.renderContractAudit = function (containerId, auditData) {
  var root = document.getElementById(containerId);
  if (!root) return;
  root.textContent = "";
  var findings = Array.isArray(auditData && auditData.policy_results) ? auditData.policy_results : [];

  var report = el("div", "report");
  report.appendChild(renderActions());
  report.appendChild(renderOverall(auditData, findings));
  report.appendChild(renderSummary(findings));
  report.appendChild(el("h2", "section-title", "Findings"));
  if (findings.length === 0) {
    report.appendChild(el("p", "finding-reason", "No findings were returned for this contract."));
  } else {
    var sorted = sortByImportance(findings);
    var TOP_N = 3;
    var top = sorted.slice(0, TOP_N);
    var rest = sorted.slice(TOP_N);

    top.forEach(function (f, i) { report.appendChild(renderFinding(f, i)); });

    if (rest.length) {
      var restWrap = el("div", "rest-findings");
      restWrap.hidden = true;
      rest.forEach(function (f, i) { restWrap.appendChild(renderFinding(f, TOP_N + i)); });

      var moreBtn = document.createElement("button");
      moreBtn.className = "more-btn";
      moreBtn.type = "button";
      var moreLabel = document.createTextNode("View all " + findings.length + " findings");
      moreBtn.appendChild(moreLabel);
      var mchev = icon("chevron");
      mchev.setAttribute("class", "ic chev");
      moreBtn.appendChild(mchev);
      moreBtn.addEventListener("click", function () {
        var open = restWrap.hidden;
        restWrap.hidden = !open;
        moreBtn.setAttribute("aria-expanded", open ? "true" : "false");
        moreLabel.textContent = open
          ? "Show fewer findings"
          : "View all " + findings.length + " findings";
      });

      report.appendChild(moreBtn);
      report.appendChild(restWrap);
    }
  }
  root.appendChild(report);
};

/* ---------- upload flow ---------- */
var dropzone = document.getElementById("dropzone");
var fileInput = document.getElementById("fileInput");
var uploadBtn = document.getElementById("uploadBtn");

["dragover", "dragenter"].forEach(function (e) {
  dropzone.addEventListener(e, function (ev) { ev.preventDefault(); dropzone.classList.add("dragover"); });
});
["dragleave", "drop"].forEach(function (e) {
  dropzone.addEventListener(e, function (ev) { ev.preventDefault(); dropzone.classList.remove("dragover"); });
});
dropzone.addEventListener("drop", function (ev) {
  if (ev.dataTransfer.files.length) { fileInput.files = ev.dataTransfer.files; fileChosen(); }
});

function fileChosen() {
  if (fileInput.files.length) {
    document.getElementById("filenameLabel").textContent = fileInput.files[0].name;
    uploadBtn.disabled = false;
  }
}

async function uploadFile() {
  var status = document.getElementById("status");
  if (!fileInput.files.length) return;

  uploadBtn.disabled = true;
  status.className = "";
  status.innerHTML = '<span class="spinner"></span>Analyzing contract against all policies...';
  document.getElementById("audit-root").textContent = "";

  var fd = new FormData();
  fd.append("file", fileInput.files[0]);

  try {
    var resp = await fetch("/audit", { method: "POST", body: fd });
    var data = await resp.json();
    if (!resp.ok) {
      status.className = "error";
      status.textContent = "Blocked: " + (data.detail || "unknown reason");
      uploadBtn.disabled = false;
      return;
    }
    status.textContent = "Audit complete -- run " + data.run_id +
      " | cost $" + (data.cost_usd || 0).toFixed(6);
    window.renderContractAudit("audit-root", data);
  } catch (err) {
    status.className = "error";
    status.textContent = "Error: " + err;
  }
  uploadBtn.disabled = false;
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def upload_page():
    return UPLOAD_PAGE


@app.get("/health")
def health():
    return {"status": "ok", "mock": MOCK, "minio_enabled": MINIO_ENABLED}


@app.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/audit")
async def audit_endpoint(file: UploadFile = File(...)):
    tmp_path = f"/tmp/{uuid.uuid4().hex}_{file.filename}"
    with open(tmp_path, "wb") as f:
        f.write(await file.read())

    try:
        result = run_audit(tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if result.get("status") == "blocked":
        raise HTTPException(status_code=422, detail=result["reason"])
    return result


@app.get("/audit-trail/{run_id}")
def audit_trail_endpoint(run_id: str):
    rows = read_audit_trail(run_id)
    if not rows:
        raise HTTPException(status_code=404, detail="No audit trail found for that run_id")
    return {"run_id": run_id, "entries": rows}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
    else:
        contract_file = sys.argv[2] if len(sys.argv) > 2 else "sample_contract.pdf"
        result = run_audit(contract_file)
        print("\n=== AUDIT RESULT ===")
        print(json.dumps(result, indent=2, default=str))