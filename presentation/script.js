"use strict";
/* ==========================================================================
   Data Processing Contract Auditor — Presentation logic (v2)
   --------------------------------------------------------------------------
   SOURCE OF TRUTH: github.com/mneerh/AAASE-CAPSTONE
   Verified files: capstone_contract_audit_v2.py (pipeline), docker-compose.yml,
   Dockerfile, requirements.txt, .env.example, sdaia_pdpl_contract_audit_policies_v1.json.

   All architecture, node names, routes, config and state fields below are
   read directly from capstone_contract_audit_v2.py. Only the compliance %,
   counts and score on the OUTPUT slide are demonstration values — the repo
   records no production run yet (Demonstration Evidence section is empty).
   ========================================================================== */

const DATA = {

  /* Architecture nodes — verified from capstone_contract_audit_v2.py. */
  arch: {
    browser: {
      title: "Browser UI", type: "Interaction layer",
      purpose: "Upload a contract and view compliance results.",
      input: "Contract PDF + selected contract type",
      output: "Rendered findings & report",
      repo: "capstone_contract_audit_v2.py · GET / (root)",
      tech: "FastAPI-served page · calls POST /audit (app on port 8080)",
    },
    fastapi: {
      title: "FastAPI service", type: "Service layer",
      purpose: "API entry point that receives uploads and serves results & metrics.",
      input: "HTTP requests",
      output: "Audit result JSON, metrics, audit trail",
      repo: "capstone_contract_audit_v2.py · audit_endpoint / health / metrics",
      tech: "FastAPI + uvicorn · routes: /, /health, /metrics, POST /audit, /audit-trail/{run_id}",
    },
    security: {
      title: "Security guard", type: "Security",
      purpose: "Validate the file and treat contract text as data — not instructions.",
      input: "Raw uploaded file",
      output: "Approved file, or blocked (audits_blocked_total++)",
      repo: "capstone_contract_audit_v2.py · input_security_guard()",
      tech: "Type/size/validity checks + INJECTION_PATTERNS regex scan (e.g. ‘ignore previous instructions’, ‘system prompt’)",
    },
    pdf: {
      title: "PDF parser", type: "LangGraph node",
      purpose: "Extract contract text from the PDF.",
      input: "Stored contract file",
      output: "contract_text",
      repo: "capstone_contract_audit_v2.py · pdf_parser(state)",
      tech: "pypdf (PdfReader)",
    },
    analysis: {
      title: "Analysis agent", type: "LangGraph node",
      purpose: "Compare each applicable policy against the contract and label it.",
      input: "contract_text + policies (from ChromaDB)",
      output: "policy_results (status, risk, evidence, reason, recommendation)",
      repo: "capstone_contract_audit_v2.py · compliance_analysis_agent(state)",
      tech: "LLM call_llm() → nvidia/nemotron-3-super-120b-a12b:free via OpenRouter. Policy set checks 38 policies (DATA-001…DATA-038) per run.",
    },
    reviewer: {
      title: "Reviewer / evaluator", type: "LangGraph node",
      purpose: "Score finding quality; low scores are re-analysed (revision loop).",
      input: "policy_results",
      output: "quality_score, review_feedback",
      repo: "capstone_contract_audit_v2.py · reviewer_evaluator(state) + review_gate(state)",
      tech: "review_gate retries → compliance_analysis_agent when quality_score < QUALITY_THRESHOLD (7), up to MAX_RETRIES (2)",
    },
    verdict: {
      title: "Verdict & report", type: "LangGraph node",
      purpose: "Aggregate an overall verdict and write the compliance report.",
      input: "policy_results",
      output: "contract_verdict, report_path (+ PostgreSQL audit entry)",
      repo: "capstone_contract_audit_v2.py · determine_contract_verdict() + generate_report(state)",
      tech: "Report file + write_audit_entry() to PostgreSQL",
    },
    minio: {
      title: "MinIO storage", type: "Data & knowledge",
      purpose: "Store the uploaded contract file.",
      input: "Approved file",
      output: "Object reference (bucket ‘contracts’)",
      repo: "capstone_contract_audit_v2.py · store_contract_in_minio()",
      tech: "MinIO S3 (docker-compose service, MINIO_ENABLED)",
    },
    chromadb: {
      title: "ChromaDB", type: "Data & knowledge",
      purpose: "Vector store for policy retrieval.",
      input: "Policy embedding text (embedding_text_en / _ar)",
      output: "Applicable policies for the contract",
      repo: "capstone_contract_audit_v2.py · get_policy_store()",
      tech: "ChromaDB (embedded, persisted at ./compliance_policies_db)",
    },
    postgres: {
      title: "PostgreSQL", type: "Data & knowledge",
      purpose: "Persist the audit trail of every run.",
      input: "Audit entries",
      output: "Queryable audit trail (/audit-trail/{run_id})",
      repo: "capstone_contract_audit_v2.py · _init_audit_db / write_audit_entry / read_audit_trail",
      tech: "PostgreSQL 16 · psycopg2 (db ‘compliance_audit’)",
    },
    prometheus: {
      title: "Prometheus metrics", type: "Observability",
      purpose: "Expose runtime metrics for the pipeline.",
      input: "Pipeline events",
      output: "/metrics endpoint",
      repo: "capstone_contract_audit_v2.py · metrics()",
      tech: "prometheus_client: audits_total, audits_blocked_total, audits_retried_total, audit_latency_seconds, audit_cost_usd_total",
    },
  },

  /* Flow order for connectors + Play Flow */
  archFlow: ["browser", "fastapi", "security", "pdf", "analysis", "reviewer", "verdict"],

  /* Workflow — verified from capstone_contract_audit_v2.py.
     `state` patches use the real AuditState field names. */
  workflow: [
    { title: "Receive contract", input: "PDF upload + contract_type", op: "FastAPI accepts the upload and starts an audit run.", output: "run_id, contract_file", state: { run_id: "run_a1b2c3", contract_file: "vendor_dpa_demo.pdf", status: "received" }, route: "→ input_security_guard", fn: "@app.post(\"/audit\") · audit_endpoint()" },
    { title: "Input security guard", input: "Raw file", op: "Check type/size/validity and scan text for INJECTION_PATTERNS.", output: "Approved or blocked", state: { status: "approved" }, route: "approved → MinIO  |  blocked → END", fn: "input_security_guard()" },
    { title: "Store contract", input: "Approved file", op: "Put the contract into MinIO object storage.", output: "Object in bucket ‘contracts’", state: { status: "stored" }, route: "→ pdf_parser", fn: "store_contract_in_minio()" },
    { title: "Parse PDF", input: "Stored contract", op: "Extract contract text with pypdf.", output: "contract_text", state: { contract_text: "…extracted text…" }, route: "→ compliance_analysis_agent", fn: "pdf_parser(state)  [LangGraph node]" },
    { title: "Retrieve policies", input: "Contract context", op: "Load applicable policies from the ChromaDB policy store.", output: "Applicable policies", state: { status: "policies_loaded" }, route: "→ compliance_analysis_agent", fn: "get_policy_store()" },
    { title: "Analyze compliance", input: "contract_text + policies", op: "LLM labels each policy: compliant / non_compliant / missing / ambiguous / not_applicable.", output: "policy_results", state: { policy_results: [{ policy_id: "DATA-01", status: "non_compliant" }], tokens_in: 4120, tokens_out: 380, cost_usd: 0.0027 }, route: "→ reviewer_evaluator", fn: "compliance_analysis_agent(state)  [node]" },
    { title: "Review findings", input: "policy_results", op: "Score finding quality and give feedback.", output: "quality_score, review_feedback", state: { quality_score: 6, review_feedback: "add evidence for DATA-01" }, route: "→ review_gate", fn: "reviewer_evaluator(state)  [node]" },
    { title: "Review gate (retry?)", input: "quality_score, retry_count", op: "If quality_score < 7 and retry_count < 2, re-analyse; else continue.", output: "Routing decision", state: { retry_count: 1, status: "retry" }, route: "↺ compliance_analysis_agent (score 6 < 7)", fn: "review_gate(state)  [conditional edge]" },
    { title: "Re-analyze (loop)", input: "Feedback + policies", op: "Second analysis pass; reviewer now passes the threshold.", output: "Improved policy_results", state: { quality_score: 8, policy_results: [{ policy_id: "DATA-01", status: "non_compliant", risk_level: "high" }] }, route: "→ generate_report (8 ≥ 7)", fn: "compliance_analysis_agent → reviewer_evaluator" },
    { title: "Verdict & report", input: "Final policy_results", op: "Determine the overall verdict and write the report file.", output: "contract_verdict, report_path", state: { contract_verdict: { overall: "human_review_required", human_review_required: true }, report_path: "reports/run_a1b2c3.json" }, route: "→ audit entry", fn: "determine_contract_verdict() · generate_report(state)" },
    { title: "Persist audit + metrics", input: "Full AuditState", op: "Write the audit entry to PostgreSQL and record Prometheus metrics.", output: "Audit trail + /metrics", state: { status: "complete" }, route: "END", fn: "write_audit_entry() · audits_total / latency / cost" },
  ],

  /* Initial AuditState (TypedDict) — real field names from the code. */
  workflowInitial: {
    run_id: null,
    contract_file: null,
    contract_text: null,
    policy_results: [],
    contract_verdict: null,
    report_path: null,
    quality_score: null,
    review_feedback: null,
    retry_count: 0,
    tokens_in: 0,
    tokens_out: 0,
    cost_usd: 0.0,
    status: "new",
  },

  /* Output — ACTUAL recorded run 0d869013f23f (23 Jul 2026, MOCK demo mode).
     Numbers taken from the app UI + terminal log of that run. */
  output: {
    runId: "0d869013f23f",
    contract: "contract_human_review.pdf",
    decision: "Human Review Required",
    compliancePct: 91,
    policiesChecked: 38,
    compliant: 31,
    nonCompliant: 0,
    attention: 7,          // "need attention"
    humanReview: 7,
    criticalRisk: 0,
    reviewScore: 9,
    retryCount: 1,
    costUsd: 0.009555,
    summaryText: "No outright failures, but 7 clauses need interpretation before this contract can be approved.",
    // Real finding shown by the app for this run (DATA-001, ambiguous).
    finding: {
      policyId: "DATA-001",
      policy: "Identification of Controller and Processor roles",
      status: "Ambiguous",
      statusClass: "b-amb",
      risk: "Medium",
      riskClass: "b-med",
      reason: "The relevant clause is present but unclear: role wording is used inconsistently across the contract or its annexes.",
      recommendation: "State each party's role expressly and align it with who actually determines the purpose and manner of Processing.",
      note: "Privacy specialist review recommended",
    },
    // Result JSON built from verified log events of this run.
    json: {
      run_id: "0d869013f23f",
      verdict: "Human Review Required",
      blocking_count: 0,
      critical_count: 0,
      review_score: 9,
      retry_count: 1,
      cost_usd: 0.009555,
      summary: { policies_checked: 38, compliant: 31, non_compliant: 0, needs_attention: 7, human_review: 7 },
      report_path: "reports/0d869013f23f.json",
      findings: [
        { policy_id: "DATA-001", status: "ambiguous", risk_level: "medium", human_review_required: true },
      ],
    },
  },

  /* Agentic-behavior diagram — verified from capstone_contract_audit_v2.py. */
  agentic: {
    state: {
      title: "Shared State", tag: "LangGraph AuditState",
      desc: "The workflow remembers what happened between steps.",
      fields: ["contract text", "policy findings", "quality score", "reviewer feedback", "retry count", "token usage", "estimated cost", "final verdict"],
    },
    analysis: {
      title: "Compliance Analysis Agent", tag: "Specialized role",
      desc: "Evaluates the contract against the active policies and produces evidence, status, risk, reason and recommendation.",
      fields: ["reads contract text + policies", "writes policy_results"],
    },
    reviewer: {
      title: "Reviewer Agent", tag: "Specialized role",
      desc: "Reviews the quality of the findings and returns a quality score and feedback.",
      fields: ["writes quality_score", "writes review_feedback"],
    },
    gate: {
      title: "Quality Gate", tag: "Conditional routing",
      desc: "Is the quality score high enough? Yes → generate report. No → return to analysis. The workflow chooses the next step based on the result.",
      fields: ["score ≥ QUALITY_THRESHOLD → report", "score below → retry", "bounded by MAX_RETRIES"],
    },
    retry: {
      title: "Retry Analysis", tag: "Revision loop",
      desc: "The reviewer feedback is included in the next analysis attempt. The loop is bounded by MAX_RETRIES.",
      fields: ["feedback re-fed to analysis", "retry_count += 1"],
    },
    report: {
      title: "Generate Report", tag: "Terminal step",
      desc: "Once quality is high enough, the verdict and report are produced and persisted.",
      fields: ["writes contract_verdict", "writes report_path"],
    },
  },
  /* Vertical flow order + the branch/retry edges. */
  agenticFlow: ["state", "analysis", "reviewer", "gate"],
  agenticEdges: [
    { from: "state", to: "analysis" },
    { from: "analysis", to: "reviewer" },
    { from: "reviewer", to: "gate" },
    { from: "gate", to: "retry", branch: true },
    { from: "gate", to: "report", branch: true },
    { from: "retry", to: "analysis", retry: true },
  ],

  sections: ["01 · OVERVIEW", "02 · THE PROBLEM", "03 · AGENTIC BEHAVIOR", "04 · ARCHITECTURE", "05 · WORKFLOW", "06 · OUTPUT", "07 · THANK YOU"],
};

/* ========================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function colorJSON(obj) {
  return esc(JSON.stringify(obj, null, 2)).replace(
    /(&quot;.*?&quot;)(\s*:)|(&quot;.*?&quot;)|(-?\d+\.?\d*)|\b(true|false|null)\b/g,
    (m, key, colon, str, num, bool) => {
      if (key) return `<span class="k">${key}</span>${colon}`;
      if (str) return `<span class="s">${str}</span>`;
      if (num) return `<span class="n">${num}</span>`;
      return `<span class="b">${bool}</span>`;
    }
  );
}

/* ========================= Navigation ========================= */
const slides = $$(".slide");
let current = 0;

function goTo(i) {
  i = Math.max(0, Math.min(slides.length - 1, i));
  slides.forEach((s, j) => {
    s.classList.toggle("active", j === i);
    s.classList.toggle("from-right", j > i);
  });
  current = i;
  $("#footSection").textContent = DATA.sections[i];
  $("#footCounter").textContent = `${i + 1} / ${slides.length}`;
  $$(".ndot").forEach((d, j) => d.classList.toggle("is-active", j === i));
  if (slides[i].id === "s-arch") requestAnimationFrame(drawEdges);
  if (slides[i].id === "s-agentic") requestAnimationFrame(drawAgEdges);
}

function buildDots() {
  const wrap = $("#dots");
  slides.forEach((s, i) => {
    const b = document.createElement("button");
    b.className = "ndot";
    b.setAttribute("aria-label", `Go to ${DATA.sections[i]}`);
    b.addEventListener("click", () => goTo(i));
    wrap.appendChild(b);
  });
}

function toggleFull() {
  const d = document, el = d.documentElement;
  if (d.fullscreenElement || d.webkitFullscreenElement) {
    (d.exitFullscreen || d.webkitExitFullscreen).call(d);
  } else {
    const req = el.requestFullscreen || el.webkitRequestFullscreen;
    if (req) { const p = req.call(el); if (p && p.catch) p.catch(() => {}); }
  }
}

function initNav() {
  buildDots();
  slides.forEach((s, i) => s.classList.toggle("from-right", i > current));
  $("#btnNext").addEventListener("click", () => goTo(current + 1));
  $("#btnPrev").addEventListener("click", () => goTo(current - 1));
  $("#btnHome").addEventListener("click", () => goTo(0));
  $("#btnFull").addEventListener("click", toggleFull);

  document.addEventListener("keydown", (e) => {
    if (e.target instanceof Element && e.target.matches("input, textarea")) return;
    switch (e.key) {
      case "ArrowRight": case " ": e.preventDefault(); goTo(current + 1); break;
      case "ArrowLeft": e.preventDefault(); goTo(current - 1); break;
      case "Home": e.preventDefault(); goTo(0); break;
      case "End": e.preventDefault(); goTo(slides.length - 1); break;
      case "f": case "F": toggleFull(); break;
      // Escape exiting fullscreen is handled natively by the browser.
    }
  });
  goTo(0);
}

/* ========================= Architecture ========================= */
let flowTimer = null;

function initArch() {
  const arch = $("#arch");
  $$(".node", arch).forEach((el) => {
    const id = el.dataset.id;
    el.addEventListener("mouseenter", () => highlight(id, true));
    el.addEventListener("mouseleave", () => { if (!flowTimer) highlight(id, false); });
    el.addEventListener("focus", () => highlight(id, true));
    el.addEventListener("blur", () => { if (!flowTimer) highlight(id, false); });
    el.addEventListener("click", () => selectNode(id));
  });
  $("#panelClose").addEventListener("click", closePanel);
  $("#btnPlay").addEventListener("click", playFlow);
  $("#btnReset").addEventListener("click", resetFlow);
  window.addEventListener("resize", () => { if (slides[current].id === "s-arch") requestAnimationFrame(drawEdges); });
}

function nodeEl(id) { return $(`.node[data-id="${id}"]`); }

/* Connectors: sequential flow + retry + data-layer verticals. */
function edgeList() {
  const seq = [];
  const f = DATA.archFlow;
  for (let i = 0; i < f.length - 1; i++) seq.push({ from: f[i], to: f[i + 1] });
  return seq.concat([
    { from: "reviewer", to: "analysis", retry: true },
    { from: "minio", to: "analysis", up: true },
    { from: "chromadb", to: "analysis", up: true },
    { from: "postgres", to: "verdict", up: true },
    { from: "prometheus", to: "chromadb", up: true },
  ]);
}

function drawEdges() {
  const svg = $("#archEdges"), arch = $("#arch");
  if (!svg || !arch) return;
  const R = arch.getBoundingClientRect();
  if (R.width === 0) return;
  svg.setAttribute("viewBox", `0 0 ${R.width} ${R.height}`);
  svg.innerHTML = `<defs><marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" class="arch-arrow"/></marker></defs>`;

  edgeList().forEach((e) => {
    const A = nodeEl(e.from).getBoundingClientRect();
    const B = nodeEl(e.to).getBoundingClientRect();
    const ax = A.left + A.width / 2 - R.left, bx = B.left + B.width / 2 - R.left;
    const aTop = A.top - R.top, aBot = A.bottom - R.top;
    const bTop = B.top - R.top, bBot = B.bottom - R.top;
    let d;
    if (e.retry) {
      // Reviewer (right) curves back to Analysis (centre), below the row.
      const y = Math.max(aBot, bBot) + 14;
      d = `M ${ax} ${aBot} C ${ax} ${y}, ${bx} ${y}, ${bx} ${bBot}`;
    } else if (e.up) {
      // Data layer flows upward into the orchestrator node.
      const midY = (aTop + bBot) / 2;
      d = `M ${ax} ${aTop} C ${ax} ${midY}, ${bx} ${midY}, ${bx} ${bBot}`;
    } else {
      const sameRow = Math.abs((aTop + aBot) / 2 - (bTop + bBot) / 2) < A.height;
      if (sameRow) {
        const goR = bx > ax;
        const sx = (goR ? A.right : A.left) - R.left, ex = (goR ? B.left : B.right) - R.left;
        const my = (aTop + aBot) / 2, ny = (bTop + bBot) / 2, mx = (sx + ex) / 2;
        d = `M ${sx} ${my} C ${mx} ${my}, ${mx} ${ny}, ${ex} ${ny}`;
      } else {
        const midY = (aBot + bTop) / 2;
        d = `M ${ax} ${aBot} C ${ax} ${midY}, ${bx} ${midY}, ${bx} ${bTop}`;
      }
    }
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d);
    p.setAttribute("class", "arch-edge" + (e.retry ? " retry" : ""));
    p.setAttribute("marker-end", "url(#ah)");
    p.dataset.from = e.from; p.dataset.to = e.to;
    svg.appendChild(p);
  });
}

function highlight(id, on) {
  const arch = $("#arch");
  arch.classList.toggle("has-focus", on);
  $$(".node").forEach((n) => n.classList.remove("lit"));
  $$(".arch-edge").forEach((e) => e.classList.remove("lit"));
  if (!on) return;
  nodeEl(id).classList.add("lit");
  $$(".arch-edge").forEach((e) => {
    if (e.dataset.from === id || e.dataset.to === id) {
      e.classList.add("lit");
      nodeEl(e.dataset.from).classList.add("lit");
      nodeEl(e.dataset.to).classList.add("lit");
    }
  });
}

function selectNode(id) {
  const n = DATA.arch[id];
  $$(".node").forEach((el) => el.classList.toggle("is-selected", el.dataset.id === id));
  $("#panelBody").innerHTML = `
    <h3>${esc(n.title)}</h3>
    <span class="tag">${esc(n.type)}</span>
    <dl>
      <div><dt>Purpose</dt><dd>${esc(n.purpose)}</dd></div>
      <div><dt>Input</dt><dd>${esc(n.input)}</dd></div>
      <div><dt>Output</dt><dd>${esc(n.output)}</dd></div>
      <div><dt>Repository file</dt><dd class="repo">${esc(n.repo)}</dd></div>
      <div><dt>Technology</dt><dd class="${n.tech.startsWith("Planned") ? "planned" : ""}">${esc(n.tech)}</dd></div>
    </dl>`;
  $("#archPanel").hidden = false;
}

function closePanel() {
  $("#archPanel").hidden = true;
  $$(".node").forEach((el) => el.classList.remove("is-selected"));
}

function playFlow() {
  resetFlow();
  const btn = $("#btnPlay"); btn.disabled = true;
  const f = DATA.archFlow;
  let i = 0;
  flowTimer = setInterval(() => {
    if (i >= f.length) {
      clearInterval(flowTimer); flowTimer = null; btn.disabled = false;
      $("#retryLabel").classList.add("lit");
      const rt = $$(".arch-edge").find((e) => e.classList.contains("retry"));
      if (rt) rt.classList.add("flow-on");
      return;
    }
    if (i > 0) {
      const edge = $$(".arch-edge").find((e) => e.dataset.from === f[i - 1] && e.dataset.to === f[i]);
      if (edge) edge.classList.add("flow-on");
    }
    nodeEl(f[i]).classList.add("flow-on");
    i++;
  }, 600);
}

function resetFlow() {
  if (flowTimer) { clearInterval(flowTimer); flowTimer = null; }
  $("#btnPlay").disabled = false;
  $("#retryLabel").classList.remove("lit");
  $$(".node").forEach((n) => n.classList.remove("flow-on", "lit", "is-selected"));
  $$(".arch-edge").forEach((e) => e.classList.remove("flow-on", "lit"));
  $("#arch").classList.remove("has-focus");
  closePanel();
}

/* ========================= Agentic behavior ========================= */
let agTimer = null;

function agNode(id) { return document.querySelector(`.agnode[data-id="${id}"]`); }

function initAgentic() {
  const dia = $("#agDiagram");
  if (!dia) return;
  $$(".agnode", dia).forEach((el) => {
    const id = el.dataset.id;
    el.addEventListener("mouseenter", () => agHighlight(id, true));
    el.addEventListener("mouseleave", () => { if (!agTimer) agHighlight(id, false); });
    el.addEventListener("focus", () => agHighlight(id, true));
    el.addEventListener("blur", () => { if (!agTimer) agHighlight(id, false); });
    el.addEventListener("click", () => agSelect(id));
  });
  $("#btnAgentPlay").addEventListener("click", agPlay);
  $("#btnAgentReset").addEventListener("click", agReset);
  window.addEventListener("resize", () => { if (slides[current].id === "s-agentic") requestAnimationFrame(drawAgEdges); });
  agPanelDefault();
  drawAgEdges();
}

function drawAgEdges() {
  const svg = $("#agEdges"), dia = $("#agDiagram");
  if (!svg || !dia) return;
  const R = dia.getBoundingClientRect();
  if (R.width === 0) return;
  svg.setAttribute("viewBox", `0 0 ${R.width} ${R.height}`);
  svg.innerHTML = `<defs>
    <marker id="agh" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" class="ag-arrow"/></marker>
    <marker id="aghr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" class="ag-arrow-retry"/></marker>
  </defs>`;

  DATA.agenticEdges.forEach((e) => {
    const A = agNode(e.from).getBoundingClientRect();
    const B = agNode(e.to).getBoundingClientRect();
    const ax = A.left + A.width / 2 - R.left, bx = B.left + B.width / 2 - R.left;
    const aTop = A.top - R.top, aBot = A.bottom - R.top;
    const bTop = B.top - R.top, bBot = B.bottom - R.top;
    let d;
    if (e.retry) {
      // Retry Analysis → Compliance Analysis Agent: curve up the left side.
      const leftX = Math.min(A.left, B.left) - R.left - 26;
      d = `M ${A.left - R.left} ${(aTop + aBot) / 2} C ${leftX} ${(aTop + aBot) / 2}, ${leftX} ${(bTop + bBot) / 2}, ${B.left - R.left} ${(bTop + bBot) / 2}`;
    } else {
      const midY = (aBot + bTop) / 2;
      d = `M ${ax} ${aBot} C ${ax} ${midY}, ${bx} ${midY}, ${bx} ${bTop}`;
    }
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d);
    p.setAttribute("class", "ag-edge" + (e.retry ? " retry" : ""));
    p.setAttribute("marker-end", e.retry ? "url(#aghr)" : "url(#agh)");
    p.dataset.from = e.from; p.dataset.to = e.to;
    svg.appendChild(p);
  });
}

function agHighlight(id, on) {
  const dia = $("#agDiagram");
  dia.classList.toggle("has-focus", on);
  $$(".agnode").forEach((n) => n.classList.remove("lit"));
  $$(".ag-edge").forEach((e) => e.classList.remove("lit"));
  if (!on) return;
  agNode(id).classList.add("lit");
  $$(".ag-edge").forEach((e) => {
    if (e.dataset.from === id || e.dataset.to === id) {
      e.classList.add("lit");
      agNode(e.dataset.from).classList.add("lit");
      agNode(e.dataset.to).classList.add("lit");
    }
  });
}

function agPanelDefault() {
  $("#agPanelBody").innerHTML = `
    <h3>State · Roles · Routing · Loop</h3>
    <p>This is more than <span class="muted">PDF → LLM → Report</span>. The graph keeps state, splits work across roles, and routes itself.</p>
    <p class="muted">Click any step in the flow to see what it does. Press <strong>Play Agent Loop</strong> to watch a low-quality result get sent back for revision.</p>`;
}

function agSelect(id) {
  const n = DATA.agentic[id];
  $$(".agnode").forEach((el) => el.classList.toggle("is-selected", el.dataset.id === id));
  $("#agPanelBody").innerHTML = `
    <h3>${esc(n.title)}</h3>
    <span class="tag">${esc(n.tag)}</span>
    <p>${esc(n.desc)}</p>
    <ul>${n.fields.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`;
}

function agPlay() {
  agReset();
  const btn = $("#btnAgentPlay"); btn.disabled = true;
  // Sequence includes a failed first pass that loops back via retry.
  const seq = [
    { node: "state" },
    { node: "analysis", edge: ["state", "analysis"] },
    { node: "reviewer", edge: ["analysis", "reviewer"] },
    { node: "gate", edge: ["reviewer", "gate"] },
    { node: "retry", edge: ["gate", "retry"] },
    { node: "analysis", edge: ["retry", "analysis"] },
    { node: "reviewer", edge: ["analysis", "reviewer"] },
    { node: "gate", edge: ["reviewer", "gate"] },
    { node: "report", edge: ["gate", "report"] },
  ];
  let i = 0;
  agTimer = setInterval(() => {
    if (i >= seq.length) { clearInterval(agTimer); agTimer = null; btn.disabled = false; return; }
    const s = seq[i];
    if (s.edge) {
      const ed = $$(".ag-edge").find((e) => e.dataset.from === s.edge[0] && e.dataset.to === s.edge[1]);
      if (ed) ed.classList.add("flow-on");
    }
    agNode(s.node).classList.add("flow-on");
    i++;
  }, 620);
}

function agReset() {
  if (agTimer) { clearInterval(agTimer); agTimer = null; }
  $("#btnAgentPlay").disabled = false;
  $$(".agnode").forEach((n) => n.classList.remove("flow-on", "lit", "is-selected"));
  $$(".ag-edge").forEach((e) => e.classList.remove("flow-on", "lit"));
  $("#agDiagram").classList.remove("has-focus");
  agPanelDefault();
}

/* ========================= Workflow ========================= */
let step = 0, wfTimer = null, prevJSON = "";
let liveState = structuredClone(DATA.workflowInitial);

function initWorkflow() {
  const stepper = $("#stepper");
  DATA.workflow.forEach((s, i) => {
    const b = document.createElement("button");
    b.className = "step"; b.setAttribute("role", "tab");
    b.innerHTML = `<span class="step__n">${i + 1}</span>${esc(s.title)}`;
    b.addEventListener("click", () => setStep(i));
    stepper.appendChild(b);
  });
  $("#wfPrev").addEventListener("click", () => setStep(step - 1));
  $("#wfNext").addEventListener("click", () => setStep(step + 1));
  $("#btnRunWf").addEventListener("click", runWf);
  setStep(0);
}

function stateUpTo(idx) {
  const st = structuredClone(DATA.workflowInitial);
  for (let i = 0; i <= idx; i++) Object.assign(st, structuredClone(DATA.workflow[i].state));
  return st;
}

function setStep(i) {
  i = Math.max(0, Math.min(DATA.workflow.length - 1, i));
  step = i;
  $$(".step").forEach((el, j) => {
    el.classList.toggle("is-active", j === i);
    el.classList.toggle("is-done", j < i);
  });
  $$(".step")[i].scrollIntoView({ inline: "center", block: "nearest", behavior: "smooth" });

  const s = DATA.workflow[i];
  $("#wfDetail").innerHTML = `
    <h3>${i + 1}. ${esc(s.title)}</h3>
    <div class="io">
      <b>Input</b><p>${esc(s.input)}</p>
      <b>Operation</b><p>${esc(s.op)}</p>
      <b>Output</b><p>${esc(s.output)}</p>
      <b>Route</b><p class="route">${esc(s.route)}</p>
    </div>
    <span class="fn-tag"><span class="c"># node/function (placeholder)</span>  ${esc(s.fn)}</span>`;
  $("#wfCount").textContent = `Step ${i + 1} / ${DATA.workflow.length}`;
  $("#wfPrev").disabled = i === 0;
  $("#wfNext").disabled = i === DATA.workflow.length - 1;

  liveState = stateUpTo(i);
  renderState();
}

function renderState() {
  const json = JSON.stringify(liveState, null, 2);
  let html = colorJSON(liveState);
  if (prevJSON && prevJSON !== json) {
    const p = prevJSON.split("\n"), n = json.split("\n"), h = html.split("\n");
    html = h.map((line, idx) => (n[idx] !== p[idx] ? `<span class="state-changed">${line}</span>` : line)).join("\n");
  }
  $("#wfState").innerHTML = html;
  prevJSON = json;
}

function runWf() {
  if (wfTimer) { clearInterval(wfTimer); wfTimer = null; }
  const btn = $("#btnRunWf"); btn.disabled = true;
  prevJSON = ""; setStep(0);
  let i = 1;
  wfTimer = setInterval(() => {
    if (i >= DATA.workflow.length) { clearInterval(wfTimer); wfTimer = null; btn.disabled = false; return; }
    setStep(i); i++;
  }, 1000);
}

/* ========================= Output ========================= */
function ringSVG(pct) {
  // pct may be null → show a neutral placeholder ring.
  const r = 34, c = 2 * Math.PI * r;
  const known = typeof pct === "number";
  const off = known ? c * (1 - pct / 100) : c;
  const label = known ? `${pct}%` : "n/a";
  return `<svg class="ring" viewBox="0 0 80 80">
    <circle cx="40" cy="40" r="${r}" fill="none" stroke="rgba(148,160,218,.2)" stroke-width="8"/>
    <circle cx="40" cy="40" r="${r}" fill="none" stroke="${known ? "#33cc99" : "#94a0da"}" stroke-width="8"
      stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 40 40)"/>
    <text x="40" y="45" text-anchor="middle" fill="#f4f6fd" font-size="15" font-family="Inter, sans-serif" font-weight="700">${label}</text>
  </svg>`;
}

function initOutput() {
  const o = DATA.output;
  $("#reportSummary").innerHTML = `
    <div class="rs-top">
      <span class="rs-contract">${esc(o.contract)}</span>
      <span class="rs-decision" style="color:var(--peri)">${esc(o.decision)}</span>
    </div>
    <div class="rs-ring">
      ${ringSVG(o.compliancePct)}
      <div class="rs-side">
        <span class="rs-checked"><b>${o.policiesChecked}</b> policies checked</span>
        <span class="rs-run">run ${esc(o.runId)}</span>
        <span class="rs-run">cost $${o.costUsd.toFixed(6)} · score ${o.reviewScore}/10 · ${o.retryCount} retry</span>
      </div>
    </div>
    <div class="rs-metrics">
      <div class="rs-metric"><b style="color:var(--green)">${o.compliant}</b><span>compliant</span></div>
      <div class="rs-metric"><b style="color:var(--red)">${o.nonCompliant}</b><span>non-compliant</span></div>
      <div class="rs-metric"><b style="color:var(--orange)">${o.attention}</b><span>needs attention</span></div>
      <div class="rs-metric"><b style="color:var(--peri)">${o.humanReview}</b><span>human review</span></div>
    </div>
    <div class="hitl"><span class="pulse"></span>${esc(o.summaryText)}</div>`;

  const f = o.finding;
  $("#view-report").innerHTML = `
    <div class="card finding">
      <div class="finding__head">
        <h4>${esc(f.policyId)} — ${esc(f.policy)}</h4>
        <span class="badge ${f.statusClass}">${esc(f.status)}</span>
        <span class="badge ${f.riskClass}">Risk: ${esc(f.risk)}</span>
      </div>
      <div class="frow"><b>Reason</b><p>${esc(f.reason)}</p></div>
      <div class="frow"><b>Recommendation</b><p>${esc(f.recommendation)}</p></div>
      <div class="fmeta">
        <span class="chip">Status: ambiguous</span>
        <span class="chip">human_review_required: true</span>
        <span class="badge b-review">${esc(f.note)}</span>
      </div>
      <p class="finding-foot">One of ${o.attention} findings flagged for attention in this run · overall verdict: <strong>${esc(o.decision)}</strong>.</p>
    </div>`;

  $("#view-json").innerHTML = `
    <div class="card json-card">
      <div class="code-head"><span class="d red"></span><span class="d gold"></span><span class="d green"></span><span class="code-title">reports/${esc(o.runId)}.json — actual run</span></div>
      <pre class="code">${colorJSON(o.json)}</pre>
    </div>`;

  $$(".seg").forEach((seg) => seg.addEventListener("click", () => {
    $$(".seg").forEach((s) => s.classList.remove("is-active"));
    seg.classList.add("is-active");
    $$(".out-view").forEach((v) => v.classList.remove("is-active"));
    $(`#view-${seg.dataset.view}`).classList.add("is-active");
  }));
}

/* ========================= Boot ========================= */
document.addEventListener("DOMContentLoaded", () => {
  initAgentic();
  initArch();
  initWorkflow();
  initOutput();
  initNav();
  requestAnimationFrame(drawEdges);
});
