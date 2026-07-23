# CAPSTONE AAASE 
# Data Processing Contract Auditor 

An AI agent that reviews data-processing contracts against an initial SDAIA-derived regulatory policy baseline and optional company-specific policies, then produces traceable compliance findings with evidence, risk level, recommendations, and human-review routing.

> **Disclaimer:** This project supports contract review and does not replace professional legal or privacy assessment.

---

## Team

| Member | GitHub | LinkedIn |
|---|---|---|
| **[Muneera AlSaeed]** | [@mneerh](https://github.com/mneerh) | [LinkedIn](https://www.linkedin.com/in/username/) |
| **[Shaikha AlKhathlan]** | [@shiakah27](https://github.com/shiakah27) | [LinkedIn](https://www.linkedin.com/in/username/) |

---

## Problem Statement

Organizations that work with external vendors often need to review data-processing agreements, cloud contracts, data-sharing agreements, and other contracts that involve personal data.

This review is usually:

- Time-consuming and repetitive.
- Dependent on manual legal or privacy review.
- Difficult to standardize across different reviewers.
- Prone to missing unclear, absent, or high-risk clauses.
- More complex when a company has internal requirements in addition to the regulatory baseline.

We chose this problem because data-processing contracts contain recurring privacy requirements that can be represented as structured policies and checked through an evidence-based agent workflow.

---

## How the Agent Solves It

### Input

The system receives:

- A contract file, such as a PDF.
- A selected contract type.
- A regulatory policy set derived from official SDAIA sources.
- Optional company-specific policy requirements.

Supported contract examples include:

- Data Processing Agreements.
- Cloud Service Agreements.
- Data Sharing Agreements.
- Cross-Border Data Transfer Agreements.
- Employee Data Vendor Agreements.
- Marketing Data Processing Agreements.

### Agent Workflow

1. **Validate the uploaded file**
   - Checks file type, size, readability, and basic safety constraints.

2. **Extract contract text**
   - Parses the PDF and preserves page-level evidence where available.

3. **Sanitize untrusted content**
   - Treats contract text as data, not instructions.
   - Detects suspicious prompt-injection patterns.

4. **Extract contract clauses**
   - Identifies relevant clauses such as purpose limitation, retention, deletion, breach notification, subprocessors, transfers, and data-subject rights.

5. **Load applicable policies**
   - Retrieves the relevant SDAIA-derived policies.
   - Adds company-specific policies when configured.

6. **Compare clauses against policies**
   - Evaluates whether each policy is:
     - `compliant`
     - `non_compliant`
     - `missing`
     - `ambiguous`
     - `not_applicable`

7. **Review the findings**
   - Checks that each result contains contract evidence, policy support, reasoning, and a recommendation.

8. **Route uncertain or high-risk cases**
   - Sends ambiguous, critical, or low-confidence findings to human review.

9. **Generate the final result**
   - Produces an overall compliance score, decision, detailed findings, and audit trail.

### Agentic Behavior

The agentic behavior is implemented through:

- **State:** contract text, extracted clauses, applicable policies, findings, scores, and review status are stored in a shared workflow state.
- **Conditional routing:** the graph chooses between report generation, re-analysis, or human review based on risk, confidence, and quality.
- **Multiple roles:** clause extraction, compliance analysis, and review are handled as separate responsibilities.
- **Revision loop:** low-quality findings can be sent back for another retrieval or analysis attempt.
- **Human-in-the-loop:** high-risk and ambiguous decisions are paused for manual validation.

### Output Example

```json
{
  "policy_id": "DATA-01",
  "status": "non_compliant",
  "risk_level": "high",
  "contract_evidence": "The vendor may use personal data for any business purpose.",
  "reason": "The clause permits unrestricted processing without a specific defined purpose.",
  "recommendation": "Limit processing to expressly documented purposes.",
  "human_review_required": true
}
```

---

## Architecture



### Main Components

| Layer | Components |
|---|---|


---

## Tech Stack

> Update this section to match the final implementation before submission.

| Area | Technology | Why We Chose It |
|---|---|---|

---

## Project Structure


> Modify the tree so it matches the actual repository.

---

## How to Run


## Demonstration Evidence


### Example Input

```text
gg
```

### Example Result



### Screenshots



## Reference

https://github.com/SDAIAAcademy

## Acknowledgment

Special thanks to SDAIA Academy for this opportunity, and to our instructor, Ibrahim Al-Shehri, for his guidance and support throughout the program.

---
