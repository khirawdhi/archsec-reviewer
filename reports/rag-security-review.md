# Security Architecture Review: Customer Support RAG Assistant

## Executive Summary

ArchSec Reviewer identified **2 security findings** and **7 attack paths** from the declared architecture.

## Security Objectives

- Prevent prompt and retrieval-based instruction injection.
- Prevent unauthorized refund execution.
- Enforce document-level retrieval authorization.
- Protect customer records from unauthorized disclosure.
- Preserve audit-log integrity.

## Declared Assumptions

- OAuth tokens are validated for every backend request.
- Only approved documents are indexed into the vector database.
- Tool execution is mediated by backend authorization.
- Audit logs are immutable after creation.

## Architecture Overview

### Trust Zones

| ID | Name | Trust level | Owner |
|---|---|---|---|
| internet | Internet | untrusted | Not declared |
| edge | Application Edge | internal | Platform Team |
| application | Application Services | internal | Support Engineering |
| data | Data Services | privileged | Data Platform |
| external_ai | External AI Provider | external | AI Platform Team |
| privileged | Privileged Business Operations | privileged | Payments Team |

### Components

| ID | Name | Type | Trust zone |
|---|---|---|---|
| customer | Customer | user | internet |
| web_app | Support Web Application | web_application | edge |
| backend_api | Backend API | api | application |
| identity_provider | OAuth Identity Provider | identity_provider | external_ai |
| vector_db | Support Vector Database | vector_database | data |
| llm | LLM Inference Service | llm | external_ai |
| refund_tool | Refund Tool | tool | privileged |
| customer_db | Customer Database | database | data |
| audit_storage | Audit Storage | storage | data |

### Assets

| ID | Name | Classification | Owner |
|---|---|---|---|
| customer_records | Customer Records | restricted | customer_db |
| support_knowledge | Support Knowledge Base | confidential | vector_db |
| refund_capability | Refund Capability | restricted | refund_tool |
| audit_logs | Security Audit Logs | confidential | audit_storage |

### Data Flows

| ID | Source | Destination | Protocol | Authenticated | Encrypted |
|---|---|---|---|---|---|
| customer_to_web | customer | web_app | HTTPS | Yes | Yes |
| web_to_backend | web_app | backend_api | HTTPS | Yes | Yes |
| backend_to_identity | backend_api | identity_provider | HTTPS | Yes | Yes |
| backend_to_vector | backend_api | vector_db | HTTPS | Yes | Yes |
| vector_to_llm | vector_db | llm | HTTPS | Yes | Yes |
| llm_to_refund | llm | refund_tool | HTTPS | Yes | Yes |
| backend_to_customer_db | backend_api | customer_db | TLS | Yes | Yes |
| backend_to_audit | backend_api | audit_storage | TLS | Yes | Yes |
| refund_to_audit | refund_tool | audit_storage | TLS | Yes | Yes |

## Security Findings

### [HIGH] AI-RAG-001:vector_to_llm — Retrieved content influences LLM behavior

- **Severity:** high
- **Confidence:** high
- **Category:** data_poisoning
- **Affected components:** vector_db, llm

#### Scenario

Poisoned or unauthorized retrieved content can enter the LLM context and manipulate generated output.

#### Evidence

- **data_flow / vector_to_llm:** Data flow 'vector_to_llm' connects Support Vector Database to LLM Inference Service.

#### Assumptions

- No additional assumptions.

#### Recommended Controls

- Preserve document provenance.
- Enforce retrieval-time authorization.
- Separate retrieved content from trusted instructions.

#### Validation Steps

- [ ] Test indirect prompt injection through retrieved documents.
- [ ] Verify retrieval results are filtered by user authorization.

### [HIGH] AI-TOOL-001:llm_to_refund — Model output reaches an executable tool

- **Severity:** high
- **Confidence:** high
- **Category:** unsafe_action
- **Affected components:** llm, refund_tool

#### Scenario

Manipulated model output can request a consequential tool operation without independent authorization.

#### Evidence

- **data_flow / llm_to_refund:** Data flow 'llm_to_refund' connects LLM Inference Service to Refund Tool.

#### Assumptions

- No additional assumptions.

#### Recommended Controls

- Authorize every tool action outside the model.
- Use scoped tool credentials.
- Require approval for high-impact actions.

#### Validation Steps

- [ ] Attempt unauthorized tool use through prompt injection.
- [ ] Verify the model cannot provide the acting user identity.

## Attack Paths

### AP-001

- **Entry point:** llm
- **Target:** refund_tool
- **Hop count:** 1
- **Route:** llm → refund_tool
- **Flow evidence:** llm_to_refund

#### Trust Transitions

- llm (external_ai) → refund_tool (privileged)

### AP-002

- **Entry point:** llm
- **Target:** audit_storage
- **Hop count:** 2
- **Route:** llm → refund_tool → audit_storage
- **Flow evidence:** llm_to_refund, refund_to_audit

#### Trust Transitions

- llm (external_ai) → refund_tool (privileged)
- refund_tool (privileged) → audit_storage (data)

### AP-003

- **Entry point:** customer
- **Target:** audit_storage
- **Hop count:** 3
- **Route:** customer → web_app → backend_api → audit_storage
- **Flow evidence:** customer_to_web, web_to_backend, backend_to_audit

#### Trust Transitions

- customer (internet) → web_app (edge)
- web_app (edge) → backend_api (application)
- backend_api (application) → audit_storage (data)

### AP-004

- **Entry point:** customer
- **Target:** customer_db
- **Hop count:** 3
- **Route:** customer → web_app → backend_api → customer_db
- **Flow evidence:** customer_to_web, web_to_backend, backend_to_customer_db

#### Trust Transitions

- customer (internet) → web_app (edge)
- web_app (edge) → backend_api (application)
- backend_api (application) → customer_db (data)

### AP-005

- **Entry point:** customer
- **Target:** vector_db
- **Hop count:** 3
- **Route:** customer → web_app → backend_api → vector_db
- **Flow evidence:** customer_to_web, web_to_backend, backend_to_vector

#### Trust Transitions

- customer (internet) → web_app (edge)
- web_app (edge) → backend_api (application)
- backend_api (application) → vector_db (data)

### AP-006

- **Entry point:** customer
- **Target:** refund_tool
- **Hop count:** 5
- **Route:** customer → web_app → backend_api → vector_db → llm → refund_tool
- **Flow evidence:** customer_to_web, web_to_backend, backend_to_vector, vector_to_llm, llm_to_refund

#### Trust Transitions

- customer (internet) → web_app (edge)
- web_app (edge) → backend_api (application)
- backend_api (application) → vector_db (data)
- vector_db (data) → llm (external_ai)
- llm (external_ai) → refund_tool (privileged)

### AP-007

- **Entry point:** customer
- **Target:** audit_storage
- **Hop count:** 6
- **Route:** customer → web_app → backend_api → vector_db → llm → refund_tool → audit_storage
- **Flow evidence:** customer_to_web, web_to_backend, backend_to_vector, vector_to_llm, llm_to_refund, refund_to_audit

#### Trust Transitions

- customer (internet) → web_app (edge)
- web_app (edge) → backend_api (application)
- backend_api (application) → vector_db (data)
- vector_db (data) → llm (external_ai)
- llm (external_ai) → refund_tool (privileged)
- refund_tool (privileged) → audit_storage (data)

## Review Limitations

This report is based on the components, data flows, trust zones, assets, and assumptions declared in the input. Missing architecture details may produce missing findings or lower-confidence conclusions.

