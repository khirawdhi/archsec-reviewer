# Security Architecture Review

## System Summary

# Example Architecture: Customer Support RAG Assistant

## Overview

The Customer Support RAG Assistant helps support engineers answer customer questions using Retrieval-Augmented Generation (RAG).

Users interact with the assistant through a web application. The backend retrieves relevant documents from an internal knowledge base before sending the user prompt and retrieved context to a Large Language Model (LLM).

For selected requests, the AI Agent can invoke backend business APIs to create support tickets, process refunds, or retrieve customer profile information.

---

## Components

- User
- Web Application
- Backend API
- OAuth Identity Provider
- Retrieval Service
- Vector Database
-

## Detected Components

- User
- Api
- Database
- Vector Db
- Llm
- Tool
- Storage
- Identity
- Third Party

## Trust Boundaries

- User / Client → API or application boundary
- Application service → Database boundary
- Application service → Retrieval / vector database boundary
- Retrieved context → LLM prompt construction boundary
- LLM reasoning → Tool / action execution boundary
- Internal service → External vendor / third-party boundary
- Identity provider / token issuer → Service authorization boundary

## Attack Paths

- Malicious user input → retrieval query manipulation → unsafe context → insecure LLM response
- Poisoned knowledge base document → retrieved as trusted context → manipulated model output
- Prompt injection → unauthorized tool selection → sensitive action execution
- Stolen or over-scoped token → service access → lateral movement across APIs

## Threat Scenarios

### Api

- Broken object-level authorization
- Unauthenticated access to sensitive endpoint
- Input tampering crosses service boundary

### Vector Db

- Poisoned documents influence generated answers
- Sensitive documents retrieved without authorization
- Untrusted content treated as authoritative context

### Llm

- Prompt injection overrides intended behavior
- Sensitive context leaks through generated output
- Model output triggers unsafe downstream action

### Tool

- Agent executes unauthorized action
- Tool call uses excessive privileges
- External action is performed without validation

### Identity

- Token replay across services
- Over-broad service identity permissions
- Weak trust model between services


## Recommended Controls

### User

- Input validation
- Rate limiting
- Authentication
- Abuse monitoring

### Api

- Authorization checks
- Schema validation
- API gateway policy
- Audit logging

### Database

- Least privilege access
- Encryption at rest
- Query authorization
- Backup protection

### Vector Db

- Source allowlists
- Document provenance
- Retrieval-time authorization
- Index segregation

### Llm

- Prompt isolation
- System prompt protection
- Context minimization
- Output policy enforcement

### Tool

- Tool allowlists
- Human approval for sensitive actions
- Scoped credentials
- Action validation

### Storage

- Bucket policy review
- Object-level access control
- Encryption
- Public access blocking

### Identity

- Short-lived tokens
- mTLS/OIDC validation
- Audience restriction
- Key rotation

### Third Party

- Vendor risk review
- Webhook signature validation
- Network egress controls
- Contractual controls


## Validation Checklist

- [ ] Confirm every trust boundary has an owner and an enforcement point.
- [ ] Verify authorization is enforced server-side, not only in the UI.
- [ ] Confirm logs capture security-relevant decisions and denied actions.
- [ ] Test whether untrusted documents can be retrieved for sensitive queries.
- [ ] Verify source metadata is preserved from ingestion to retrieval.
- [ ] Confirm retrieval results are filtered by user authorization.
- [ ] Test prompt injection attempts against system and developer instructions.
- [ ] Verify sensitive context is not leaked in model output.
- [ ] Confirm output filtering is applied before returning responses.
- [ ] Verify tool calls require explicit authorization.
- [ ] Test whether the model can trigger high-risk actions without approval.
- [ ] Confirm tools use scoped credentials with least privilege.

## Final Note

> Threat model trust transitions, not just components.