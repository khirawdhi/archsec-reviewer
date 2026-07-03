# RAG Assistant Security Architecture Review

## System Summary

# Example Architecture: Customer Support RAG Assistant

A customer support AI assistant accepts questions from users through a web application.

The backend API sends the user question to a retrieval layer. The retrieval layer searches a vector database containing internal support articles, refund policy documents, and troubleshooting guides.

The retrieved context is sent to an LLM inference layer. The LLM generates an answer for the user.

For some requests, an AI agent can call external tools, including:
- ticket creation API
- refund API
- customer profile lookup API

The system uses OAuth tokens for service-to-service access. Logs are stored in cloud object storage.

## Detected Components

- user
- api
- database
- vector_db
- llm
- tool
- storage
- identity
- third_party

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

### api

- Broken object-level authorization
- Unauthenticated access to sensitive endpoint
- Input tampering crosses service boundary

### vector_db

- Poisoned documents influence generated answers
- Sensitive documents retrieved without authorization
- Untrusted content treated as authoritative context

### llm

- Prompt injection overrides intended behavior
- Sensitive context leaks through generated output
- Model output triggers unsafe downstream action

### tool

- Agent executes unauthorized action
- Tool call uses excessive privileges
- External action is performed without validation

### identity

- Token replay across services
- Over-broad service identity permissions
- Weak trust model between services

## Recommended Controls

### user

- Input validation
- Rate limiting
- Authentication
- Abuse monitoring

### api

- Authorization checks
- Schema validation
- API gateway policy
- Audit logging

### database

- Least privilege access
- Encryption at rest
- Query authorization
- Backup protection

### vector_db

- Source allowlists
- Document provenance
- Retrieval-time authorization
- Index segregation

### llm

- Prompt isolation
- System prompt protection
- Context minimization
- Output policy enforcement

### tool

- Tool allowlists
- Human approval for sensitive actions
- Scoped credentials
- Action validation

### storage

- Bucket policy review
- Object-level access control
- Encryption
- Public access blocking

### identity

- Short-lived tokens
- mTLS/OIDC validation
- Audience restriction
- Key rotation

### third_party

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
