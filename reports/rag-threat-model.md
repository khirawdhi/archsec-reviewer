# Security Architecture Review

**System:** Customer Support RAG Assistant

---

# Executive Summary

**Overall Risk:** 🔴 High

This architecture follows a typical Retrieval-Augmented Generation (RAG) pattern with external tool execution. The primary security risks are untrusted retrieval, prompt injection, and unauthorized tool execution.

### Top Risks

| Priority | Risk                        | Severity |
| -------- | --------------------------- | -------- |
| 1        | Prompt Injection            | Critical |
| 2        | Retrieval Data Poisoning    | High     |
| 3        | Unauthorized Tool Execution | High     |
| 4        | Over-scoped OAuth Tokens    | Medium   |
| 5        | Sensitive Data Leakage      | Medium   |

---

# System Overview

The application accepts user questions, retrieves relevant documents from a vector database, sends the retrieved context to an LLM, and allows the LLM to invoke external tools such as refund and ticket APIs.

---

# Detected Components

* User
* Web API
* Vector Database
* LLM Inference
* Tool Execution Layer
* OAuth Identity Provider
* Cloud Object Storage

---

# Critical Assets

* Customer Support Knowledge Base
* OAuth Access Tokens
* Customer Data
* Refund API
* Ticket API
* LLM Context Window
* Audit Logs

---

# Trust Boundaries

| Boundary              | Trust Transition              |
| --------------------- | ----------------------------- |
| User → API            | External → Internal           |
| API → Vector Database | Application → Data Store      |
| Vector Database → LLM | Retrieved Context → AI        |
| LLM → Tool Execution  | AI Decision → External Action |
| API → OAuth Provider  | Identity Validation           |
| API → Cloud Storage   | Internal → Persistent Storage |

---

# Attack Paths

### Attack Path 1 — Prompt Injection

User Input

↓

Prompt Injection

↓

LLM

↓

Unauthorized Tool Selection

↓

Refund API

**Risk:** Critical

---

### Attack Path 2 — Retrieval Data Poisoning

Malicious Document

↓

Knowledge Base

↓

Vector Retrieval

↓

LLM Context

↓

Unsafe Response

**Risk:** High

---

### Attack Path 3 — Token Misuse

Compromised OAuth Token

↓

API

↓

Internal Services

↓

Privilege Escalation

**Risk:** Medium

---

# STRIDE Analysis

| Component       | Threat                                         |
| --------------- | ---------------------------------------------- |
| API             | Spoofing, Tampering                            |
| Vector Database | Tampering, Information Disclosure              |
| LLM             | Information Disclosure, Elevation of Privilege |
| Tool Execution  | Elevation of Privilege                         |
| OAuth           | Spoofing, Elevation of Privilege               |

---

# Recommended Controls

## API

* Enforce authentication and authorization
* Validate all user input
* Apply rate limiting
* Enable structured audit logging

## Vector Database

* Verify document provenance
* Maintain trusted document allowlists
* Enforce retrieval-time authorization
* Separate trusted and untrusted indexes

## LLM

* Isolate system prompts
* Minimize supplied context
* Apply output filtering
* Detect prompt injection attempts

## Tool Execution

* Require explicit authorization
* Restrict available tools
* Use least-privilege credentials
* Require human approval for sensitive actions

## Identity

* Short-lived OAuth tokens
* Audience validation
* Token rotation
* Mutual TLS for service-to-service communication where appropriate

---

# Validation Checklist

* [ ] Attempt prompt injection against the system prompt.
* [ ] Verify unauthorized documents cannot be retrieved.
* [ ] Confirm retrieval respects user authorization.
* [ ] Verify output filtering blocks sensitive information.
* [ ] Confirm tool execution requires authorization.
* [ ] Verify OAuth tokens cannot be reused across services.
* [ ] Review audit logs for denied requests and security events.

---

# Architecture Observations

### Positive Findings

* OAuth-based service authentication detected.
* Retrieval layer separated from the application.
* External tool execution isolated.
* Audit logging present.

### Areas for Improvement

* Document provenance is not verified.
* Retrieval authorization is not explicitly defined.
* Tool execution approval workflow is missing.
* Output filtering is not evident.
* Token scope should be reviewed.

---

# Remediation Roadmap

### High Priority

1. Implement retrieval-time authorization.
2. Add document provenance verification.
3. Restrict tool execution with allowlists and approval.
4. Deploy prompt injection detection.
5. Apply output filtering before responding to users.

### Medium Priority

1. Reduce OAuth token scope.
2. Strengthen audit logging.
3. Review cloud storage permissions.

---

# Final Assessment

The architecture demonstrates a sound high-level design but contains several high-impact trust boundaries that require additional controls before deployment. The most critical improvements are securing the retrieval pipeline, constraining tool execution, and enforcing authorization across AI interactions.
