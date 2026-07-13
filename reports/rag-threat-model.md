# RAG Threat Model Example

## System Overview

A customer support assistant uses Retrieval-Augmented Generation (RAG) to answer user questions.

The application retrieves relevant documents from a Vector Database, sends the retrieved context and user prompt to an LLM, and allows an AI Agent to invoke backend APIs for approved actions such as ticket creation and refund processing.

---

## Architecture

### Components

- User
- Web Application
- Backend API
- OAuth Identity Provider
- Retrieval Service
- Vector Database
- LLM Inference Service
- AI Agent
- Ticket API
- Refund API
- Customer Profile API
- Cloud Object Storage

---

### Data Flow

1. User authenticates through the Web Application.
2. Backend API validates the OAuth access token.
3. Retrieval Service queries the Vector Database.
4. Retrieved documents are added to the prompt.
5. Prompt is sent to the LLM.
6. The AI Agent may invoke backend APIs.
7. Backend API returns the response.
8. Audit logs are written to Cloud Object Storage.

---

## Assets

- Customer profile information
- Customer support knowledge base
- OAuth access tokens
- Refund capability
- Ticket management system
- LLM context
- Audit logs

---

## Trust Boundaries

- User → Web Application
- Web Application → Backend API
- Backend API → Retrieval Service
- Retrieval Service → Vector Database
- Vector Database → LLM
- LLM → AI Agent
- AI Agent → Backend APIs
- Backend API → Cloud Storage

---

## External Dependencies

- OAuth Identity Provider
- LLM Provider
- Ticket Management Service
- Payment Service

---

## Security Assumptions

- OAuth tokens are validated for every request.
- Only trusted documents are indexed into the Vector Database.
- The LLM cannot directly access databases.
- AI actions are executed through backend APIs.
- Service-to-service communication is authenticated.
- Audit logs are immutable.

---

## Security Objectives

- Prevent prompt injection.
- Prevent retrieval data poisoning.
- Prevent unauthorized tool execution.
- Protect customer data.
- Enforce authorization for retrieved documents.
- Preserve audit log integrity.
- Apply least privilege to AI actions.