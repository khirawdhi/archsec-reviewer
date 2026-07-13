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
- LLM Inference Service
- AI Agent
- Ticket Creation API
- Refund API
- Customer Profile API
- Cloud Object Storage for audit logs

---

## Data Flow

1. A user authenticates through the Web Application.
2. The Backend API validates the user's OAuth access token.
3. The Retrieval Service searches the Vector Database for relevant support documents.
4. Retrieved documents are combined with the user's prompt.
5. The combined prompt is sent to the LLM Inference Service.
6. The LLM generates a response.
7. When appropriate, the AI Agent invokes one or more backend APIs:
   - Ticket Creation API
   - Refund API
   - Customer Profile API
8. The Backend API returns the final response to the user.
9. Security and application events are written to Cloud Object Storage.

---

## Critical Assets

- Customer support knowledge base
- Customer profile information
- OAuth access tokens
- Refund capability
- Ticket management system
- LLM context
- Audit logs

---

## External Dependencies

- OAuth Identity Provider
- LLM Provider
- Ticket Management Service
- Payment Service

---

## Trust Assumptions

- OAuth tokens are validated before every backend request.
- Only approved documents are indexed into the Vector Database.
- Retrieved documents are trusted by the LLM.
- The LLM cannot directly access databases or cloud storage.
- Tool execution occurs only through backend APIs.
- Audit logs are immutable after creation.
- Service-to-service communication is authenticated.

---

## Security Goals

- Prevent prompt injection attacks.
- Prevent retrieval data poisoning.
- Prevent unauthorized tool execution.
- Protect customer information from unauthorized disclosure.
- Ensure retrieved documents are authorized for the requesting user.
- Preserve audit log integrity.
- Enforce least privilege for AI-driven actions.
- Prevent excessive service-to-service permissions.

---

## Out of Scope

- Model training and fine-tuning
- Infrastructure provisioning
- Endpoint protection
- Physical security