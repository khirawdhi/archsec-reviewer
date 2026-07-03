# Example Architecture: Customer Support RAG Assistant

## Overview

The Customer Support RAG Assistant helps support engineers answer customer questions by retrieving relevant internal documentation and generating responses using a Large Language Model (LLM).

The application follows a Retrieval-Augmented Generation (RAG) architecture and can invoke backend business APIs for approved actions such as ticket creation and refund requests.

---

## Components

* User
* Web Application
* Backend API
* OAuth Identity Provider
* Retrieval Service
* Vector Database
* LLM Inference Service
* AI Agent
* Ticket Creation API
* Refund API
* Customer Profile API
* Cloud Object Storage (Audit Logs)

---

## Data Flow

1. A user submits a question through the Web Application.
2. The Backend API authenticates the user using OAuth.
3. The Retrieval Service searches the Vector Database for relevant documents.
4. Retrieved documents are combined with the user's prompt.
5. The combined prompt is sent to the LLM.
6. The LLM generates a response.
7. For specific requests, the AI Agent invokes one or more backend APIs:

   * Ticket Creation API
   * Refund API
   * Customer Profile API
8. The Backend API returns the final response to the user.
9. Security and application events are written to Cloud Object Storage.

---

## Assets

* Customer support knowledge base
* Customer profile data
* OAuth access tokens
* Refund capability
* Ticket management system
* LLM context window
* Audit logs

---

## External Dependencies

* OAuth Identity Provider
* LLM Provider
* Ticket Management Service
* Payment/Refund Service

---

## Trust Assumptions

* OAuth tokens are validated before every API request.
* Only approved documents are indexed in the Vector Database.
* The LLM cannot directly access databases or cloud storage.
* Tool execution is performed only through backend APIs.
* Audit logs are immutable after being written.
* Service-to-service communication uses authenticated connections.

---

## Security Goals

* Prevent prompt injection.
* Prevent retrieval data poisoning.
* Prevent unauthorized tool execution.
* Protect customer data from unauthorized disclosure.
* Ensure retrieved documents are authorized for the requesting user.
* Maintain integrity of audit logs.
* Restrict AI actions using least-privilege principles.
