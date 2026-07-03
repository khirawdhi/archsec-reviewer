# Example Architecture: Customer Support RAG Assistant

A customer support AI assistant accepts questions from users through a web application.

The backend API sends the user question to a retrieval layer. The retrieval layer searches a vector database containing internal support articles, refund policy documents, and troubleshooting guides.

The retrieved context is sent to an LLM inference layer. The LLM generates an answer for the user.

For some requests, an AI agent can call external tools, including:
- ticket creation API
- refund API
- customer profile lookup API

The system uses OAuth tokens for service-to-service access. Logs are stored in cloud object storage.
