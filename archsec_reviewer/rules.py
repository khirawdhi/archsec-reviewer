COMPONENT_KEYWORDS = {
    "user": ["user", "employee", "customer", "admin", "client"],
    "api": ["api", "gateway", "endpoint", "backend", "service"],
    "database": ["database", "db", "postgres", "mysql", "mongodb", "dynamodb"],
    "vector_db": ["vector", "embedding", "retrieval", "rag", "knowledge base"],
    "llm": ["llm", "model", "gpt", "claude", "inference", "prompt"],
    "tool": ["tool", "agent", "action", "function", "plugin", "refund", "ticket"],
    "storage": ["s3", "bucket", "blob", "storage", "object store"],
    "ci_cd": ["ci/cd", "pipeline", "build", "artifact", "deployment", "github actions"],
    "identity": ["oauth", "oidc", "iam", "jwt", "token", "mtls", "certificate"],
    "third_party": ["vendor", "third-party", "external", "saas", "webhook"],
}

CONTROL_LIBRARY = {
    "user": ["Input validation", "Rate limiting", "Authentication", "Abuse monitoring"],
    "api": ["Authorization checks", "Schema validation", "API gateway policy", "Audit logging"],
    "database": ["Least privilege access", "Encryption at rest", "Query authorization", "Backup protection"],
    "vector_db": ["Source allowlists", "Document provenance", "Retrieval-time authorization", "Index segregation"],
    "llm": ["Prompt isolation", "System prompt protection", "Context minimization", "Output policy enforcement"],
    "tool": ["Tool allowlists", "Human approval for sensitive actions", "Scoped credentials", "Action validation"],
    "storage": ["Bucket policy review", "Object-level access control", "Encryption", "Public access blocking"],
    "ci_cd": ["Signed builds", "Secret scanning", "Protected branches", "Artifact provenance"],
    "identity": ["Short-lived tokens", "mTLS/OIDC validation", "Audience restriction", "Key rotation"],
    "third_party": ["Vendor risk review", "Webhook signature validation", "Network egress controls", "Contractual controls"],
}

THREAT_LIBRARY = {
    "vector_db": [
        "Poisoned documents influence generated answers",
        "Sensitive documents retrieved without authorization",
        "Untrusted content treated as authoritative context",
    ],
    "llm": [
        "Prompt injection overrides intended behavior",
        "Sensitive context leaks through generated output",
        "Model output triggers unsafe downstream action",
    ],
    "tool": [
        "Agent executes unauthorized action",
        "Tool call uses excessive privileges",
        "External action is performed without validation",
    ],
    "api": [
        "Broken object-level authorization",
        "Unauthenticated access to sensitive endpoint",
        "Input tampering crosses service boundary",
    ],
    "ci_cd": [
        "Pipeline secrets exposed to untrusted code",
        "Compromised dependency enters build",
        "Unsigned artifact deployed to production",
    ],
    "identity": [
        "Token replay across services",
        "Over-broad service identity permissions",
        "Weak trust model between services",
    ],
}
