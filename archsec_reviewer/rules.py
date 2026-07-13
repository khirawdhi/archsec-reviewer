"""Security rules and component definitions for ArchSec Reviewer."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ComponentDefinition:
    keywords: tuple[str, ...]
    threats: tuple[str, ...] = field(default_factory=tuple)
    controls: tuple[str, ...] = field(default_factory=tuple)
    validation_checks: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RuleDefinition:
    required_components: frozenset[str]
    message: str


COMPONENTS: dict[str, ComponentDefinition] = {
    "user": ComponentDefinition(
        keywords=(
            "user",
            "employee",
            "customer",
            "admin",
            "client",
        ),
        controls=(
            "Input validation",
            "Rate limiting",
            "Authentication",
            "Abuse monitoring",
        ),
    ),
    "api": ComponentDefinition(
        keywords=(
            "api",
            "gateway",
            "endpoint",
            "backend",
            "service",
        ),
        threats=(
            "Broken object-level authorization",
            "Unauthenticated access to sensitive endpoint",
            "Input tampering crosses service boundary",
        ),
        controls=(
            "Authorization checks",
            "Schema validation",
            "API gateway policy",
            "Audit logging",
        ),
    ),
    "database": ComponentDefinition(
        keywords=(
            "database",
            "db",
            "postgres",
            "mysql",
            "mongodb",
            "dynamodb",
        ),
        controls=(
            "Least privilege access",
            "Encryption at rest",
            "Query authorization",
            "Backup protection",
        ),
    ),
    "vector_db": ComponentDefinition(
        keywords=(
            "vector",
            "embedding",
            "retrieval",
            "rag",
            "knowledge base",
        ),
        threats=(
            "Poisoned documents influence generated answers",
            "Sensitive documents retrieved without authorization",
            "Untrusted content treated as authoritative context",
        ),
        controls=(
            "Source allowlists",
            "Document provenance",
            "Retrieval-time authorization",
            "Index segregation",
        ),
        validation_checks=(
            "Test whether untrusted documents can be retrieved for sensitive queries.",
            "Verify source metadata is preserved from ingestion to retrieval.",
            "Confirm retrieval results are filtered by user authorization.",
        ),
    ),
    "llm": ComponentDefinition(
        keywords=(
            "llm",
            "model",
            "gpt",
            "claude",
            "inference",
            "prompt",
        ),
        threats=(
            "Prompt injection overrides intended behavior",
            "Sensitive context leaks through generated output",
            "Model output triggers unsafe downstream action",
        ),
        controls=(
            "Prompt isolation",
            "System prompt protection",
            "Context minimization",
            "Output policy enforcement",
        ),
        validation_checks=(
            "Test prompt injection attempts against system and developer instructions.",
            "Verify sensitive context is not leaked in model output.",
            "Confirm output filtering is applied before returning responses.",
        ),
    ),
    "tool": ComponentDefinition(
        keywords=(
            "tool",
            "agent",
            "action",
            "function",
            "plugin",
            "refund",
            "ticket",
        ),
        threats=(
            "Agent executes unauthorized action",
            "Tool call uses excessive privileges",
            "External action is performed without validation",
        ),
        controls=(
            "Tool allowlists",
            "Human approval for sensitive actions",
            "Scoped credentials",
            "Action validation",
        ),
        validation_checks=(
            "Verify tool calls require explicit authorization.",
            "Test whether the model can trigger high-risk actions without approval.",
            "Confirm tools use scoped credentials with least privilege.",
        ),
    ),
    "storage": ComponentDefinition(
        keywords=(
            "s3",
            "bucket",
            "blob",
            "storage",
            "object store",
        ),
        controls=(
            "Bucket policy review",
            "Object-level access control",
            "Encryption",
            "Public access blocking",
        ),
    ),
    "ci_cd": ComponentDefinition(
        keywords=(
            "ci/cd",
            "pipeline",
            "build",
            "artifact",
            "deployment",
            "github actions",
        ),
        threats=(
            "Pipeline secrets exposed to untrusted code",
            "Compromised dependency enters build",
            "Unsigned artifact deployed to production",
        ),
        controls=(
            "Signed builds",
            "Secret scanning",
            "Protected branches",
            "Artifact provenance",
        ),
        validation_checks=(
            "Verify build artifacts are signed and traceable.",
            "Confirm secrets are not available to untrusted pull requests.",
            "Test dependency confusion and malicious package scenarios.",
        ),
    ),
    "identity": ComponentDefinition(
        keywords=(
            "oauth",
            "oidc",
            "iam",
            "jwt",
            "token",
            "mtls",
            "certificate",
        ),
        threats=(
            "Token replay across services",
            "Over-broad service identity permissions",
            "Weak trust model between services",
        ),
        controls=(
            "Short-lived tokens",
            "mTLS/OIDC validation",
            "Audience restriction",
            "Key rotation",
        ),
    ),
    "third_party": ComponentDefinition(
        keywords=(
            "vendor",
            "third-party",
            "external",
            "saas",
            "webhook",
        ),
        controls=(
            "Vendor risk review",
            "Webhook signature validation",
            "Network egress controls",
            "Contractual controls",
        ),
    ),
}


TRUST_BOUNDARY_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        required_components=frozenset({"user", "api"}),
        message="User / Client → API or application boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"api", "database"}),
        message="Application service → Database boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"api", "vector_db"}),
        message="Application service → Retrieval / vector database boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"vector_db", "llm"}),
        message="Retrieved context → LLM prompt construction boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"llm", "tool"}),
        message="LLM reasoning → Tool / action execution boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"api", "third_party"}),
        message="Internal service → External vendor / third-party boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"ci_cd"}),
        message="Source code → Build pipeline → Artifact → Deployment boundary",
    ),
    RuleDefinition(
        required_components=frozenset({"identity", "api"}),
        message="Identity provider / token issuer → Service authorization boundary",
    ),
)


ATTACK_PATH_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        required_components=frozenset({"user", "api", "vector_db", "llm"}),
        message=(
            "Malicious user input → retrieval query manipulation → "
            "unsafe context → insecure LLM response"
        ),
    ),
    RuleDefinition(
        required_components=frozenset({"vector_db", "llm"}),
        message=(
            "Poisoned knowledge base document → retrieved as trusted context → "
            "manipulated model output"
        ),
    ),
    RuleDefinition(
        required_components=frozenset({"llm", "tool"}),
        message=(
            "Prompt injection → unauthorized tool selection → "
            "sensitive action execution"
        ),
    ),
    RuleDefinition(
        required_components=frozenset({"ci_cd", "storage"}),
        message=(
            "Compromised build pipeline → malicious artifact → "
            "deployment to runtime environment"
        ),
    ),
    RuleDefinition(
        required_components=frozenset({"identity", "api"}),
        message=(
            "Stolen or over-scoped token → service access → "
            "lateral movement across APIs"
        ),
    ),
)


BASE_VALIDATION_CHECKS: tuple[str, ...] = (
    "Confirm every trust boundary has an owner and an enforcement point.",
    "Verify authorization is enforced server-side, not only in the UI.",
    "Confirm logs capture security-relevant decisions and denied actions.",
)