"""
agent-immune: adaptive threat intelligence for AI agent governance integrations.
"""

from agent_immune.core.models import SecurityPolicy, ThreatAction, ThreatAssessment
from agent_immune.hardener import PromptHardener
from agent_immune.immune import AdaptiveImmuneSystem
from agent_immune.observability import MetricsCollector
from agent_immune.rate_limiter import CircuitBreaker

__version__ = "0.1.0"

__all__ = [
    "AdaptiveImmuneSystem",
    "CircuitBreaker",
    "MetricsCollector",
    "PromptHardener",
    "SecurityPolicy",
    "ThreatAction",
    "ThreatAssessment",
    "__version__",
]
