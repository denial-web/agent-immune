"""
agent-immune: adaptive threat intelligence for AI agent governance integrations.
"""

from agent_immune.core.models import ThreatAction, ThreatAssessment
from agent_immune.immune import AdaptiveImmuneSystem

__version__ = "0.1.0"

__all__ = [
    "AdaptiveImmuneSystem",
    "ThreatAction",
    "ThreatAssessment",
    "__version__",
]
