"""
WSHawk Smart Payloads - Context-aware adaptive payload generation
Author: Regaan (@noobforanonymous)
"""

from .context_generator import ContextAwareGenerator
from .feedback_loop import FeedbackLoop
from .payload_evolver import PayloadEvolver

__all__ = ['ContextAwareGenerator', 'FeedbackLoop', 'PayloadEvolver']
