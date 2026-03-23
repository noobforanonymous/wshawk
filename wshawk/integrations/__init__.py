"""
WSHawk Integrations - Connect scan results to external platforms
Author: Regaan (@regaan)
"""

from .defectdojo import DefectDojoIntegration
from .jira_connector import JiraIntegration
from .webhook import WebhookNotifier

__all__ = ['DefectDojoIntegration', 'JiraIntegration', 'WebhookNotifier']
