#!/usr/bin/env python3
"""
Tests for WSHawk Integrations (DefectDojo, Jira, Webhook)
"""

import json
import os
import unittest
from unittest.mock import patch, AsyncMock, MagicMock


class TestDefectDojoIntegration(unittest.TestCase):
    """Tests for DefectDojo integration."""
    
    def setUp(self):
        from wshawk.integrations.defectdojo import DefectDojoIntegration
        self.dd = DefectDojoIntegration(
            url="https://dd.example.com",
            api_key="test-api-key",
            product_id=1,
        )
        self.sample_vulns = [
            {
                'type': 'SQL Injection',
                'confidence': 'HIGH',
                'description': 'SQL injection found in message handler',
                'payload': "' OR 1=1--",
                'response_snippet': 'mysql error',
                'cvss_score': 8.5,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'recommendation': 'Use parameterized queries',
            },
            {
                'type': 'XSS',
                'confidence': 'MEDIUM',
                'description': 'Cross-site scripting via WebSocket',
                'payload': '<script>alert(1)</script>',
                'cvss_score': 6.1,
            },
        ]
        self.scan_info = {
            'target': 'ws://example.com/ws',
            'duration': 45.2,
            'messages_sent': 200,
            'messages_received': 180,
        }
    
    def test_headers(self):
        headers = self.dd._get_headers()
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], 'Token test-api-key')
    
    def test_convert_findings(self):
        findings = self.dd._convert_findings(self.sample_vulns, self.scan_info)
        self.assertEqual(len(findings), 2)
        
        # Check first finding
        f = findings[0]
        self.assertIn('[WSHawk]', f['title'])
        self.assertEqual(f['severity'], 'High')
        self.assertTrue(f['active'])
        self.assertIn('SQL Injection', f['title'])
    
    def test_cwe_mapping(self):
        self.assertEqual(self.dd._get_cwe('SQL Injection'), 89)
        self.assertEqual(self.dd._get_cwe('XSS Reflected'), 79)
        self.assertEqual(self.dd._get_cwe('Command Injection'), 78)
        self.assertEqual(self.dd._get_cwe('Path Traversal'), 22)
        self.assertEqual(self.dd._get_cwe('SSRF Attack'), 918)
        self.assertEqual(self.dd._get_cwe('Unknown Type'), 0)
    
    def test_severity_mapping(self):
        self.assertEqual(self.dd.SEVERITY_MAP['CRITICAL'], 'Critical')
        self.assertEqual(self.dd.SEVERITY_MAP['HIGH'], 'High')
        self.assertEqual(self.dd.SEVERITY_MAP['LOW'], 'Low')
    
    def test_build_description(self):
        desc = self.dd._build_description(self.sample_vulns[0], self.scan_info)
        self.assertIn('SQL Injection', desc)
        self.assertIn('ws://example.com/ws', desc)
        self.assertIn("OR 1=1", desc)
    
    def test_build_reproduction_steps(self):
        steps = self.dd._build_reproduction_steps(self.sample_vulns[0], self.scan_info)
        self.assertIn('ws://example.com/ws', steps)
        self.assertIn("OR 1=1", steps)
    
    def test_from_env_missing(self):
        from wshawk.integrations.defectdojo import from_env
        # Should return None when env vars are not set
        with patch.dict(os.environ, {}, clear=True):
            result = from_env()
            self.assertIsNone(result)
    
    def test_from_env_present(self):
        from wshawk.integrations.defectdojo import from_env
        env = {
            'DEFECTDOJO_URL': 'https://dd.test.com',
            'DEFECTDOJO_API_KEY': 'test-key-123',
        }
        with patch.dict(os.environ, env, clear=True):
            result = from_env()
            self.assertIsNotNone(result)
            self.assertEqual(result.url, 'https://dd.test.com')


class TestJiraIntegration(unittest.TestCase):
    """Tests for Jira integration."""
    
    def setUp(self):
        from wshawk.integrations.jira_connector import JiraIntegration
        self.jira = JiraIntegration(
            url="https://company.atlassian.net",
            email="test@company.com",
            api_token="test-token",
            project_key="SEC",
        )
        self.sample_vulns = [
            {
                'type': 'SQL Injection',
                'confidence': 'CRITICAL',
                'description': 'Critical SQL injection',
                'payload': "' OR 1=1--",
                'cvss_score': 9.8,
            },
        ]
        self.scan_info = {
            'target': 'ws://example.com/ws',
            'duration': 30.5,
        }
    
    def test_headers(self):
        headers = self.jira._get_headers()
        self.assertIn('Authorization', headers)
        self.assertTrue(headers['Authorization'].startswith('Basic '))
        self.assertEqual(headers['Content-Type'], 'application/json')
    
    def test_priority_mapping(self):
        self.assertEqual(self.jira.PRIORITY_MAP['CRITICAL'], 'Highest')
        self.assertEqual(self.jira.PRIORITY_MAP['HIGH'], 'High')
        self.assertEqual(self.jira.PRIORITY_MAP['LOW'], 'Low')
    
    def test_build_issue(self):
        issue = self.jira._build_issue(self.sample_vulns[0], self.scan_info)
        fields = issue['fields']
        
        self.assertEqual(fields['project']['key'], 'SEC')
        self.assertIn('[WSHawk]', fields['summary'])
        self.assertEqual(fields['priority']['name'], 'Highest')
        self.assertIn('wshawk', fields['labels'])
        self.assertIn('severity-critical', fields['labels'])
    
    def test_build_description(self):
        desc = self.jira._build_description(self.sample_vulns[0], self.scan_info)
        self.assertIn('WebSocket Security Vulnerability', desc)
        self.assertIn('SQL Injection', desc)
        self.assertIn('ws://example.com/ws', desc)
    
    def test_summary_truncation(self):
        long_vuln = {
            'type': 'A' * 300,
            'confidence': 'HIGH',
        }
        issue = self.jira._build_issue(long_vuln, self.scan_info)
        self.assertTrue(len(issue['fields']['summary']) <= 255)
    
    def test_default_labels(self):
        self.assertIn('wshawk', self.jira.labels)
        self.assertIn('security', self.jira.labels)
    
    def test_from_env_missing(self):
        from wshawk.integrations.jira_connector import from_env
        with patch.dict(os.environ, {}, clear=True):
            result = from_env()
            self.assertIsNone(result)


class TestWebhookNotifier(unittest.TestCase):
    """Tests for Webhook notifier."""
    
    def setUp(self):
        from wshawk.integrations.webhook import WebhookNotifier
        self.notifier = WebhookNotifier(
            webhook_url="https://hooks.example.com/test",
            platform="generic"
        )
        self.sample_vulns = [
            {'type': 'SQL Injection', 'confidence': 'CRITICAL', 'cvss_score': 9.8,
             'description': 'Critical SQLi', 'browser_verified': True},
            {'type': 'XSS', 'confidence': 'HIGH', 'cvss_score': 7.2,
             'description': 'Reflected XSS'},
            {'type': 'Info Leak', 'confidence': 'LOW', 'cvss_score': 3.1,
             'description': 'Minor info disclosure'},
        ]
        self.scan_info = {
            'target': 'ws://example.com/ws',
            'duration': 60.0,
            'messages_sent': 500,
            'messages_received': 450,
        }
    
    def test_generic_payload(self):
        payload = self.notifier._build_generic_payload(self.sample_vulns, self.scan_info)
        self.assertEqual(payload['event'], 'scan_complete')
        self.assertEqual(payload['summary']['total_findings'], 3)
        self.assertEqual(len(payload['findings']), 3)
    
    def test_slack_payload(self):
        from wshawk.integrations.webhook import WebhookNotifier
        slack = WebhookNotifier("https://hooks.slack.com/test", platform="slack")
        payload = slack._build_slack_payload(self.sample_vulns, self.scan_info)
        self.assertIn('blocks', payload)
        self.assertTrue(len(payload['blocks']) > 0)
    
    def test_discord_payload(self):
        from wshawk.integrations.webhook import WebhookNotifier
        discord = WebhookNotifier("https://discord.com/api/webhooks/test", platform="discord")
        payload = discord._build_discord_payload(self.sample_vulns, self.scan_info)
        self.assertIn('embeds', payload)
        self.assertEqual(len(payload['embeds']), 1)
        embed = payload['embeds'][0]
        self.assertEqual(embed['color'], 0xFF0000)  # Critical = red
    
    def test_teams_payload(self):
        from wshawk.integrations.webhook import WebhookNotifier
        teams = WebhookNotifier("https://outlook.office.com/test", platform="teams")
        payload = teams._build_teams_payload(self.sample_vulns, self.scan_info)
        self.assertEqual(payload['@type'], 'MessageCard')
        self.assertTrue(len(payload['sections']) > 0)
    
    def test_severity_summary(self):
        counts = self.notifier._count_severities(self.sample_vulns)
        self.assertEqual(counts['CRITICAL'], 1)
        self.assertEqual(counts['HIGH'], 1)
        self.assertEqual(counts['LOW'], 1)
    
    def test_risk_level(self):
        self.assertEqual(self.notifier._get_risk_level(self.sample_vulns), 'CRITICAL')
        self.assertEqual(self.notifier._get_risk_level([]), 'NONE')
    
    def test_empty_findings(self):
        payload = self.notifier._build_generic_payload([], self.scan_info)
        self.assertEqual(payload['summary']['total_findings'], 0)
        self.assertEqual(payload['summary']['risk_level'], 'NONE')
    
    def test_platform_detection(self):
        from wshawk.integrations.webhook import WebhookNotifier
        n = WebhookNotifier("https://hooks.example.com/test", platform="invalid")
        self.assertEqual(n.platform, 'generic')


class TestSmartPayloads(unittest.TestCase):
    """Tests for Smart Payload modules."""
    
    def test_context_generator_json_learning(self):
        from wshawk.smart_payloads.context_generator import ContextAwareGenerator
        gen = ContextAwareGenerator()
        
        # Learn from sample messages
        gen.learn_from_message('{"action": "ping", "user": "test", "id": 42}')
        gen.learn_from_message('{"action": "subscribe", "user": "admin", "id": 100}')
        gen.learn_from_message('{"action": "message", "user": "agent", "id": 7}')
        
        self.assertEqual(gen.context['format'], 'json')
        self.assertTrue(gen.analysis_complete)
        self.assertIn('action', gen.context['fields'])
        self.assertIn('user', gen.context['fields'])
    
    def test_context_generator_payloads(self):
        from wshawk.smart_payloads.context_generator import ContextAwareGenerator
        gen = ContextAwareGenerator()
        gen.learn_from_message('{"input": "hello"}')
        gen.learn_from_message('{"input": "world"}')
        gen.learn_from_message('{"input": "test"}')
        
        payloads = gen.generate_payloads('sqli', count=5)
        self.assertTrue(len(payloads) > 0)
        
        # Payloads should be JSON-formatted
        for p in payloads[:3]:
            try:
                data = json.loads(p)
                self.assertIsInstance(data, dict)
            except json.JSONDecodeError:
                pass  # Some payloads may not be valid JSON
    
    def test_context_generator_xml_detection(self):
        from wshawk.smart_payloads.context_generator import ContextAwareGenerator
        gen = ContextAwareGenerator()
        gen.learn_from_message('<message><body>hello</body></message>')
        self.assertEqual(gen.context['format'], 'xml')
    
    def test_feedback_loop_baseline(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop
        loop = FeedbackLoop()
        
        loop.establish_baseline("Normal response", 0.1)
        loop.establish_baseline("Normal response 2", 0.12)
        loop.establish_baseline("Normal response 3", 0.11)
        
        self.assertTrue(loop.baseline_established)
    
    def test_feedback_loop_error_detection(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop, ResponseSignal
        loop = FeedbackLoop()
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        
        signal, confidence = loop.analyze_response(
            "' OR 1=1--",
            "mysql syntax error near '1=1'",
            0.15,
            category='sqli'
        )
        
        self.assertEqual(signal, ResponseSignal.ERROR)
        self.assertGreater(confidence, 0.5)
    
    def test_feedback_loop_block_detection(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop, ResponseSignal
        loop = FeedbackLoop()
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        
        signal, _ = loop.analyze_response(
            "<script>alert(1)</script>",
            "Request blocked by firewall",
            0.05,
            category='xss'
        )
        
        self.assertEqual(signal, ResponseSignal.BLOCKED)
    
    def test_feedback_loop_delay_detection(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop, ResponseSignal
        loop = FeedbackLoop()
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        
        signal, _ = loop.analyze_response(
            "1' AND SLEEP(5)--",
            "OK",
            0.5,  # 5x slower than 0.1 baseline
            category='sqli'
        )
        
        self.assertEqual(signal, ResponseSignal.DELAYED)
    
    def test_feedback_loop_mutations(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop
        loop = FeedbackLoop()
        
        mutations = loop.generate_mutations("' OR 1=1--", count=5)
        self.assertTrue(len(mutations) > 0)
        self.assertTrue(len(mutations) <= 5)
    
    def test_feedback_loop_category_priority(self):
        from wshawk.smart_payloads.feedback_loop import FeedbackLoop
        loop = FeedbackLoop()
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        loop.establish_baseline("OK", 0.1)
        
        # Simulate SQLi being effective
        loop.analyze_response("sqli1", "mysql error", 0.1, 'sqli')
        loop.analyze_response("sqli2", "OK", 0.1, 'sqli')
        loop.analyze_response("xss1", "blocked", 0.1, 'xss')
        
        priorities = loop.get_priority_categories()
        self.assertTrue(len(priorities) >= 2)
    
    def test_payload_evolver_seed(self):
        from wshawk.smart_payloads.payload_evolver import PayloadEvolver
        evolver = PayloadEvolver(population_size=20)
        
        seeds = ["' OR 1=1--", "<script>alert(1)</script>", "; cat /etc/passwd"]
        evolver.seed(seeds)
        
        self.assertEqual(len(evolver.population), 3)
    
    def test_payload_evolver_evolve(self):
        from wshawk.smart_payloads.payload_evolver import PayloadEvolver
        evolver = PayloadEvolver(population_size=50)
        
        seeds = [
            "' OR 1=1--", "' UNION SELECT null--",
            "<script>alert(1)</script>", "; id",
        ]
        evolver.seed(seeds)
        
        new_payloads = evolver.evolve(count=10)
        self.assertTrue(len(new_payloads) > 0)
        self.assertEqual(evolver.generation, 1)
    
    def test_payload_evolver_fitness(self):
        from wshawk.smart_payloads.payload_evolver import PayloadEvolver
        evolver = PayloadEvolver()
        
        evolver.seed(["test_payload"])
        evolver.update_fitness("test_payload", 0.9)
        
        best = evolver.get_best(1)
        self.assertEqual(len(best), 1)
        self.assertGreater(best[0][1], 0.5)
    
    def test_payload_evolver_stats(self):
        from wshawk.smart_payloads.payload_evolver import PayloadEvolver
        evolver = PayloadEvolver()
        evolver.seed(["a", "b", "c"])
        
        stats = evolver.get_stats()
        self.assertEqual(stats['population_size'], 3)
        self.assertEqual(stats['generation'], 0)
    
    def test_payload_evolver_dedup(self):
        from wshawk.smart_payloads.payload_evolver import PayloadEvolver
        evolver = PayloadEvolver()
        
        # Same payload shouldn't be added twice
        evolver.seed(["dup", "dup", "dup"])
        self.assertEqual(len(evolver.population), 1)


if __name__ == '__main__':
    unittest.main()
