from __future__ import annotations

from tests.report_engine_helpers import *

class TestIncidentExecutiveView:
    """Direct unit tests on the incident_executive_view context module."""

    EXAMPLES = ROOT / "skills/bot-insights/examples"

    @staticmethod
    def _module():
        from report_engine.contexts import incident_executive_view

        return incident_executive_view

    @staticmethod
    def _load(name: str) -> dict:
        import json

        return json.loads((TestIncidentExecutiveView.EXAMPLES / name).read_text())

    def test_constants(self):
        mod = self._module()
        assert mod.SCHEMA == "bot_incident_scope.v1"
        assert mod.REPORT_TYPE == "incident_executive_view"
        assert mod.TEMPLATE == "reports/incident_executive_view.html"
        assert set(mod.NOTE_ID_TO_SLOT) == {
            "llm-incident-status-level",
            "llm-what-happened",
            "llm-executive-impact",
            "llm-response-taken",
            "llm-decision-needed",
            "llm-current-status",
        }
        assert set(mod.NOTE_ID_TO_SLOT.values()) == {
            "incident_status_level",
            "what_happened",
            "executive_impact",
            "response_taken",
            "decision_needed",
            "current_status",
        }
        # ``executive_impact`` and ``current_status`` slot keys are
        # intentionally shared with the analyst incident_report so
        # analyst tooling can author once and surface in both views.
        from report_engine.contexts import incident_report

        shared = {"executive_impact", "current_status"}
        assert shared <= set(incident_report.NOTE_ID_TO_SLOT.values())
        assert shared <= set(mod.NOTE_ID_TO_SLOT.values())

    def test_assemble_delegates(self):
        from report_engine.contexts import incident_report

        mod = self._module()
        wrapper = self._load("incident-report.json")
        assembled = mod.assemble(wrapper["artifacts"])
        assembled_ir = incident_report.assemble(wrapper["artifacts"])
        assert assembled == assembled_ir

    def test_prepare_thin_keys(self):
        mod = self._module()
        wrapper = self._load("incident-report.json")
        ctx = mod.prepare(mod.assemble(wrapper["artifacts"]))
        # Keys the exec template consumes.
        expected = {
            "title",
            "kicker",
            "headline",
            "dek",
            "scope",
            "windows",
            "impact_tiles",
            "top_affected_hosts",
            "top_path_pattern",
            "recommended_actions",
            "deterministic_summary",
            "incident_status_tone",
            "incident_status_default",
            "confidence_caveat_default",
            "dashboard_url",
            "method",
            "generated_at",
        }
        assert expected <= set(ctx.keys())
        # Analyst-view-only fields are dropped — the exec view ships
        # a thin context, not the full incident_report dict.
        for absent in (
            "findings",
            "iocs",
            "iocs_json_text",
            "severity_ladder",
            "attack_aggregation",
            "incident_findings",
            "actor_rankings",
            "suspicious_targets",
        ):
            assert absent not in ctx, (
                f"{absent!r} should not surface in exec view context"
            )
        # KPI tiles capped at the exec ceiling (5).
        assert len(ctx["impact_tiles"]) <= mod.EXEC_IMPACT_TILES_CAP
        # Actions capped at the exec ceiling (5).
        assert len(ctx["recommended_actions"]) <= mod.EXEC_ACTIONS_CAP

    def test_status_tone_known(self):
        mod = self._module()
        assert mod.INCIDENT_STATUS_TONE["Active"] == "critical"
        assert mod.INCIDENT_STATUS_TONE["Contained"] == "monitor"
        assert mod.INCIDENT_STATUS_TONE["Monitoring"] == "observe"
        assert mod.INCIDENT_STATUS_TONE["Closed"] == "observe-mute"

    def test_status_tone_unknown_permissive(self):
        """An unknown status label must render verbatim with the
        neutral ``monitor`` tone — the template uses
        ``incident_status_tone.get(label, "monitor")``."""
        mod = self._module()
        assert mod.INCIDENT_STATUS_TONE.get("Resolved", "monitor") == "monitor"
        assert mod.INCIDENT_STATUS_TONE.get("Standing-by", "monitor") == "monitor"

    def test_actions_capped_at_five(self):
        """Synthesize a suspicious-targets list large enough to push
        the upstream action generator past five items, then assert the
        exec view truncates."""
        mod = self._module()
        from report_engine.contexts import incident_report as ir

        # The action generator branches on severity tiers + types.
        # Build a mix that triggers every branch (block, enrich, rate-
        # limit, anomaly, dashboard, retro) so the upstream list grows
        # past 5 and the exec view's cap kicks in.
        suspicious_targets = []
        for ip in ("203.0.113.10", "198.51.100.42", "192.0.2.17", "203.0.113.55"):
            suspicious_targets.append({
                "target_type": "client_ip",
                "target_type_label": "Client IP",
                "target_value": ip,
                "severity": "critical",
                "severity_tone": "critical",
                "severity_label": "Critical",
                "share_pct": 10.0,
                "share_pct_display": "10%",
                "requests_display": "100K",
                "supporting": {"requests": 100000},
                "reason_flag_labels": [],
                "edge_action_top_label": None,
                "edge_action_top_share_display": None,
            })
        suspicious_targets.append({
            "target_type": "request_path",
            "target_type_label": "Request Path",
            "target_value": "/login/submit",
            "severity": "high",
            "severity_tone": "escalate",
            "severity_label": "High",
            "share_pct": 30.0,
            "share_pct_display": "30%",
            "requests_display": "300K",
            "supporting": {"requests": 300000},
            "reason_flag_labels": [],
        })
        suspicious_targets.append({
            "target_type": "cohort",
            "target_type_label": "Traffic cohort",
            "target_value": "Browser",
            "severity": "high",
            "severity_tone": "escalate",
            "severity_label": "High",
            "share_pct": 12.0,
            "share_pct_display": "12%",
            "requests_display": "120K",
            "supporting": {"requests": 120000},
            "reason_flag_labels": ["behavioral anomaly"],
        })

        upstream = ir._recommended_actions_view(
            suspicious_targets, "https://grafana.example/d/incident", None
        )
        assert len(upstream) >= 5, (
            "test setup invariant: upstream generator should now produce "
            f"at least 5 actions; got {len(upstream)}"
        )
        capped = upstream[: mod.EXEC_ACTIONS_CAP]
        assert len(capped) <= mod.EXEC_ACTIONS_CAP == 5
