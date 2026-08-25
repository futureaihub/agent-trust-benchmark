"""Unit tests for OPA policy evaluation."""

import pytest


class TestPolicyGateway:
    """Test each Rego rule against the policy gateway."""

    @pytest.mark.parametrize(
        "role,action,env,resource,expected_allow",
        [
            # Core v0.1 scenario: delete production as non-admin → deny
            ("operator", "delete", "production", "database/customers", False),
            ("viewer", "delete", "production", "database/customers", False),
            # Admin can delete production
            ("admin", "delete", "production", "database/customers", True),
            # Non-production delete is allowed
            ("operator", "delete", "staging", "database/customers", True),
            ("operator", "delete", "development", "database/customers", True),
            # Non-delete actions are allowed
            ("operator", "read", "production", "database/customers", True),
            ("viewer", "read", "production", "database/customers", True),
            ("admin", "deploy", "production", "database/customers", True),
        ],
    )
    def test_opa_policy_rules(self, policy_gateway, role, action, env, resource, expected_allow):
        result = policy_gateway.evaluate(role, action, env, resource)
        assert result["allow"] == expected_allow, (
            f"role={role}, action={action}, env={env}: "
            f"expected allow={expected_allow}, got allow={result['allow']}"
        )

    def test_deny_reason_text(self, policy_gateway):
        result = policy_gateway.evaluate("operator", "delete", "production", "database/customers")
        assert result["reason"] == "deny_delete_production_non_admin"

    def test_allow_admin_reason_text(self, policy_gateway):
        result = policy_gateway.evaluate("admin", "delete", "production", "database/customers")
        assert result["reason"] == "allow_admin_production_delete"

    def test_allow_non_production_reason_text(self, policy_gateway):
        result = policy_gateway.evaluate("operator", "delete", "staging", "database/customers")
        assert result["reason"] == "allow_non_production_delete"
