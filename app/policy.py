"""OPA policy client. Evaluates Rego policies via OPA eval subprocess."""

import json
import os
import subprocess
import tempfile

OPA_BIN = os.path.join(os.path.dirname(os.path.dirname(__file__)), "opa")
POLICIES_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies", "auth.rego")


class PolicyGateway:
    """Client for OPA policy evaluation using opa eval.

    Fail-closed: any subprocess or parse error returns deny.
    """

    def __init__(self, opa_bin: str = OPA_BIN, policies_file: str = POLICIES_FILE):
        self._opa_bin = opa_bin
        self._policies_file = policies_file

    def evaluate(
        self, role: str, action: str, environment: str, resource: str,
        trusted_role: str | None = None,
    ) -> dict:
        """Evaluate policy against the given input.

        When trusted_role is provided, OPA evaluates using trusted_role
        instead of the agent-provided role. The agent's role is recorded
        in the result but does NOT influence authorization.

        Returns:
            {"allow": bool, "reason": str, "role": str}

        On any failure, returns deny (fail-closed).
        """
        effective_role = trusted_role if trusted_role is not None else role
        input_data = {
            "user": "test",
            "role": effective_role,
            "action": action,
            "resource": resource,
            "environment": environment,
        }

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp:
                json.dump(input_data, tmp)
                tmp_path = tmp.name

            proc = subprocess.run(
                [
                    self._opa_bin, "eval",
                    "-d", self._policies_file,
                    "-i", tmp_path,
                    "--format", "pretty",
                    "data.benchmark.auth",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if proc.returncode != 0:
                return {"allow": False, "reason": "policy_engine_error"}

            raw = json.loads(proc.stdout.strip())
            if not raw:
                return {"allow": False, "reason": "no_policy_match"}

            return {
                "allow": raw.get("allow", False),
                "reason": raw.get("reason", "unknown"),
                "role": effective_role,
            }

        except FileNotFoundError:
            return {"allow": False, "reason": "policy_engine_unavailable"}
        except OSError:
            return {"allow": False, "reason": "policy_engine_unavailable"}
        except subprocess.TimeoutExpired:
            return {"allow": False, "reason": "policy_engine_timeout"}
        except json.JSONDecodeError:
            return {"allow": False, "reason": "policy_engine_invalid_response"}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def close(self) -> None:
        pass
