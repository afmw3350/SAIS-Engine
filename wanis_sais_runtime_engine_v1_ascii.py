"""
SAIS Runtime Governance Engine v1.0
Wanis Definition

Author:
    Abdelfattah Wanis
    Synesis AI Solutions (SAIS)

Core distinction:

1. MLG - Mathematical Logic Generator
   The foundational mathematical logic system that generates proposals,
   plans, commands, or execution requests.

2. AI System
   The operational bot, software agent, robotic system, workflow, tool,
   API client, or other external system that may act on an MLG output.

3. SAIS
   A deterministic runtime governance layer positioned between generation
   and execution.

SAIS does not attempt to govern:
    - model weights
    - embeddings
    - training data
    - hidden internal reasoning

SAIS governs:
    - execution requests
    - actions
    - tool calls
    - API interactions
    - robotic movement
    - external system impact
    - identity
    - jurisdiction
    - permissions
    - telemetry
    - audit evidence

Central principle:
    The MLG may propose.
    The AI system may execute only after SAIS authorization.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple
from uuid import uuid4


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class ActionType(str, Enum):
    INFORMATION = "INFORMATION"
    TOOL_CALL = "TOOL_CALL"
    API_INTERACTION = "API_INTERACTION"
    FILE_OPERATION = "FILE_OPERATION"
    SOFTWARE_EXECUTION = "SOFTWARE_EXECUTION"
    ROBOTIC_MOVEMENT = "ROBOTIC_MOVEMENT"
    FINANCIAL_ACTION = "FINANCIAL_ACTION"
    CRITICAL_INFRASTRUCTURE = "CRITICAL_INFRASTRUCTURE"


@dataclass(frozen=True)
class MLGProposal:
    generator_id: str
    request_text: str
    action_type: ActionType
    target: str
    parameters: Dict[str, Any]
    stated_purpose: str
    confidence: float


@dataclass(frozen=True)
class ExecutionIdentity:
    actor_id: str
    organization: str
    jurisdiction: str
    role: str
    authenticated: bool


@dataclass(frozen=True)
class ExecutionRequest:
    request_id: str
    timestamp_utc: str
    proposal: MLGProposal
    identity: ExecutionIdentity
    requested_permissions: FrozenSet[str]
    estimated_impact: int
    reversibility: int
    telemetry_available: bool
    human_approval_available: bool


@dataclass(frozen=True)
class GovernanceResult:
    request_id: str
    decision: Decision
    risk_score: int
    reasons: Tuple[str, ...]
    permitted_permissions: FrozenSet[str]
    policy_version: str
    audit_hash: str


@dataclass(frozen=True)
class SAISPolicy:
    version: str = "WANIS-SAIS-1.0"
    allow_risk_max: int = 2
    review_risk_max: int = 5
    escalate_risk_max: int = 7

    prohibited_targets: FrozenSet[str] = frozenset({
        "weapons_system",
        "unauthorized_surveillance",
        "public_safety_control",
    })

    high_impact_actions: FrozenSet[ActionType] = frozenset({
        ActionType.ROBOTIC_MOVEMENT,
        ActionType.FINANCIAL_ACTION,
        ActionType.CRITICAL_INFRASTRUCTURE,
    })


class SAISRuntimeGovernor:
    """
    Deterministic runtime authorization valve.

    It evaluates observable execution facts.
    It does not inspect hidden model internals.
    """

    def __init__(self, policy: Optional[SAISPolicy] = None) -> None:
        self.policy = policy or SAISPolicy()

    def authorize(self, request: ExecutionRequest) -> GovernanceResult:
        score = 0
        reasons = []

        if not request.identity.authenticated:
            score += 8
            reasons.append("Execution identity is not authenticated.")

        if not request.identity.jurisdiction.strip():
            score += 4
            reasons.append("Execution jurisdiction is undefined.")

        normalized_target = request.proposal.target.strip().lower()

        if normalized_target in self.policy.prohibited_targets:
            score += 10
            reasons.append("The requested target is prohibited by policy.")

        impact = self._bounded(request.estimated_impact)
        reversibility = self._bounded(request.reversibility)

        score += impact // 2

        if impact >= 7:
            score += 2
            reasons.append("The request may create high external impact.")

        if reversibility <= 3:
            score += 2
            reasons.append("The requested action is difficult to reverse.")

        if request.proposal.action_type in self.policy.high_impact_actions:
            score += 2
            reasons.append("The request belongs to a high-impact action class.")

        if not request.requested_permissions:
            score += 3
            reasons.append("No explicit execution permissions were declared.")

        if "unrestricted" in request.requested_permissions:
            score += 7
            reasons.append("Unrestricted execution authority is not permitted.")

        if not request.telemetry_available:
            score += 4
            reasons.append("Runtime telemetry is unavailable.")

        if (
            request.proposal.action_type in self.policy.high_impact_actions
            and not request.human_approval_available
        ):
            score += 3
            reasons.append(
                "Human approval is unavailable for a high-impact action."
            )

        decision = self._decision(score)

        if decision == Decision.ALLOW:
            permitted = request.requested_permissions
        else:
            permitted = frozenset()

        if not reasons:
            reasons.append(
                "Identity, permissions, impact, telemetry, and execution "
                "boundary satisfy the deterministic runtime policy."
            )

        audit_payload = {
            "request_id": request.request_id,
            "decision": decision.value,
            "risk_score": score,
            "reasons": reasons,
            "permitted_permissions": sorted(permitted),
            "policy_version": self.policy.version,
        }

        audit_hash = sha256(
            json.dumps(audit_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return GovernanceResult(
            request_id=request.request_id,
            decision=decision,
            risk_score=score,
            reasons=tuple(reasons),
            permitted_permissions=permitted,
            policy_version=self.policy.version,
            audit_hash=audit_hash,
        )

    def execute_if_allowed(
        self,
        request: ExecutionRequest,
        executor: Callable[[ExecutionRequest], Any],
    ) -> Tuple[GovernanceResult, Optional[Any]]:
        result = self.authorize(request)

        if result.decision != Decision.ALLOW:
            return result, None

        output = executor(request)
        return result, output

    def _decision(self, score: int) -> Decision:
        if score <= self.policy.allow_risk_max:
            return Decision.ALLOW
        if score <= self.policy.review_risk_max:
            return Decision.REVIEW
        if score <= self.policy.escalate_risk_max:
            return Decision.ESCALATE
        return Decision.BLOCK

    @staticmethod
    def _bounded(value: int) -> int:
        return max(0, min(10, int(value)))


def create_request(
    proposal: MLGProposal,
    identity: ExecutionIdentity,
    permissions: FrozenSet[str],
    estimated_impact: int,
    reversibility: int,
    telemetry_available: bool,
    human_approval_available: bool,
) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=str(uuid4()),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        proposal=proposal,
        identity=identity,
        requested_permissions=permissions,
        estimated_impact=estimated_impact,
        reversibility=reversibility,
        telemetry_available=telemetry_available,
        human_approval_available=human_approval_available,
    )


def result_to_json(result: GovernanceResult) -> str:
    payload = asdict(result)
    payload["decision"] = result.decision.value
    payload["permitted_permissions"] = sorted(result.permitted_permissions)
    payload["reasons"] = list(result.reasons)
    return json.dumps(payload, indent=2)


def print_result(
    title: str,
    result: GovernanceResult,
    execution_output: Any = None,
) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print(result_to_json(result))
    print("EXECUTION OUTPUT:")
    print(json.dumps(execution_output, indent=2))


def run_demo() -> None:
    governor = SAISRuntimeGovernor()

    verified_identity = ExecutionIdentity(
        actor_id="operator-001",
        organization="Synesis AI Solutions",
        jurisdiction="Belgium / EU",
        role="Authorized Research Operator",
        authenticated=True,
    )

    # Scenario 1: Low-impact information request
    safe_proposal = MLGProposal(
        generator_id="MLG-CORE-01",
        request_text="Read the approved telemetry status.",
        action_type=ActionType.INFORMATION,
        target="approved_telemetry_store",
        parameters={"operation": "read_status"},
        stated_purpose="Governance monitoring",
        confidence=0.98,
    )

    safe_request = create_request(
        proposal=safe_proposal,
        identity=verified_identity,
        permissions=frozenset({"read:telemetry"}),
        estimated_impact=1,
        reversibility=10,
        telemetry_available=True,
        human_approval_available=True,
    )

    safe_result, safe_output = governor.execute_if_allowed(
        safe_request,
        executor=lambda request: {
            "status": "EXECUTED",
            "message": "Approved telemetry status returned.",
        },
    )

    print_result("SCENARIO 1 - SAFE REQUEST", safe_result, safe_output)

    # Scenario 2: High-impact robotic movement without human approval
    robot_proposal = MLGProposal(
        generator_id="MLG-CORE-01",
        request_text="Move an industrial robotic arm.",
        action_type=ActionType.ROBOTIC_MOVEMENT,
        target="industrial_robot_arm",
        parameters={"axis": "X", "distance_mm": 500},
        stated_purpose="Automated repositioning",
        confidence=0.91,
    )

    robot_request = create_request(
        proposal=robot_proposal,
        identity=verified_identity,
        permissions=frozenset({"robot:move"}),
        estimated_impact=8,
        reversibility=2,
        telemetry_available=True,
        human_approval_available=False,
    )

    robot_result, robot_output = governor.execute_if_allowed(
        robot_request,
        executor=lambda request: {
            "status": "ROBOT_MOVED"
        },
    )

    print_result(
        "SCENARIO 2 - HIGH-IMPACT ROBOTIC REQUEST",
        robot_result,
        robot_output,
    )

    # Scenario 3: Unauthenticated unrestricted API request
    unsafe_proposal = MLGProposal(
        generator_id="MLG-CORE-01",
        request_text="Call an external API with unrestricted authority.",
        action_type=ActionType.API_INTERACTION,
        target="external_financial_api",
        parameters={"operation": "transfer"},
        stated_purpose="Unverified automation",
        confidence=0.77,
    )

    unsafe_identity = ExecutionIdentity(
        actor_id="unknown",
        organization="unknown",
        jurisdiction="",
        role="unknown",
        authenticated=False,
    )

    unsafe_request = create_request(
        proposal=unsafe_proposal,
        identity=unsafe_identity,
        permissions=frozenset({"unrestricted"}),
        estimated_impact=9,
        reversibility=1,
        telemetry_available=False,
        human_approval_available=False,
    )

    unsafe_result, unsafe_output = governor.execute_if_allowed(
        unsafe_request,
        executor=lambda request: {
            "status": "TRANSFER_EXECUTED"
        },
    )

    print_result(
        "SCENARIO 3 - UNAUTHORIZED API REQUEST",
        unsafe_result,
        unsafe_output,
    )


if __name__ == "__main__":
    run_demo()
