"""
Attack Engine
=============
Orchestrates execution of payloads against a target LLM endpoint.
Manages concurrency, progress tracking, and result collection.

Each attack run:
1. Loads payloads for the selected categories
2. Sends each payload via the LLM client
3. Passes responses to the analyzer
4. Scores results and returns AttackResult objects
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.client import LLMClient, LLMRequest, LLMResponse
from core.analyzer import analyze_response, AnalysisResult
from core.scoring import (
    AttackCategory,
    RiskScore,
    compute_risk_score,
    aggregate_scan_score,
)
from payloads.loader import Payload, load_payloads

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Result of a single payload execution."""
    payload: Payload
    llm_response: LLMResponse
    analysis: AnalysisResult
    risk_score: RiskScore
    timestamp: float = field(default_factory=time.time)


@dataclass
class ScanResult:
    """Complete result set from a full scan."""
    target_url: str
    model: str
    provider: str
    start_time: float
    end_time: float
    attack_results: list[AttackResult]
    aggregate_risk: Optional[RiskScore]
    total_payloads: int
    successful_attacks: int
    categories_tested: list[str]

    @property
    def duration_seconds(self) -> float:
        return round(self.end_time - self.start_time, 2)

    @property
    def success_rate(self) -> float:
        if not self.total_payloads:
            return 0.0
        return round(self.successful_attacks / self.total_payloads, 4)


class AttackEngine:
    """
    Core engine that runs the full attack suite against a target LLM.

    Args:
        client: Configured LLMClient pointing at the target.
        payload_dir: Path to directory containing payloads.yaml (optional override).
        categories: Subset of AttackCategory to test. None = all categories.
        max_workers: Thread concurrency for parallel payload execution.
        system_prompt: Optional system prompt to inject for context testing.
        progress_callback: Optional callable(current, total, result) for live progress.
    """

    def __init__(
        self,
        client: LLMClient,
        payload_dir: Optional[str] = None,
        categories: Optional[list[AttackCategory]] = None,
        max_workers: int = 4,
        system_prompt: Optional[str] = None,
        progress_callback: Optional[Callable] = None,
    ):
        self.client = client
        self.payload_dir = payload_dir
        self.categories = categories or list(AttackCategory)
        self.max_workers = max_workers
        self.system_prompt = system_prompt
        self.progress_callback = progress_callback

    def run(self) -> ScanResult:
        """
        Execute the full attack suite and return a ScanResult.

        Payloads are loaded from the YAML library + built-in defaults.
        Execution is parallelized with thread pool.
        """
        start_time = time.time()

        payloads = load_payloads(
            payload_dir=self.payload_dir,
            categories=self.categories,
        )

        logger.info(
            f"Starting scan: {len(payloads)} payloads across "
            f"{len(self.categories)} categories"
        )

        attack_results: list[AttackResult] = []
        completed = 0
        total = len(payloads)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._execute_payload, payload): payload
                for payload in payloads
            }

            for future in as_completed(futures):
                payload = futures[future]
                try:
                    result = future.result()
                    attack_results.append(result)
                    completed += 1

                    if self.progress_callback:
                        self.progress_callback(completed, total, result)

                    logger.debug(
                        f"[{completed}/{total}] {payload.id} → "
                        f"{'SUCCESS' if result.analysis.success else 'FAILED'} "
                        f"(conf={result.analysis.confidence:.2f})"
                    )
                except Exception as e:
                    logger.error(f"Error executing payload {payload.id}: {e}")
                    completed += 1

        successful = [r for r in attack_results if r.analysis.success]

        risk_scores = [r.risk_score for r in successful]
        aggregate = aggregate_scan_score(risk_scores)

        categories_tested = list({r.payload.category for r in attack_results})

        end_time = time.time()

        return ScanResult(
            target_url=self.client.base_url,
            model=self.client.model,
            provider=self.client.provider.value,
            start_time=start_time,
            end_time=end_time,
            attack_results=attack_results,
            aggregate_risk=aggregate,
            total_payloads=total,
            successful_attacks=len(successful),
            categories_tested=[c.value for c in categories_tested],
        )

    def _execute_payload(self, payload: Payload) -> AttackResult:
        """
        Execute a single payload and return an AttackResult.

        Constructs the LLM request, sends it, analyzes the response,
        and computes a risk score.
        """
        # Build message list — inject the payload as user turn
        messages = [{"role": "user", "content": payload.content}]

        request = LLMRequest(
            messages=messages,
            system_prompt=payload.override_system or self.system_prompt,
            temperature=0.0,   # Deterministic for consistent results
            max_tokens=512,
        )

        llm_response = self.client.complete(request)

        # If API call failed, return a failure result
        if llm_response.error:
            analysis = AnalysisResult(
                success=False,
                confidence=0.0,
                exposure_type="none",
                signals_triggered=[f"API error: {llm_response.error}"],
                raw_response="",
                truncated_response="",
            )
            risk_score = compute_risk_score(payload.category, 0.0, "none")
            return AttackResult(
                payload=payload,
                llm_response=llm_response,
                analysis=analysis,
                risk_score=risk_score,
            )

        analysis = analyze_response(
            response=llm_response.content,
            category=payload.category,
            system_prompt_hint=self.system_prompt,
        )

        risk_score = compute_risk_score(
            category=payload.category,
            success_confidence=analysis.confidence,
            exposure_type=analysis.exposure_type,
        )

        return AttackResult(
            payload=payload,
            llm_response=llm_response,
            analysis=analysis,
            risk_score=risk_score,
        )
