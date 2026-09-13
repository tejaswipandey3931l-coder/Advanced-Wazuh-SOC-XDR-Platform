"""
Deterministic Multi-Provider Threat Intelligence Consensus Engine.
Derives explainable verdicts without opaque provider weights or universal threat scores.
"""

from __future__ import annotations

from typing import Iterable

from threat_intel.models import (
    EnrichmentConsensus,
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatSeverity,
    ThreatVerdict,
)


class ConsensusEngine:
    """
    Evaluates multi-provider evidence and derives transparent consensus according to
    the deterministic Phase 4 Revision 4 rules.
    """

    @classmethod
    def evaluate(
        cls,
        observable: NormalizedObservable,
        results: Iterable[ProviderResult],
    ) -> EnrichmentConsensus:
        results_list = list(results)
        providers_evaluated = [r.provider for r in results_list]

        # Partition results into successful evaluations (R) and failures (F)
        # SUCCESS and NOT_FOUND count as successful evaluations of the observable.
        successful_results: list[ProviderResult] = []
        failed_results: list[ProviderResult] = []

        for r in results_list:
            if r.status in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND):
                successful_results.append(r)
            else:
                failed_results.append(r)

        failed_providers = [r.provider for r in failed_results]

        # Case B: All queried providers failed (R = empty, F != empty)
        if not successful_results and failed_results:
            reasons = [f"{r.provider} ({r.status.value}: {r.error_message or 'error'})" for r in failed_results]
            rationale = f"All {len(failed_results)} queried provider(s) failed: {'; '.join(reasons)}."
            return EnrichmentConsensus(
                verdict=ThreatVerdict.UNKNOWN,
                provider_confidence=None,
                derived_heuristic_confidence=None,
                severity=None,
                providers_evaluated=providers_evaluated,
                failed_providers=failed_providers,
                agreeing_providers=[],
                conflicting_providers=[],
                rationale=rationale,
                is_derived=True,
            )

        # Case: No providers were evaluated at all
        if not successful_results and not failed_results:
            return EnrichmentConsensus(
                verdict=ThreatVerdict.UNKNOWN,
                provider_confidence=None,
                derived_heuristic_confidence=None,
                severity=None,
                providers_evaluated=[],
                failed_providers=[],
                agreeing_providers=[],
                conflicting_providers=[],
                rationale="No threat intelligence providers were applicable or queried.",
                is_derived=True,
            )

        # Analyze successful evaluations (R)
        malicious_results: list[ProviderResult] = []
        suspicious_results: list[ProviderResult] = []
        clean_results: list[ProviderResult] = []
        not_found_results: list[ProviderResult] = []

        for r in successful_results:
            if r.verdict == ThreatVerdict.MALICIOUS:
                malicious_results.append(r)
            elif r.verdict == ThreatVerdict.SUSPICIOUS:
                suspicious_results.append(r)
            elif r.verdict == ThreatVerdict.BENIGN:
                clean_results.append(r)
            elif r.status == ProviderStatus.NOT_FOUND:
                not_found_results.append(r)

        # Helper to get effective confidence
        def get_confidence(r: ProviderResult) -> float:
            if r.provider_confidence is not None:
                return r.provider_confidence
            if r.derived_heuristic_confidence is not None:
                return r.derived_heuristic_confidence
            return 0.5

        # Check for high-confidence malicious and high-confidence benign (requires actual clean evidence)
        high_conf_malicious = [r for r in malicious_results if get_confidence(r) >= 0.70]
        high_conf_benign = [r for r in clean_results if get_confidence(r) >= 0.70]

        # Case D: CONFLICT - High-confidence MALICIOUS vs High-confidence confirmed BENIGN
        if high_conf_malicious and high_conf_benign:
            mal_names = [r.provider for r in high_conf_malicious]
            ben_names = [r.provider for r in high_conf_benign]
            conflicting = mal_names + ben_names
            rationale = (
                f"Contradictory intelligence detected between providers: "
                f"{', '.join(mal_names)} reported high-confidence MALICIOUS, whereas "
                f"{', '.join(ben_names)} reported confirmed BENIGN."
            )
            if failed_providers:
                rationale += f" Additional provider(s) failed: {', '.join(failed_providers)}."

            return EnrichmentConsensus(
                verdict=ThreatVerdict.CONFLICT,
                provider_confidence=None,
                derived_heuristic_confidence=None,
                severity=ThreatSeverity.MEDIUM,
                providers_evaluated=providers_evaluated,
                failed_providers=failed_providers,
                agreeing_providers=[],
                conflicting_providers=conflicting,
                rationale=rationale,
                is_derived=True,
            )

        # Case E: MALICIOUS without confirmed high-confidence BENIGN
        if malicious_results:
            agreeing = [r.provider for r in malicious_results]
            confidences = [get_confidence(r) for r in malicious_results]
            max_conf = max(confidences) if confidences else None

            # Determine highest severity
            severities = [r.severity for r in malicious_results if r.severity]
            sev_order = [
                ThreatSeverity.NONE,
                ThreatSeverity.LOW,
                ThreatSeverity.MEDIUM,
                ThreatSeverity.HIGH,
                ThreatSeverity.CRITICAL,
            ]
            max_sev = max(severities, key=lambda s: sev_order.index(s)) if severities else ThreatSeverity.HIGH

            rationale = f"Classified MALICIOUS based on reports from {', '.join(agreeing)}."
            if suspicious_results:
                rationale += f" Corroborated by suspicious findings from {', '.join(r.provider for r in suspicious_results)}."
            if not_found_results:
                rationale += f" No threat records found by: {', '.join(r.provider for r in not_found_results)}."
            if failed_providers:
                rationale += f" Failed providers: {', '.join(failed_providers)}."

            # Determine if native or derived
            native_confs = [r.provider_confidence for r in malicious_results if r.provider_confidence is not None]
            derived_confs = [r.derived_heuristic_confidence for r in malicious_results if r.derived_heuristic_confidence is not None]

            return EnrichmentConsensus(
                verdict=ThreatVerdict.MALICIOUS,
                provider_confidence=max(native_confs) if native_confs else None,
                derived_heuristic_confidence=max(derived_confs) if derived_confs and not native_confs else None,
                severity=max_sev,
                providers_evaluated=providers_evaluated,
                failed_providers=failed_providers,
                agreeing_providers=agreeing,
                conflicting_providers=[],
                rationale=rationale,
                is_derived=True,
            )

        # Case F: SUSPICIOUS without MALICIOUS or confirmed BENIGN
        if suspicious_results:
            agreeing = [r.provider for r in suspicious_results]
            confidences = [get_confidence(r) for r in suspicious_results]
            max_conf = max(confidences) if confidences else None

            severities = [r.severity for r in suspicious_results if r.severity]
            sev_order = [
                ThreatSeverity.NONE,
                ThreatSeverity.LOW,
                ThreatSeverity.MEDIUM,
                ThreatSeverity.HIGH,
                ThreatSeverity.CRITICAL,
            ]
            max_sev = max(severities, key=lambda s: sev_order.index(s)) if severities else ThreatSeverity.MEDIUM

            rationale = f"Classified SUSPICIOUS based on reports from {', '.join(agreeing)}."
            if not_found_results:
                rationale += f" No threat records found by: {', '.join(r.provider for r in not_found_results)}."
            if failed_providers:
                rationale += f" Failed providers: {', '.join(failed_providers)}."

            return EnrichmentConsensus(
                verdict=ThreatVerdict.SUSPICIOUS,
                provider_confidence=max_conf,
                derived_heuristic_confidence=None,
                severity=max_sev,
                providers_evaluated=providers_evaluated,
                failed_providers=failed_providers,
                agreeing_providers=agreeing,
                conflicting_providers=[],
                rationale=rationale,
                is_derived=True,
            )

        # Cases A & C: All successful evaluations reported BENIGN (clean) or NOT_FOUND
        # Case A: All evaluating providers returned clean or NOT_FOUND -> consensus BENIGN
        # Case C: At least one clean/NOT_FOUND + provider failure -> consensus BENIGN with failure in failed_providers
        agreeing = [r.provider for r in successful_results]
        clean_names = [r.provider for r in clean_results]
        not_found_names = [r.provider for r in not_found_results]

        if clean_names and not not_found_names:
            confidences = [get_confidence(r) for r in clean_results]
            provider_conf = round(sum(confidences) / len(confidences), 4)
            derived_conf = None
            rationale = f"Classified BENIGN: All {len(agreeing)} evaluating provider(s) ({', '.join(agreeing)}) confirmed clean/benign evidence."
        elif clean_names and not_found_names:
            confidences = [get_confidence(r) for r in clean_results]
            provider_conf = round(sum(confidences) / len(confidences), 4)
            derived_conf = None
            rationale = (
                f"Classified BENIGN: {', '.join(clean_names)} provided confirmed clean evidence; "
                f"{', '.join(not_found_names)} found no threat records (NOT_FOUND). "
                f"Consensus BENIGN reflects clean evidence and lack of negative intelligence."
            )
        else:
            # Only NOT_FOUND results: Absence of threat records across all evaluating providers
            provider_conf = None
            derived_conf = 0.50
            rationale = (
                f"Consensus verdict BENIGN derived from absence of threat records across evaluating provider(s) "
                f"({', '.join(not_found_names)}). Note: BENIGN is a consensus-derived state based on lack of "
                f"threat records (NOT_FOUND) and NOT provider proof of objective benignness."
            )

        if failed_providers:
            rationale += f" Note that {len(failed_providers)} provider(s) failed during evaluation: {', '.join(failed_providers)}."

        return EnrichmentConsensus(
            verdict=ThreatVerdict.BENIGN,
            provider_confidence=provider_conf,
            derived_heuristic_confidence=derived_conf,
            severity=ThreatSeverity.NONE,
            providers_evaluated=providers_evaluated,
            failed_providers=failed_providers,
            agreeing_providers=agreeing,
            conflicting_providers=[],
            rationale=rationale,
            is_derived=True,
        )
