"""
Intelligent risk scoring engine for Valkyrie.

This module implements multi-factor risk scoring that combines detection engine
results with heuristic analysis to provide accurate threat assessment.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .logger import get_logger
from .config import ValkyrieConfig

logger = get_logger("scoring")


@dataclass
class ScoringWeights:
    """Weights for different detection factors."""
    clamav_signature: int = 100
    yara_critical: int = 90
    yara_high: int = 70
    yara_medium: int = 40
    yara_low: int = 20
    entropy_high: int = 30
    entropy_suspicious: int = 15
    packer_detected: int = 25
    file_type_mismatch: int = 20
    archive_bomb: int = 50
    suspicious_imports: int = 15


@dataclass
class ScoringThresholds:
    """Verdict thresholds."""
    quarantine: int = 80
    review: int = 40


@dataclass
class ScoringResult:
    """Result of risk scoring."""
    total_score: int
    verdict: str  # "quarantine", "review", or "allow"
    factors: List[Dict[str, Any]] = field(default_factory=list)
    breakdown: Dict[str, int] = field(default_factory=dict)


class RiskScorer:
    """
    Intelligent multi-factor risk scoring engine.

    Combines results from multiple detection engines and heuristic analysis
    to provide accurate threat assessment.
    """

    def __init__(self, config: Optional[ValkyrieConfig] = None):
        """
        Initialize scorer with configuration.

        Args:
            config: Valkyrie configuration
        """
        self.config = config
        if config:
            self.weights = ScoringWeights(**config.scoring.weights)
            self.thresholds = ScoringThresholds(**config.scoring.thresholds)
        else:
            self.weights = ScoringWeights()
            self.thresholds = ScoringThresholds()

    def calculate_score(self, analysis_results: Dict[str, Any]) -> ScoringResult:
        """
        Calculate risk score from analysis results.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            ScoringResult with total score, verdict, and breakdown
        """
        score = 0
        factors = []
        breakdown = {}

        # ClamAV scoring
        if "clamav" in analysis_results:
            clamav_result = analysis_results["clamav"]
            if clamav_result.get("found"):
                factor_score = self.weights.clamav_signature
                score += factor_score
                factors.append({
                    "engine": "ClamAV",
                    "description": "Virus signature detected",
                    "score": factor_score,
                    "details": clamav_result.get("output", "")
                })
                breakdown["clamav"] = factor_score
                logger.warning(f"ClamAV detection: {clamav_result.get('output', '')}")

        # YARA scoring
        if "yara" in analysis_results:
            yara_result = analysis_results["yara"]
            hits = yara_result.get("hits", [])

            if hits:
                # Score each YARA hit based on severity
                yara_scores = []
                for hit in hits:
                    # Determine severity from rule name or metadata
                    severity = self._determine_yara_severity(hit)
                    weight = getattr(self.weights, f"yara_{severity}", self.weights.yara_low)
                    yara_scores.append(weight)
                    score += weight
                    factors.append({
                        "engine": "YARA",
                        "rule": hit,
                        "severity": severity,
                        "score": weight,
                        "description": f"YARA rule matched: {hit}"
                    })

                breakdown["yara"] = sum(yara_scores)
                logger.info(f"YARA hits: {len(hits)} rules matched")

        # Heuristic scoring
        if "heuristics" in analysis_results:
            heuristics = analysis_results["heuristics"]

            # Entropy scoring
            if "entropy" in heuristics:
                entropy = heuristics["entropy"]
                entropy_score = entropy.get("score", 0)
                if entropy_score > 0:
                    score += entropy_score
                    factors.append({
                        "engine": "Heuristic",
                        "test": "entropy",
                        "description": f"High entropy detected ({entropy.get('overall', 0):.2f})",
                        "score": entropy_score,
                        "details": entropy
                    })
                    breakdown["entropy"] = entropy_score

            # Packer detection scoring
            if "packer" in heuristics:
                packer = heuristics["packer"]
                if packer.get("detected"):
                    packer_score = self.weights.packer_detected
                    score += packer_score
                    factors.append({
                        "engine": "Heuristic",
                        "test": "packer",
                        "description": f"Packer detected: {packer.get('packer', 'Unknown')}",
                        "score": packer_score,
                        "details": packer
                    })
                    breakdown["packer"] = packer_score

            # Archive inspection scoring
            if "archive" in heuristics:
                archive = heuristics["archive"]
                if archive.get("is_archive"):
                    archive_score = archive.get("score", 0)
                    if archive_score > 0:
                        score += archive_score
                        factors.append({
                            "engine": "Heuristic",
                            "test": "archive",
                            "description": "Suspicious archive characteristics",
                            "score": archive_score,
                            "details": archive
                        })
                        breakdown["archive"] = archive_score

            # File type validation scoring
            if "file_type" in heuristics:
                file_type = heuristics["file_type"]
                file_type_score = file_type.get("score", 0)
                if file_type_score > 0:
                    score += file_type_score
                    factors.append({
                        "engine": "Heuristic",
                        "test": "file_type",
                        "description": "File type anomalies detected",
                        "score": file_type_score,
                        "details": file_type
                    })
                    breakdown["file_type"] = file_type_score

        # Determine verdict
        verdict = self._determine_verdict(score)

        return ScoringResult(
            total_score=score,
            verdict=verdict,
            factors=factors,
            breakdown=breakdown
        )

    def _determine_yara_severity(self, yara_hit: str) -> str:
        """
        Determine severity of YARA hit.

        Args:
            yara_hit: YARA rule name or match description

        Returns:
            Severity level (critical, high, medium, low)
        """
        # Simplified severity determination
        # In production, this would parse YARA rule metadata
        yara_hit_lower = yara_hit.lower()

        # Critical indicators
        critical_keywords = ["backdoor", "trojan", "ransomware", "loader", "dropper"]
        if any(keyword in yara_hit_lower for keyword in critical_keywords):
            return "critical"

        # High severity indicators
        high_keywords = ["worm", "virus", "rootkit", "exploit"]
        if any(keyword in yara_hit_lower for keyword in high_keywords):
            return "high"

        # Medium severity indicators
        medium_keywords = ["suspect", "malicious", "pua", "unwanted"]
        if any(keyword in yara_hit_lower for keyword in medium_keywords):
            return "medium"

        # Default to low
        return "low"

    def _determine_verdict(self, score: int) -> str:
        """
        Determine verdict based on score.

        Args:
            score: Total risk score

        Returns:
            Verdict string
        """
        if score >= self.thresholds.quarantine:
            return "quarantine"
        elif score >= self.thresholds.review:
            return "review"
        else:
            return "allow"

    def get_verdict_description(self, verdict: str) -> str:
        """
        Get human-readable verdict description.

        Args:
            verdict: Verdict string

        Returns:
            Description text
        """
        descriptions = {
            "quarantine": "Threat detected - File moved to quarantine",
            "review": "Suspicious - Requires manual review",
            "allow": "No threats detected - File allowed"
        }
        return descriptions.get(verdict, "Unknown verdict")

    def print_scoring_summary(self, result: ScoringResult) -> None:
        """
        Print a formatted summary of scoring results.

        Args:
            result: ScoringResult to summarize
        """
        print("\n" + "="*60)
        print(f"Risk Assessment Summary")
        print("="*60)
        print(f"Total Score: {result.total_score}")
        print(f"Verdict: {result.verdict.upper()}")
        print(f"\nScoring Breakdown:")
        for factor, score in result.breakdown.items():
            print(f"  {factor:20s} +{score:3d}")

        if result.factors:
            print(f"\nDetection Details:")
            for i, factor in enumerate(result.factors, 1):
                print(f"  {i}. {factor['engine']:10s} - {factor['description']} (+{factor['score']})")

        print("="*60 + "\n")
