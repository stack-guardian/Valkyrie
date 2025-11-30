"""Tests for risk scoring engine."""

import pytest

from valkyrie.scoring import (
    RiskScorer,
    ScoringWeights,
    ScoringThresholds,
    ScoringResult
)


class TestRiskScorer:
    """Test risk scoring logic."""

    def test_clamav_detection_high_score(self):
        """Test ClamAV detection gives high score."""
        weights = ScoringWeights()
        assert weights.clamav_signature == 100

    def test_yara_severity_determination(self):
        """Test YARA severity determination."""
        scorer = RiskScorer()

        # Critical keywords
        assert scorer._determine_yara_severity("BackdoorTrojan") == "critical"
        assert scorer._determine_yara_severity("Ransomware_X") == "critical"

        # High severity
        assert scorer._determine_yara_severity("Worm_Payload") == "high"
        assert scorer._determine_yara_severity("Rootkit_Detector") == "high"

        # Medium severity
        assert scorer._determine_yara_severity("Suspicious_Behavior") == "medium"

        # Default to low
        assert scorer._determine_yara_severity("GenericRule") == "low"

    def test_verdict_determination(self):
        """Test verdict determination from score."""
        thresholds = ScoringThresholds(quarantine=80, review=40)
        scorer = RiskScorer()

        # Quarantine
        assert scorer._determine_verdict(90) == "quarantine"
        assert scorer._determine_verdict(80) == "quarantine"

        # Review
        assert scorer._determine_verdict(60) == "review"
        assert scorer._determine_verdict(40) == "review"

        # Allow
        assert scorer._determine_verdict(30) == "allow"
        assert scorer._determine_verdict(0) == "allow"

    def test_clamav_scoring(self):
        """Test scoring with ClamAV detection."""
        scorer = RiskScorer()

        analysis_results = {
            "clamav": {"found": True, "output": "Trojan.FakeAlert FOUND"}
        }

        result = scorer.calculate_score(analysis_results)
        assert result.total_score == 100
        assert result.verdict == "quarantine"
        assert "clamav" in result.breakdown
        assert result.breakdown["clamav"] == 100

    def test_yara_scoring(self):
        """Test scoring with YARA detections."""
        scorer = RiskScorer()

        analysis_results = {
            "yara": {
                "hits": [
                    "Backdoor_Trojan",
                    "Suspicious_Behavior"
                ]
            }
        }

        result = scorer.calculate_score(analysis_results)
        assert result.total_score == 130  # 90 + 40
        assert result.verdict == "quarantine"
        assert "yara" in result.breakdown

    def test_heuristic_scoring(self):
        """Test scoring with heuristic analysis."""
        scorer = RiskScorer()

        analysis_results = {
            "heuristics": {
                "entropy": {
                    "score": 30,
                    "overall": 7.9
                },
                "packer": {
                    "detected": True,
                    "packer": "UPX"
                },
                "archive": {
                    "is_archive": False,
                    "score": 0
                },
                "file_type": {
                    "score": 0
                }
            }
        }

        result = scorer.calculate_score(analysis_results)
        assert result.total_score == 55  # 30 + 25
        assert result.verdict == "review"

    def test_combined_scoring(self):
        """Test scoring with multiple detection methods."""
        scorer = RiskScorer()

        analysis_results = {
            "clamav": {"found": False},
            "yara": {"hits": ["Suspicious_Payload"]},
            "heuristics": {
                "entropy": {"score": 15, "overall": 7.3},
                "packer": {"detected": False},
                "archive": {"is_archive": False},
                "file_type": {"score": 0}
            }
        }

        result = scorer.calculate_score(analysis_results)
        assert result.total_score == 55  # 40 + 15
        assert result.verdict == "review"
        assert len(result.factors) > 0

    def test_no_detections(self):
        """Test scoring with no detections."""
        scorer = RiskScorer()

        analysis_results = {
            "clamav": {"found": False},
            "yara": {"hits": []},
            "heuristics": {
                "entropy": {"score": 0, "overall": 3.0},
                "packer": {"detected": False},
                "archive": {"is_archive": False},
                "file_type": {"score": 0}
            }
        }

        result = scorer.calculate_score(analysis_results)
        assert result.total_score == 0
        assert result.verdict == "allow"

    def test_custom_thresholds(self):
        """Test scoring with custom thresholds."""
        from valkyrie.config import ValkyrieConfig

        # Create custom config with stricter thresholds
        config = type('Config', (), {
            'scoring': type('Scoring', (), {
                'weights': {
                    'clamav_signature': 100,
                    'yara_critical': 90,
                    'yara_high': 70,
                    'yara_medium': 40,
                    'yara_low': 20,
                    'entropy_high': 30,
                    'entropy_suspicious': 15,
                    'packer_detected': 25,
                    'file_type_mismatch': 20,
                    'archive_bomb': 50,
                    'suspicious_imports': 15
                },
                'thresholds': {
                    'quarantine': 50,
                    'review': 25
                }
            })()
        })()

        scorer = RiskScorer(config)

        analysis_results = {
            "yara": {"hits": ["Suspicious_File"]}
        }

        result = scorer.calculate_score(analysis_results)
        assert result.verdict == "quarantine"  # 40 > 50? No, should be review
        assert result.verdict == "review"

    def test_scoring_result_structure(self):
        """Test ScoringResult structure."""
        result = ScoringResult(
            total_score=50,
            verdict="review",
            factors=[{"test": "factor"}],
            breakdown={"test": 50}
        )

        assert result.total_score == 50
        assert result.verdict == "review"
        assert len(result.factors) == 1
        assert result.breakdown["test"] == 50

    def test_verdict_description(self):
        """Test verdict descriptions."""
        scorer = RiskScorer()

        assert "threat detected" in scorer.get_verdict_description("quarantine").lower()
        assert "suspicious" in scorer.get_verdict_description("review").lower()
        assert "no threats" in scorer.get_verdict_description("allow").lower()


if __name__ == "__main__":
    pytest.main([__file__])
