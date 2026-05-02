"""
Unit Tests for PUF Modeling Defense

Tests the machine learning-based defense system for evaluating Physical
Unclonable Function (PUF) resilience against modeling attacks.

Test Coverage:
    - Defense system initialization
    - Challenge-response conversion
    - PUF resilience evaluation
    - Attack simulation
    - Mitigation strategy generation
    - Comparative analysis
    - Report generation
    - Edge cases and error handling
"""
import sys
import os
#  look one directory up for the 'src' folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import numpy as np
import tempfile
import os
from src.ai.puf_modeling_defense import PUFModelingDefense


class TestPUFModelingDefenseInitialization:
    """Test defense system initialization."""
    
    def test_default_initialization(self):
        """Test defense with default parameters."""
        defense = PUFModelingDefense()
        
        assert defense.test_size == 0.3
        assert defense.random_state == 42
        assert len(defense.attack_models) == 4
    
    def test_custom_initialization(self):
        """Test defense with custom parameters."""
        defense = PUFModelingDefense(
            test_size=0.2,
            random_state=123
        )
        
        assert defense.test_size == 0.2
        assert defense.random_state == 123
    
    def test_attack_models_present(self):
        """Test that all attack models are initialized."""
        defense = PUFModelingDefense()
        expected_models = [
            'Random Forest',
            'Gradient Boosting',
            'SVM',
            'Neural Network'
        ]
        
        for model_name in expected_models:
            assert model_name in defense.attack_models


class TestChallengeResponseConversion:
    """Test challenge-response conversion utilities."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense()
    
    def test_challenge_to_features(self):
        """Test challenge integer to binary conversion."""
        challenge = 42
        features = self.defense._challenge_to_features(challenge, num_bits=8)
        
        assert len(features) == 8
        assert all(bit in [0, 1] for bit in features)
        # 42 in binary is 00101010
        expected = np.array([0, 0, 1, 0, 1, 0, 1, 0])
        np.testing.assert_array_equal(features, expected)
    
    def test_challenge_to_features_32bit(self):
        """Test 32-bit challenge conversion."""
        challenge = 1
        features = self.defense._challenge_to_features(challenge, num_bits=32)
        
        assert len(features) == 32
        assert features[-1] == 1  # LSB should be 1
        assert sum(features) == 1  # Only one bit set
    
    def test_response_to_binary(self):
        """Test response bytes to binary conversion."""
        response = bytes([0])
        binary = self.defense._response_to_binary(response)
        assert binary == 0
        
        response = bytes([1])
        binary = self.defense._response_to_binary(response)
        assert binary == 1
        
        response = bytes([255])
        binary = self.defense._response_to_binary(response)
        assert binary == 1  # 255 % 2 = 1


class TestPUFResilienceEvaluation:
    """Test PUF resilience evaluation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense(random_state=42)
        np.random.seed(42)
    
    def _generate_puf_data(self, count=1000, predictable=False):
        """Generate synthetic PUF challenge-response pairs."""
        challenges = [np.random.randint(0, 2**31-1) for _ in range(count)]
        
        if predictable:
            # Highly predictable responses (vulnerable PUF)
            responses = [
                bytes([sum(int(b) for b in format(c, '032b')) % 2])
                for c in challenges
            ]
        else:
            # Random responses (resilient PUF)
            responses = [bytes([np.random.randint(0, 2)]) for _ in challenges]
        
        return challenges, responses
    
    def test_evaluate_resilient_puf(self):
        """Test evaluation of resilient PUF."""
        challenges, responses = self._generate_puf_data(
            count=1000,
            predictable=False
        )
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Test Resilient"
        )
        
        assert 'overall_score' in results
        assert 'attack_results' in results
        assert 'mitigation_strategies' in results
        assert results['overall_score'] > 30  # Should be reasonably resilient
    
    def test_evaluate_vulnerable_puf(self):
        """Test evaluation of vulnerable PUF."""
        challenges, responses = self._generate_puf_data(
            count=1000,
            predictable=True
        )
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Test Vulnerable"
        )
        
        assert results['overall_score'] < 60  # Should be vulnerable
        
        # Check that attacks succeeded
        for attack_name, metrics in results['attack_results'].items():
            if 'accuracy' in metrics:
                assert metrics['accuracy'] > 0.7  # High attack accuracy
    
    def test_evaluate_insufficient_data(self):
        """Test evaluation with insufficient data."""
        challenges = list(range(50))
        responses = [bytes([i % 2]) for i in range(50)]
        
        with pytest.raises(ValueError, match="at least 100"):
            self.defense.evaluate_puf_resilience(
                challenges=challenges,
                responses=responses
            )
    
    def test_evaluate_mismatched_data(self):
        """Test evaluation with mismatched challenge-response pairs."""
        challenges = list(range(100))
        responses = [bytes([i % 2]) for i in range(50)]  # Wrong length
        
        with pytest.raises(ValueError, match="same length"):
            self.defense.evaluate_puf_resilience(
                challenges=challenges,
                responses=responses
            )
    
    def test_attack_results_structure(self):
        """Test that attack results have correct structure."""
        challenges, responses = self._generate_puf_data(count=1000)
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses
        )
        
        for attack_name, metrics in results['attack_results'].items():
            assert 'accuracy' in metrics or 'error' in metrics
            if 'accuracy' in metrics:
                assert 'precision' in metrics
                assert 'recall' in metrics
                assert 'f1_score' in metrics
                assert 'resilience_score' in metrics
                assert 'vulnerable' in metrics
    
    def test_resilience_score_range(self):
        """Test that resilience scores are in valid range."""
        challenges, responses = self._generate_puf_data(count=1000)
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses
        )
        
        assert 0 <= results['overall_score'] <= 100
        
        for metrics in results['attack_results'].values():
            if 'resilience_score' in metrics:
                assert 0 <= metrics['resilience_score'] <= 100


class TestMitigationStrategies:
    """Test mitigation strategy generation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense(random_state=42)
        np.random.seed(42)
    
    def test_mitigation_for_vulnerable_puf(self):
        """Test mitigation strategies for vulnerable PUF."""
        challenges = [i for i in range(1000)]
        responses = [bytes([sum(int(b) for b in format(c, '032b')) % 2]) 
                    for c in challenges]
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="SRAM"
        )
        
        strategies = results['mitigation_strategies']
        
        assert len(strategies) > 0
        assert any('GOOD' in s or 'WARNING' in s for s in strategies)
        assert any('SRAM' in s for s in strategies)  # PUF-specific strategies
    
    def test_mitigation_for_resilient_puf(self):
        """Test mitigation strategies for resilient PUF."""
        challenges = [np.random.randint(0, 2**31-1) for _ in range(1000)]
        responses = [bytes([np.random.randint(0, 2)]) for _ in range(1000)]
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Arbiter"
        )
        
        strategies = results['mitigation_strategies']
        
        assert len(strategies) > 0
        # Should have positive feedback for good resilience
        assert any('GOOD' in s or 'strong' in s for s in strategies)
    
    def test_puf_specific_strategies(self):
        """Test that PUF-specific strategies are generated."""
        challenges = [i for i in range(1000)]
        responses = [bytes([i % 2]) for i in range(1000)]
        
        # Test SRAM PUF
        sram_results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="SRAM"
        )
        assert any('SRAM' in s for s in sram_results['mitigation_strategies'])
        
        # Test Ring Oscillator PUF
        ro_results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Ring Oscillator"
        )
        assert any('oscillator' in s.lower() 
                  for s in ro_results['mitigation_strategies'])
        
        # Test Arbiter PUF
        arbiter_results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Arbiter"
        )
        assert any('arbiter' in s.lower() or 'XOR' in s
                  for s in arbiter_results['mitigation_strategies'])


class TestComparativePUFAnalysis:
    """Test comparative PUF analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense(random_state=42)
        np.random.seed(42)
    
    def _generate_puf_evaluation(self, puf_type, score):
        """Generate a mock PUF evaluation result."""
        return {
            'puf_type': puf_type,
            'overall_score': score,
            'attack_results': {},
            'mitigation_strategies': []
        }
    
    def test_compare_multiple_pufs(self):
        """Test comparison of multiple PUF implementations."""
        evaluations = [
            self._generate_puf_evaluation('SRAM', 10.0),
            self._generate_puf_evaluation('Ring Oscillator', 25.0),
            self._generate_puf_evaluation('Arbiter', 45.0)
        ]
        
        comparison = self.defense.compare_pufs(evaluations)
        
        assert comparison['num_pufs_compared'] == 3
        assert comparison['best_puf']['type'] == 'Arbiter'
        assert comparison['best_puf']['score'] == 45.0
        assert comparison['worst_puf']['type'] == 'SRAM'
        assert comparison['worst_puf']['score'] == 10.0
    
    def test_compare_rankings(self):
        """Test that PUFs are ranked correctly."""
        evaluations = [
            self._generate_puf_evaluation('PUF_A', 30.0),
            self._generate_puf_evaluation('PUF_B', 50.0),
            self._generate_puf_evaluation('PUF_C', 20.0)
        ]
        
        comparison = self.defense.compare_pufs(evaluations)
        rankings = comparison['rankings']
        
        assert len(rankings) == 3
        assert rankings[0]['type'] == 'PUF_B'  # Highest score
        assert rankings[1]['type'] == 'PUF_A'
        assert rankings[2]['type'] == 'PUF_C'  # Lowest score
    
    def test_compare_statistics(self):
        """Test comparison statistics calculation."""
        evaluations = [
            self._generate_puf_evaluation('PUF_1', 20.0),
            self._generate_puf_evaluation('PUF_2', 40.0),
            self._generate_puf_evaluation('PUF_3', 60.0)
        ]
        
        comparison = self.defense.compare_pufs(evaluations)
        
        assert comparison['average_score'] == 40.0
        assert comparison['score_std'] > 0
    
    def test_compare_empty_list(self):
        """Test comparison with empty list raises error."""
        with pytest.raises(ValueError, match="at least one"):
            self.defense.compare_pufs([])


class TestReportGeneration:
    """Test security report generation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense(random_state=42)
        self.temp_dir = tempfile.mkdtemp()
        np.random.seed(42)
    
    def _generate_mock_evaluation(self):
        """Generate a mock evaluation result."""
        return {
            'puf_type': 'Test PUF',
            'overall_score': 35.5,
            'num_samples': 1000,
            'attack_results': {
                'Random Forest': {
                    'accuracy': 0.65,
                    'precision': 0.64,
                    'recall': 0.66,
                    'f1_score': 0.65,
                    'resilience_score': 35.0,
                    'vulnerable': False
                }
            },
            'mitigation_strategies': [
                'Increase PUF complexity',
                'Implement challenge rotation'
            ]
        }
    
    def test_generate_report_string(self):
        """Test report generation as string."""
        evaluation = self._generate_mock_evaluation()
        report = self.defense.generate_report(evaluation)
        
        assert isinstance(report, str)
        assert 'Test PUF' in report
        assert '35.5' in report or '35.50' in report
        assert 'Random Forest' in report
        assert 'MITIGATION STRATEGIES' in report
    
    def test_generate_report_to_file(self):
        """Test report generation to file."""
        evaluation = self._generate_mock_evaluation()
        report_path = os.path.join(self.temp_dir, 'test_report.txt')
        
        report = self.defense.generate_report(evaluation, filepath=report_path)
        
        assert os.path.exists(report_path)
        
        with open(report_path, 'r') as f:
            file_content = f.read()
        
        assert file_content == report
    
    def test_report_contains_all_sections(self):
        """Test that report contains all required sections."""
        evaluation = self._generate_mock_evaluation()
        report = self.defense.generate_report(evaluation)
        
        required_sections = [
            'PUF MODELING ATTACK RESILIENCE REPORT',
            'PUF Type:',
            'Overall Resilience Score:',
            'ATTACK RESULTS:',
            'MITIGATION STRATEGIES:'
        ]
        
        for section in required_sections:
            assert section in report


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense()
    
    def test_all_same_responses(self):
        """Test handling of PUF with all same responses."""
        challenges = list(range(1000))
        responses = [bytes([1])] * 1000  # All same
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Constant PUF"
        )
        
        # Should complete without error
        assert 'overall_score' in results
        # Score should be very low (highly vulnerable)
        assert results['overall_score'] < 10
    
    def test_alternating_responses(self):
        """Test handling of perfectly alternating responses."""
        challenges = list(range(1000))
        responses = [bytes([i % 2]) for i in range(1000)]
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Alternating PUF"
        )
        
        assert 'overall_score' in results
    
    def test_minimal_data(self):
        """Test with minimal acceptable data."""
        challenges = list(range(100))
        responses = [bytes([i % 2]) for i in range(100)]
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses
        )
        
        assert 'overall_score' in results
        assert len(results['attack_results']) == 4
    
    def test_large_challenge_values(self):
        """Test with large challenge values."""
        challenges = [2**30 - i for i in range(1000)]
        responses = [bytes([i % 2]) for i in range(1000)]
        
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses
        )
        
        assert 'overall_score' in results


class TestIntegration:
    """Integration tests for complete workflows."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.defense = PUFModelingDefense(random_state=42)
        np.random.seed(42)
    
    def test_complete_evaluation_workflow(self):
        """Test complete evaluation workflow."""
        # Generate data
        challenges = [np.random.randint(0, 2**31-1) for _ in range(1000)]
        responses = [bytes([np.random.randint(0, 2)]) for _ in range(1000)]
        
        # Evaluate
        results = self.defense.evaluate_puf_resilience(
            challenges=challenges,
            responses=responses,
            puf_type="Integration Test PUF"
        )
        
        # Generate report
        report = self.defense.generate_report(results)
        
        # Verify complete workflow
        assert 'overall_score' in results
        assert len(results['mitigation_strategies']) > 0
        assert 'Integration Test PUF' in report
    
    def test_multiple_puf_comparison_workflow(self):
        """Test workflow for comparing multiple PUFs."""
        evaluations = []
        
        for i, puf_type in enumerate(['SRAM', 'Ring Oscillator', 'Arbiter']):
            challenges = [np.random.randint(0, 2**31-1) for _ in range(500)]
            responses = [bytes([np.random.randint(0, 2)]) for _ in range(500)]
            
            result = self.defense.evaluate_puf_resilience(
                challenges=challenges,
                responses=responses,
                puf_type=puf_type
            )
            evaluations.append(result)
        
        # Compare
        comparison = self.defense.compare_pufs(evaluations)
        
        assert comparison['num_pufs_compared'] == 3
        assert 'best_puf' in comparison
        assert 'rankings' in comparison


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

# Made with Bob
