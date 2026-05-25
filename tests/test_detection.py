"""Tests for secret detection"""

import unittest
from src.detectors.secret_detector import SecretDetector


class TestSecretDetection(unittest.TestCase):

      def setUp(self):
                self.detector = SecretDetector()

      def test_aws_key_detection(self):
                content = "AWS_KEY=AKIA1234567890ABCDEF"
                findings = self.detector.detect_by_regex(content)
                self.assertGreater(len(findings), 0)

      def test_entropy_detection(self):
                high_entropy_string = "aK9$mL2@vP7#xQ4&bZ1!cD6%"
                is_secret, entropy = self.detector.detect_by_entropy(high_entropy_string)
                self.assertTrue(is_secret)
                self.assertGreater(entropy, 4.5)

      def test_low_entropy_string(self):
                normal_string = "helloworld"
                is_secret, entropy = self.detector.detect_by_entropy(normal_string)
                # Short low-entropy strings should not be flagged
                self.assertLessEqual(entropy, 4.5)

      def test_github_token_detection(self):
                content = "TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
                findings = self.detector.detect_by_regex(content)
                github_findings = [f for f in findings if f['type'] == 'github_token']
                self.assertGreater(len(github_findings), 0)


if __name__ == '__main__':
      unittest.main()
  
