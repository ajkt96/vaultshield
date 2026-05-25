"""
VAULTSHIELD Secret Detection Engine
Multi-method detection: Regex + Entropy + ML
"""

import re
import math
from typing import List, Dict, Tuple
from enum import Enum


class SecretType(Enum):
      AWS_KEY = "AWS Access Key"
      PRIVATE_KEY = "Private Key"
      API_KEY = "API Key"
      DATABASE_PASSWORD = "Database Password"
      GITHUB_TOKEN = "GitHub Token"
      JWT = "JWT Token"


class SecretDetector:
      """Detects secrets using multiple methods"""

    def __init__(self):
              self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, str]:
              """Load regex patterns for secret detection"""
              return {
                  'aws_key': r'AKIA[0-9A-Z]{16}',
                  'github_token': r'ghp_[0-9a-zA-Z]{36}',
                  'private_key': r'-----BEGIN.*PRIVATE KEY-----',
                  'api_key': r'(api[_-]?key|apikey)\s*[=:]\s*["\']?([0-9a-zA-Z]{20,})',
                  'jwt': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
              }

    def detect_by_regex(self, content: str) -> List[Dict]:
              """Detect secrets using regex patterns"""
              findings = []
              for secret_type, pattern in self.patterns.items():
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                              findings.append({
                                                                    'type': secret_type,
                                                                    'method': 'regex',
                                                                    'confidence': 0.95,
                                                                    'value': match.group(0)[:20] + '***'
                                              })
                                      return findings

    def detect_by_entropy(self, value: str) -> Tuple[bool, float]:
              """Detect high-entropy strings (passwords, keys)"""
              if len(value) < 8:
                            return False, 0.0

              entropy = 0
              for char in set(value):
                            p = value.count(char) / len(value)
                            entropy -= p * math.log2(p)

              is_secret = entropy > 4.5
              return is_secret, entropy

    def detect_secrets(self, content: str) -> List[Dict]:
              """Multi-method secret detection"""
              secrets = []

        regex_findings = self.detect_by_regex(content)
        secrets.extend(regex_findings)

        for word in content.split():
                      if len(word) > 15 and not word.startswith('http'):
                                        is_secret, entropy = self.detect_by_entropy(word)
                                        if is_secret:
                                                              secrets.append({
                                                                                        'type': 'high_entropy_string',
                                                                                        'method': 'entropy',
                                                                                        'confidence': 0.7,
                                                                                        'entropy': entropy,
                                                                                        'value': word[:20] + '***'
                                                              })

                                return secrets


if __name__ == "__main__":
      detector = SecretDetector()
    test_content = """
        AWS_KEY=AKIA1234567890ABCDEF
            API_KEY=sk_live_4eC39HqLyjWDarhtT657Gb81
                ghp_1234567890abcdefghijklmnopqrstuvwxyz
                    """
    findings = detector.detect_secrets(test_content)
    for finding in findings:
              print(f"Found {finding['type']}: {finding['value']} (confidence: {finding['confidence']})")
