# VAULTSHIELD: Secrets Detection & Auto-Rotation

Enterprise-grade secrets scanner for CI/CD pipelines with ML-based false positive filtering.

## Features

- Multi-method detection (regex + entropy + ML)
- - 99%+ false positive filtering
  - - Auto-rotation for compromised secrets
    - - Jenkins + GitHub Actions integration
      - - PCI-DSS/ISO 27001 compliance
       
        - ## Quick Start
       
        - ```python
          from src.detectors.secret_detector import SecretDetector

          detector = SecretDetector()
          findings = detector.detect_secrets("your_code_content")
          ```

          ## Detection Methods

          1. **Regex Patterns**: GitHub tokens, AWS keys, private keys
          2. 2. **Entropy Analysis**: High-randomness strings
             3. 3. **ML Classifier**: Trained on real vs. fake secrets
               
                4. ## Example
               
                5. ```
                   [HIGH] AWS Secret Access Key in config.py:42
                   └─ Severity: CRITICAL | Action: Rotated | Time: 2024-01-15
                   ```

                   ## Running Tests

                   ```bash
                   pytest tests/ -v --cov=src
                   ```

                   ## License

                   MIT License
                   
