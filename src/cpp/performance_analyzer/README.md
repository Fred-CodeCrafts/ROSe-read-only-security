# OSS Performance Security Analyzer

A comprehensive C++ security pattern analyzer that provides cryptographic analysis, performance metrics, and threat assessment capabilities using open-source technologies.

## Features

- **Cryptographic Pattern Analysis**: Detects and analyzes OpenSSL and libsodium usage patterns
- **Performance Metrics**: Benchmarks encryption/decryption operations and analyzes performance bottlenecks
- **Threat Assessment**: Identifies security threats from event logs and provides mitigation strategies
- **Security Recommendations**: Generates actionable recommendations for improving cryptographic implementations
- **OSS-First Design**: Built with OpenSSL by default, optional libsodium support

## Dependencies

### Required
- **OpenSSL**: Cryptographic library for analysis and benchmarking
- **C++17 Compiler**: g++, clang++, or MSVC
- **Catch2**: Testing framework (for running tests)

### Optional
- **libsodium**: Modern cryptographic library for additional pattern analysis

## Building

### Using Make (Linux/macOS)
```bash
make all                # Build main analyzer
make run-property-test  # Run property-based tests
make run-unit-test      # Run unit tests
make run-all-tests      # Run all tests
```

### Using CMake
```bash
mkdir build && cd build
cmake ..
make
ctest  # Run all tests
```

### Manual Compilation
```bash
g++ -std=c++17 -Wall -Wextra -O2 -I. main.cpp oss_security_analyzer.cpp -o oss_performance_analyzer -lssl -lcrypto
```

## Usage

### Basic Analysis
```bash
./oss_performance_analyzer
```

The analyzer will:
1. Analyze sample cryptographic code patterns
2. Generate performance metrics for encryption operations
3. Assess threat patterns from security events
4. Provide comprehensive recommendations

### Integration

```cpp
#include "oss_security_analyzer.h"

oss_security::OSSSecurityAnalyzer analyzer;

// Analyze cryptographic patterns in code
std::string code = "/* your C++ code with crypto usage */";
auto crypto_report = analyzer.analyze_crypto_patterns(code);

// Analyze performance of security operations
std::vector<uint8_t> data = {/* your data */};
auto perf_metrics = analyzer.analyze_security_performance(data);

// Assess security threats from events
std::vector<std::string> events = {"failed_login", "sql_injection"};
auto threat_report = analyzer.assess_threat_patterns(events);

// Generate recommendations
auto recommendations = analyzer.generate_crypto_recommendations(crypto_report.crypto_patterns);
```

## Architecture

### Core Components

1. **OSSSecurityAnalyzer**: Main analysis engine
   - OpenSSL integration for cryptographic analysis
   - libsodium integration (optional) for modern crypto patterns
   - Performance benchmarking capabilities
   - Threat pattern recognition

2. **Pattern Detection**: 
   - Regular expression-based code analysis
   - Algorithm identification and classification
   - Security vulnerability detection

3. **Performance Analysis**:
   - Real-time encryption/decryption benchmarking
   - Memory usage analysis
   - Throughput calculations

4. **Threat Assessment**:
   - Event log analysis
   - Threat classification and prioritization
   - Mitigation strategy generation

### Supported Algorithms

- **AES-256-GCM**: Advanced Encryption Standard with Galois/Counter Mode
- **AES-128-GCM**: AES with 128-bit keys
- **ChaCha20-Poly1305**: Modern authenticated encryption (libsodium)
- **RSA-2048/4096**: RSA public key cryptography
- **ECDSA-P256/P384**: Elliptic Curve Digital Signature Algorithm

## Testing

### Property-Based Tests
- **Property 25**: Technology Stack Compliance validation
- Tests cryptographic technology compliance with requirements
- Validates performance consistency across different data sizes
- Ensures threat assessment consistency with input events

### Unit Tests
- Cryptographic pattern detection accuracy
- Performance analysis metrics calculation
- Security recommendation generation
- Threat assessment functionality
- Edge cases and error handling

## Security Features

### Pattern Detection
- Weak algorithm identification (MD5, SHA-1, DES, RC4)
- Insecure random number usage detection
- Key management issue identification
- Proper initialization verification

### Performance Analysis
- Encryption/decryption timing analysis
- Memory usage profiling
- Throughput measurement
- Bottleneck identification

### Threat Assessment
- SQL injection detection
- Cross-site scripting (XSS) identification
- Brute force attack recognition
- Weak cryptography usage alerts

## Requirements Validation

This analyzer validates:
- **Requirements 7.3**: C++ for performance-critical security operations
- **Requirements 4.5**: Comprehensive threat model generation

## OSS-First Design

- **Default**: OpenSSL for cryptographic operations
- **Optional**: libsodium for modern cryptographic patterns
- **Upgrade Path**: Clear documentation for enterprise-scale alternatives
- **Zero Cost**: Runs entirely on open-source components

## Contributing

1. Follow C++17 standards
2. Maintain OpenSSL compatibility
3. Add unit tests for new features
4. Update property tests for new compliance requirements
5. Document security implications of changes

## License

This project follows the OSS-first principle and is designed to work with open-source cryptographic libraries.