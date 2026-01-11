#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>

// Forward declarations for OpenSSL types
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace oss_security {

enum class CryptoAlgorithm {
    AES_256_GCM,
    AES_128_GCM,
    CHACHA20_POLY1305,
    RSA_2048,
    RSA_4096,
    ECDSA_P256,
    ECDSA_P384,
    UNKNOWN
};

enum class SecurityLevel {
    HIGH,
    MEDIUM,
    LOW,
    CRITICAL_ISSUE
};

struct CryptoUsagePattern {
    CryptoAlgorithm algorithm;
    std::string context;
    size_t key_size;
    bool proper_initialization;
    bool secure_random_usage;
    std::vector<std::string> vulnerabilities;
};

struct PerformanceMetrics {
    std::chrono::microseconds encryption_time;
    std::chrono::microseconds decryption_time;
    size_t memory_usage_bytes;
    double cpu_utilization;
    size_t throughput_bytes_per_second;
};

struct SecurityPatternReport {
    std::vector<CryptoUsagePattern> crypto_patterns;
    std::map<std::string, SecurityLevel> security_assessments;
    std::vector<std::string> recommendations;
    PerformanceMetrics performance_metrics;
    std::string analysis_timestamp;
};

struct ThreatAssessmentReport {
    std::vector<std::string> identified_threats;
    std::map<std::string, SecurityLevel> threat_levels;
    std::vector<std::string> mitigation_strategies;
    std::string assessment_timestamp;
};

struct RecommendationReport {
    std::vector<std::string> crypto_recommendations;
    std::vector<std::string> performance_improvements;
    std::vector<std::string> security_enhancements;
    std::string report_timestamp;
};

class OSSSecurityAnalyzer {
public:
    OSSSecurityAnalyzer();
    virtual ~OSSSecurityAnalyzer();

    // Core analysis methods
    virtual SecurityPatternReport analyze_crypto_patterns(const std::string& codebase);
    virtual PerformanceMetrics analyze_security_performance(const std::vector<uint8_t>& data);
    virtual ThreatAssessmentReport assess_threat_patterns(const std::vector<std::string>& security_events);
    virtual RecommendationReport generate_crypto_recommendations(const std::vector<CryptoUsagePattern>& patterns);

    // OpenSSL integration methods
    bool initialize_openssl();
    std::vector<CryptoUsagePattern> detect_openssl_patterns(const std::string& code);
    SecurityLevel assess_openssl_usage(const CryptoUsagePattern& pattern);

    // libsodium integration methods
    bool initialize_libsodium();
    std::vector<CryptoUsagePattern> detect_libsodium_patterns(const std::string& code);
    SecurityLevel assess_libsodium_usage(const CryptoUsagePattern& pattern);

    // Performance analysis methods
    PerformanceMetrics benchmark_crypto_operations(CryptoAlgorithm algorithm, size_t data_size);
    std::vector<std::string> analyze_performance_bottlenecks(const PerformanceMetrics& metrics);

    // Security pattern detection
    std::vector<std::string> detect_weak_crypto_patterns(const std::string& code);
    std::vector<std::string> detect_insecure_random_usage(const std::string& code);
    std::vector<std::string> detect_key_management_issues(const std::string& code);

private:
    bool openssl_initialized_;
    bool libsodium_initialized_;
    
    // Internal analysis helpers
    CryptoAlgorithm identify_algorithm(const std::string& algorithm_name);
    SecurityLevel calculate_overall_security_level(const std::vector<CryptoUsagePattern>& patterns);
    std::vector<std::string> generate_security_recommendations(const std::vector<CryptoUsagePattern>& patterns);
    
    // Pattern matching helpers
    bool matches_openssl_pattern(const std::string& line);
    bool matches_libsodium_pattern(const std::string& line);
    bool is_weak_algorithm(CryptoAlgorithm algorithm);
    bool has_proper_key_size(CryptoAlgorithm algorithm, size_t key_size);
};

} // namespace oss_security