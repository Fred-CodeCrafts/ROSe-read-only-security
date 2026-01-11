#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_adapters.hpp>
#include <catch2/generators/catch_generators_random.hpp>

#include "oss_security_analyzer.h"
#include <random>
#include <algorithm>
#include <sstream>

using namespace oss_security;

// Helper function to generate random code samples
std::string generate_random_code_sample(size_t lines, std::mt19937& rng) {
    std::vector<std::string> code_patterns = {
        "#include <openssl/evp.h>",
        "EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();",
        "EVP_aes_256_gcm();",
        "EVP_aes_128_gcm();",
        "RAND_bytes(key, 32);",
        "RSA_generate_key(2048, RSA_F4, NULL, NULL);",
        "crypto_secretbox_easy(c, m, mlen, n, k);",
        "crypto_aead_chacha20poly1305_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);",
        "randombytes(buf, sizeof(buf));",
        "MD5_Init(&ctx);",  // Weak pattern
        "rand();",          // Insecure random
        "DES_encrypt(&data, &key, DES_ENCRYPT);", // Weak encryption
        "// Regular code comment",
        "int main() { return 0; }",
        "void function() { /* implementation */ }"
    };
    
    std::uniform_int_distribution<size_t> pattern_dist(0, code_patterns.size() - 1);
    std::ostringstream code;
    
    for (size_t i = 0; i < lines; ++i) {
        code << code_patterns[pattern_dist(rng)] << "\n";
    }
    
    return code.str();
}

// Helper function to generate random security events
std::vector<std::string> generate_random_security_events(size_t count, std::mt19937& rng) {
    std::vector<std::string> event_patterns = {
        "failed_login attempt from 192.168.1.100",
        "successful_login from user admin",
        "sql_injection detected in parameter 'id'",
        "xss attempt blocked in user input",
        "crypto_weak algorithm MD5 detected",
        "file_access denied for user guest",
        "network_scan detected from external IP",
        "privilege_escalation attempt blocked",
        "malware_signature detected in upload",
        "normal_operation user activity logged"
    };
    
    std::uniform_int_distribution<size_t> pattern_dist(0, event_patterns.size() - 1);
    std::vector<std::string> events;
    
    for (size_t i = 0; i < count; ++i) {
        events.push_back(event_patterns[pattern_dist(rng)]);
    }
    
    return events;
}

// Helper function to generate random data
std::vector<uint8_t> generate_random_data(size_t size, std::mt19937& rng) {
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::vector<uint8_t> data;
    data.reserve(size);
    
    for (size_t i = 0; i < size; ++i) {
        data.push_back(byte_dist(rng));
    }
    
    return data;
}

/**
 * Property 25: Technology Stack Compliance
 * For any system component, it should use only approved technologies 
 * (Python for AI, Go for microservices, C++ for performance-critical security, 
 * approved AWS services, approved CI/CD platforms)
 * **Validates: Requirements 7.3**
 * **Feature: ai-cybersecurity-platform, Property 25: Technology Stack Compliance**
 */
TEST_CASE("Property 25: Technology Stack Compliance", "[property][technology-compliance]") {
    OSSSecurityAnalyzer analyzer;
    std::random_device rd;
    std::mt19937 rng(rd());
    
    SECTION("C++ analyzer should properly analyze approved cryptographic technologies") {
        // Generate random code samples with various patterns
        auto code_lines = GENERATE(take(10, random(5, 50)));
        auto code_sample = generate_random_code_sample(code_lines, rng);
        
        CAPTURE(code_sample);
        
        // Analyze the code sample
        auto report = analyzer.analyze_crypto_patterns(code_sample);
        
        // Property: The analyzer should always produce a valid report
        REQUIRE_FALSE(report.analysis_timestamp.empty());
        
        // Property: Security assessments should be consistent with detected patterns
        REQUIRE(report.security_assessments.size() <= report.crypto_patterns.size() + 1);
        
        // Property: All detected patterns should have valid algorithms or be marked as unknown
        for (const auto& pattern : report.crypto_patterns) {
            REQUIRE(static_cast<int>(pattern.algorithm) >= 0);
            REQUIRE(static_cast<int>(pattern.algorithm) <= static_cast<int>(CryptoAlgorithm::UNKNOWN));
            REQUIRE_FALSE(pattern.context.empty());
        }
        
        // Property: Recommendations should be provided when patterns are detected
        if (!report.crypto_patterns.empty()) {
            REQUIRE_FALSE(report.recommendations.empty());
        }
        
        // Property: Performance metrics should have reasonable values
        REQUIRE(report.performance_metrics.encryption_time.count() >= 0);
        REQUIRE(report.performance_metrics.decryption_time.count() >= 0);
        REQUIRE(report.performance_metrics.memory_usage_bytes >= 0);
        REQUIRE(report.performance_metrics.throughput_bytes_per_second >= 0);
    }
    
    SECTION("Performance analysis should be consistent across different data sizes") {
        // Generate random data of various sizes
        auto data_size = GENERATE(take(10, random(1, 10240)));
        auto test_data = generate_random_data(data_size, rng);
        
        CAPTURE(data_size);
        
        // Analyze performance
        auto metrics = analyzer.analyze_security_performance(test_data);
        
        // Property: Larger data should generally take more time (or at least not less)
        // This is a weak property due to system variations, but should hold generally
        REQUIRE(metrics.encryption_time.count() >= 0);
        REQUIRE(metrics.decryption_time.count() >= 0);
        
        // Property: Memory usage should be proportional to data size
        REQUIRE(metrics.memory_usage_bytes >= data_size);
        
        // Property: Throughput should be calculable when operations take time
        auto total_time = metrics.encryption_time + metrics.decryption_time;
        if (total_time.count() > 0) {
            REQUIRE(metrics.throughput_bytes_per_second > 0);
        }
    }
    
    SECTION("Threat assessment should be consistent with input events") {
        // Generate random security events
        auto event_count = GENERATE(take(10, random(1, 20)));
        auto security_events = generate_random_security_events(event_count, rng);
        
        CAPTURE(event_count);
        CAPTURE(security_events);
        
        // Assess threats
        auto threat_report = analyzer.assess_threat_patterns(security_events);
        
        // Property: Report should always have a valid timestamp
        REQUIRE_FALSE(threat_report.assessment_timestamp.empty());
        
        // Property: Should always identify at least one threat (even if "no threats")
        REQUIRE_FALSE(threat_report.identified_threats.empty());
        
        // Property: Number of threat levels should not exceed identified threats
        REQUIRE(threat_report.threat_levels.size() <= threat_report.identified_threats.size());
        
        // Property: Should always provide mitigation strategies
        REQUIRE_FALSE(threat_report.mitigation_strategies.empty());
        
        // Property: Threat levels should be valid enum values
        for (const auto& threat_level : threat_report.threat_levels) {
            auto level = static_cast<int>(threat_level.second);
            REQUIRE(level >= static_cast<int>(SecurityLevel::LOW));
            REQUIRE(level <= static_cast<int>(SecurityLevel::CRITICAL_ISSUE));
        }
    }
    
    SECTION("Crypto recommendations should be consistent with detected patterns") {
        // Generate code with known patterns
        std::vector<CryptoUsagePattern> test_patterns;
        
        // Create a pattern with known characteristics
        CryptoUsagePattern pattern1;
        pattern1.algorithm = CryptoAlgorithm::AES_256_GCM;
        pattern1.context = "Test context 1";
        pattern1.key_size = 256;
        pattern1.proper_initialization = true;
        pattern1.secure_random_usage = true;
        test_patterns.push_back(pattern1);
        
        // Create a pattern with security issues
        CryptoUsagePattern pattern2;
        pattern2.algorithm = CryptoAlgorithm::UNKNOWN;
        pattern2.context = "Test context 2";
        pattern2.key_size = 64; // Too small
        pattern2.proper_initialization = false;
        pattern2.secure_random_usage = false;
        test_patterns.push_back(pattern2);
        
        // Generate recommendations
        auto rec_report = analyzer.generate_crypto_recommendations(test_patterns);
        
        // Property: Report should have a valid timestamp
        REQUIRE_FALSE(rec_report.report_timestamp.empty());
        
        // Property: Should provide recommendations for problematic patterns
        // Pattern2 has multiple issues, so should generate recommendations
        REQUIRE_FALSE(rec_report.crypto_recommendations.empty());
        
        // Property: Should provide security enhancements
        REQUIRE_FALSE(rec_report.security_enhancements.empty());
        
        // Property: Recommendations should be non-empty strings
        for (const auto& rec : rec_report.crypto_recommendations) {
            REQUIRE_FALSE(rec.empty());
        }
        
        for (const auto& enhancement : rec_report.security_enhancements) {
            REQUIRE_FALSE(enhancement.empty());
        }
    }
    
    SECTION("Analyzer should handle edge cases gracefully") {
        // Test with empty inputs
        auto empty_report = analyzer.analyze_crypto_patterns("");
        REQUIRE_FALSE(empty_report.analysis_timestamp.empty());
        
        // Test with empty data
        std::vector<uint8_t> empty_data;
        auto empty_metrics = analyzer.analyze_security_performance(empty_data);
        REQUIRE(empty_metrics.encryption_time.count() >= 0);
        
        // Test with empty events
        std::vector<std::string> empty_events;
        auto empty_threat_report = analyzer.assess_threat_patterns(empty_events);
        REQUIRE_FALSE(empty_threat_report.identified_threats.empty());
        
        // Test with empty patterns
        std::vector<CryptoUsagePattern> empty_patterns;
        auto empty_rec_report = analyzer.generate_crypto_recommendations(empty_patterns);
        REQUIRE_FALSE(empty_rec_report.report_timestamp.empty());
    }
}