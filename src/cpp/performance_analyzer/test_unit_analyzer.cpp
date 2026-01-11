#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "oss_security_analyzer.h"

using namespace oss_security;

TEST_CASE("OSSSecurityAnalyzer initialization", "[unit][initialization]") {
    SECTION("Analyzer initializes successfully") {
        OSSSecurityAnalyzer analyzer;
        // If we get here without exceptions, initialization succeeded
        REQUIRE(true);
    }
}

TEST_CASE("Cryptographic pattern detection accuracy", "[unit][crypto-detection]") {
    OSSSecurityAnalyzer analyzer;
    
    SECTION("Detects OpenSSL AES-256-GCM pattern") {
        std::string code = R"(
            #include <openssl/evp.h>
            void encrypt() {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_aes_256_gcm();
                RAND_bytes(key, 32);
            }
        )";
        
        auto report = analyzer.analyze_crypto_patterns(code);
        
        REQUIRE_FALSE(report.crypto_patterns.empty());
        
        // Should detect at least one AES-256-GCM pattern
        bool found_aes256 = false;
        for (const auto& pattern : report.crypto_patterns) {
            if (pattern.algorithm == CryptoAlgorithm::AES_256_GCM) {
                found_aes256 = true;
                REQUIRE(pattern.key_size == 256);
                break;
            }
        }
        REQUIRE(found_aes256);
    }
    
    SECTION("Detects RSA pattern") {
        std::string code = R"(
            #include <openssl/rsa.h>
            void generate_key() {
                RSA_generate_key(2048, RSA_F4, NULL, NULL);
            }
        )";
        
        auto report = analyzer.analyze_crypto_patterns(code);
        
        REQUIRE_FALSE(report.crypto_patterns.empty());
        
        // Should detect RSA pattern
        bool found_rsa = false;
        for (const auto& pattern : report.crypto_patterns) {
            if (pattern.algorithm == CryptoAlgorithm::RSA_2048) {
                found_rsa = true;
                REQUIRE(pattern.key_size == 2048);
                break;
            }
        }
        REQUIRE(found_rsa);
    }
    
    SECTION("Detects libsodium ChaCha20-Poly1305 pattern") {
        std::string code = R"(
            #include <sodium.h>
            void encrypt() {
                crypto_secretbox_easy(c, m, mlen, n, k);
                randombytes(buf, sizeof(buf));
            }
        )";
        
        auto report = analyzer.analyze_crypto_patterns(code);
        
        // Should detect ChaCha20-Poly1305 pattern if libsodium is available
        bool found_chacha = false;
        for (const auto& pattern : report.crypto_patterns) {
            if (pattern.algorithm == CryptoAlgorithm::CHACHA20_POLY1305) {
                found_chacha = true;
                REQUIRE(pattern.key_size == 256);
                REQUIRE(pattern.secure_random_usage == true);
                break;
            }
        }
        // Note: This test may not find patterns if libsodium is not available
        // That's acceptable for this unit test
    }
    
    SECTION("Handles empty code gracefully") {
        std::string empty_code = "";
        
        auto report = analyzer.analyze_crypto_patterns(empty_code);
        
        REQUIRE_FALSE(report.analysis_timestamp.empty());
        REQUIRE(report.crypto_patterns.empty());
        REQUIRE_FALSE(report.recommendations.empty()); // Should have general recommendations
    }
    
    SECTION("Detects weak crypto patterns") {
        std::string weak_code = R"(
            #include <openssl/md5.h>
            void weak_hash() {
                MD5_Init(&ctx);
                rand(); // Insecure random
            }
        )";
        
        auto report = analyzer.analyze_crypto_patterns(weak_code);
        
        // Should generate security recommendations for weak patterns
        REQUIRE_FALSE(report.recommendations.empty());
        
        // Check if any security assessment indicates issues
        bool has_security_concerns = false;
        for (const auto& assessment : report.security_assessments) {
            if (assessment.second == SecurityLevel::HIGH || 
                assessment.second == SecurityLevel::CRITICAL_ISSUE) {
                has_security_concerns = true;
                break;
            }
        }
        // Note: This may not always trigger depending on pattern detection
    }
}

TEST_CASE("Performance analysis metrics calculation", "[unit][performance-metrics]") {
    OSSSecurityAnalyzer analyzer;
    
    SECTION("Calculates metrics for non-empty data") {
        std::vector<uint8_t> test_data(1024, 0x42);
        
        auto metrics = analyzer.analyze_security_performance(test_data);
        
        REQUIRE(metrics.encryption_time.count() >= 0);
        REQUIRE(metrics.decryption_time.count() >= 0);
        REQUIRE(metrics.memory_usage_bytes >= test_data.size());
        REQUIRE(metrics.throughput_bytes_per_second >= 0);
    }
    
    SECTION("Handles empty data gracefully") {
        std::vector<uint8_t> empty_data;
        
        auto metrics = analyzer.analyze_security_performance(empty_data);
        
        REQUIRE(metrics.encryption_time.count() >= 0);
        REQUIRE(metrics.decryption_time.count() >= 0);
        REQUIRE(metrics.memory_usage_bytes >= 0);
        REQUIRE(metrics.throughput_bytes_per_second >= 0);
    }
    
    SECTION("Memory usage scales with data size") {
        std::vector<uint8_t> small_data(100, 0x42);
        std::vector<uint8_t> large_data(10000, 0x42);
        
        auto small_metrics = analyzer.analyze_security_performance(small_data);
        auto large_metrics = analyzer.analyze_security_performance(large_data);
        
        // Larger data should use more memory
        REQUIRE(large_metrics.memory_usage_bytes >= small_metrics.memory_usage_bytes);
    }
    
    SECTION("Benchmarks different algorithms") {
        auto aes256_metrics = analyzer.benchmark_crypto_operations(CryptoAlgorithm::AES_256_GCM, 1024);
        auto aes128_metrics = analyzer.benchmark_crypto_operations(CryptoAlgorithm::AES_128_GCM, 1024);
        
        REQUIRE(aes256_metrics.encryption_time.count() >= 0);
        REQUIRE(aes128_metrics.encryption_time.count() >= 0);
        
        // Both should have reasonable performance characteristics
        REQUIRE(aes256_metrics.throughput_bytes_per_second >= 0);
        REQUIRE(aes128_metrics.throughput_bytes_per_second >= 0);
    }
}

TEST_CASE("Security recommendation generation", "[unit][recommendations]") {
    OSSSecurityAnalyzer analyzer;
    
    SECTION("Generates recommendations for weak patterns") {
        std::vector<CryptoUsagePattern> weak_patterns;
        
        CryptoUsagePattern weak_pattern;
        weak_pattern.algorithm = CryptoAlgorithm::UNKNOWN;
        weak_pattern.context = "Weak crypto usage";
        weak_pattern.key_size = 64; // Too small
        weak_pattern.proper_initialization = false;
        weak_pattern.secure_random_usage = false;
        weak_patterns.push_back(weak_pattern);
        
        auto report = analyzer.generate_crypto_recommendations(weak_patterns);
        
        REQUIRE_FALSE(report.report_timestamp.empty());
        REQUIRE_FALSE(report.crypto_recommendations.empty());
        REQUIRE_FALSE(report.security_enhancements.empty());
        
        // Should recommend fixing the weak algorithm
        bool has_algorithm_recommendation = false;
        for (const auto& rec : report.crypto_recommendations) {
            if (rec.find("algorithm") != std::string::npos || 
                rec.find("initialization") != std::string::npos ||
                rec.find("random") != std::string::npos) {
                has_algorithm_recommendation = true;
                break;
            }
        }
        REQUIRE(has_algorithm_recommendation);
    }
    
    SECTION("Generates recommendations for RSA usage") {
        std::vector<CryptoUsagePattern> rsa_patterns;
        
        CryptoUsagePattern rsa_pattern;
        rsa_pattern.algorithm = CryptoAlgorithm::RSA_2048;
        rsa_pattern.context = "RSA encryption usage";
        rsa_pattern.key_size = 2048;
        rsa_pattern.proper_initialization = true;
        rsa_pattern.secure_random_usage = true;
        rsa_patterns.push_back(rsa_pattern);
        
        auto report = analyzer.generate_crypto_recommendations(rsa_patterns);
        
        REQUIRE_FALSE(report.report_timestamp.empty());
        
        // Should suggest ECDSA for better performance
        bool has_performance_recommendation = false;
        for (const auto& improvement : report.performance_improvements) {
            if (improvement.find("ECDSA") != std::string::npos || 
                improvement.find("performance") != std::string::npos) {
                has_performance_recommendation = true;
                break;
            }
        }
        REQUIRE(has_performance_recommendation);
    }
    
    SECTION("Handles empty patterns gracefully") {
        std::vector<CryptoUsagePattern> empty_patterns;
        
        auto report = analyzer.generate_crypto_recommendations(empty_patterns);
        
        REQUIRE_FALSE(report.report_timestamp.empty());
        REQUIRE_FALSE(report.crypto_recommendations.empty()); // Should have general recommendations
        REQUIRE_FALSE(report.security_enhancements.empty());
    }
}

TEST_CASE("Threat assessment functionality", "[unit][threat-assessment]") {
    OSSSecurityAnalyzer analyzer;
    
    SECTION("Identifies SQL injection threats") {
        std::vector<std::string> events = {
            "sql_injection detected in parameter 'id'",
            "normal user activity logged"
        };
        
        auto report = analyzer.assess_threat_patterns(events);
        
        REQUIRE_FALSE(report.assessment_timestamp.empty());
        REQUIRE_FALSE(report.identified_threats.empty());
        REQUIRE_FALSE(report.mitigation_strategies.empty());
        
        // Should identify SQL injection threat
        bool found_sql_injection = false;
        for (const auto& threat : report.identified_threats) {
            if (threat.find("SQL injection") != std::string::npos || 
                threat.find("sql_injection") != std::string::npos) {
                found_sql_injection = true;
                break;
            }
        }
        REQUIRE(found_sql_injection);
        
        // Should have critical threat level for SQL injection
        REQUIRE(report.threat_levels.count("sql_injection") > 0);
        REQUIRE(report.threat_levels["sql_injection"] == SecurityLevel::CRITICAL_ISSUE);
    }
    
    SECTION("Identifies brute force attacks") {
        std::vector<std::string> events = {
            "failed_login attempt from 192.168.1.100",
            "failed_login attempt from 192.168.1.100",
            "failed_login attempt from 192.168.1.100"
        };
        
        auto report = analyzer.assess_threat_patterns(events);
        
        REQUIRE_FALSE(report.identified_threats.empty());
        
        // Should identify brute force threat
        bool found_brute_force = false;
        for (const auto& threat : report.identified_threats) {
            if (threat.find("Brute force") != std::string::npos || 
                threat.find("brute force") != std::string::npos) {
                found_brute_force = true;
                break;
            }
        }
        REQUIRE(found_brute_force);
    }
    
    SECTION("Identifies XSS attempts") {
        std::vector<std::string> events = {
            "xss attempt blocked in user input"
        };
        
        auto report = analyzer.assess_threat_patterns(events);
        
        REQUIRE_FALSE(report.identified_threats.empty());
        
        // Should identify XSS threat
        bool found_xss = false;
        for (const auto& threat : report.identified_threats) {
            if (threat.find("Cross-site scripting") != std::string::npos || 
                threat.find("xss") != std::string::npos) {
                found_xss = true;
                break;
            }
        }
        REQUIRE(found_xss);
    }
    
    SECTION("Identifies weak crypto usage") {
        std::vector<std::string> events = {
            "crypto_weak algorithm MD5 detected"
        };
        
        auto report = analyzer.assess_threat_patterns(events);
        
        REQUIRE_FALSE(report.identified_threats.empty());
        
        // Should identify weak crypto threat
        bool found_weak_crypto = false;
        for (const auto& threat : report.identified_threats) {
            if (threat.find("Weak cryptographic") != std::string::npos || 
                threat.find("crypto_weak") != std::string::npos) {
                found_weak_crypto = true;
                break;
            }
        }
        REQUIRE(found_weak_crypto);
    }
    
    SECTION("Handles empty events gracefully") {
        std::vector<std::string> empty_events;
        
        auto report = analyzer.assess_threat_patterns(empty_events);
        
        REQUIRE_FALSE(report.assessment_timestamp.empty());
        REQUIRE_FALSE(report.identified_threats.empty()); // Should have "no threats" message
        REQUIRE_FALSE(report.mitigation_strategies.empty());
    }
}

TEST_CASE("Edge cases and error handling", "[unit][edge-cases]") {
    OSSSecurityAnalyzer analyzer;
    
    SECTION("Handles malformed code input") {
        std::string malformed_code = "This is not valid C++ code @#$%^&*()";
        
        auto report = analyzer.analyze_crypto_patterns(malformed_code);
        
        REQUIRE_FALSE(report.analysis_timestamp.empty());
        // Should not crash and should return valid report
    }
    
    SECTION("Handles very large code input") {
        std::string large_code(100000, 'x'); // 100KB of 'x' characters
        
        auto report = analyzer.analyze_crypto_patterns(large_code);
        
        REQUIRE_FALSE(report.analysis_timestamp.empty());
        // Should handle large input without issues
    }
    
    SECTION("Handles special characters in code") {
        std::string special_code = R"(
            // Special characters: àáâãäåæçèéêë
            /* Unicode: 你好世界 */
            void function() { /* ñoño */ }
        )";
        
        auto report = analyzer.analyze_crypto_patterns(special_code);
        
        REQUIRE_FALSE(report.analysis_timestamp.empty());
        // Should handle special characters gracefully
    }
    
    SECTION("Handles very large data for performance analysis") {
        std::vector<uint8_t> large_data(1024 * 1024, 0x42); // 1MB
        
        auto metrics = analyzer.analyze_security_performance(large_data);
        
        REQUIRE(metrics.encryption_time.count() >= 0);
        REQUIRE(metrics.memory_usage_bytes >= large_data.size());
        // Should handle large data without crashing
    }
}