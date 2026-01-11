// Performance Security Analyzer - OSS-first performance analysis
#include <iostream>
#include <vector>
#include <string>
#include "oss_security_analyzer.h"

int main() {
    std::cout << "OSS Performance Security Analyzer Starting..." << std::endl;
    
    try {
        // Initialize the OSS Security Analyzer
        oss_security::OSSSecurityAnalyzer analyzer;
        
        // Example code analysis
        std::string sample_code = R"(
            #include <openssl/evp.h>
            #include <openssl/rand.h>
            
            void encrypt_data() {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_aes_256_gcm();
                RAND_bytes(key, 32);
            }
            
            void weak_crypto() {
                // This uses MD5 - should be flagged
                MD5_Init(&ctx);
                rand(); // Insecure random
            }
        )";
        
        std::cout << "Analyzing cryptographic patterns..." << std::endl;
        auto crypto_report = analyzer.analyze_crypto_patterns(sample_code);
        
        std::cout << "\n=== Cryptographic Analysis Report ===" << std::endl;
        std::cout << "Timestamp: " << crypto_report.analysis_timestamp << std::endl;
        std::cout << "Patterns found: " << crypto_report.crypto_patterns.size() << std::endl;
        
        for (const auto& pattern : crypto_report.crypto_patterns) {
            std::cout << "  - Algorithm: " << static_cast<int>(pattern.algorithm) << std::endl;
            std::cout << "    Context: " << pattern.context << std::endl;
            std::cout << "    Key size: " << pattern.key_size << " bits" << std::endl;
            std::cout << "    Proper init: " << (pattern.proper_initialization ? "Yes" : "No") << std::endl;
            std::cout << "    Secure random: " << (pattern.secure_random_usage ? "Yes" : "No") << std::endl;
        }
        
        std::cout << "\nSecurity Assessments:" << std::endl;
        for (const auto& assessment : crypto_report.security_assessments) {
            std::cout << "  - " << assessment.first << ": Level " << static_cast<int>(assessment.second) << std::endl;
        }
        
        std::cout << "\nRecommendations:" << std::endl;
        for (const auto& rec : crypto_report.recommendations) {
            std::cout << "  - " << rec << std::endl;
        }
        
        // Performance analysis
        std::cout << "\n=== Performance Analysis ===" << std::endl;
        std::vector<uint8_t> test_data(1024, 0x42);
        auto perf_metrics = analyzer.analyze_security_performance(test_data);
        
        std::cout << "Encryption time: " << perf_metrics.encryption_time.count() << " microseconds" << std::endl;
        std::cout << "Decryption time: " << perf_metrics.decryption_time.count() << " microseconds" << std::endl;
        std::cout << "Memory usage: " << perf_metrics.memory_usage_bytes << " bytes" << std::endl;
        std::cout << "Throughput: " << perf_metrics.throughput_bytes_per_second << " bytes/sec" << std::endl;
        
        // Threat assessment
        std::cout << "\n=== Threat Assessment ===" << std::endl;
        std::vector<std::string> security_events = {
            "failed_login attempt from 192.168.1.100",
            "sql_injection detected in user input",
            "crypto_weak algorithm usage detected"
        };
        
        auto threat_report = analyzer.assess_threat_patterns(security_events);
        std::cout << "Threats identified: " << threat_report.identified_threats.size() << std::endl;
        
        for (const auto& threat : threat_report.identified_threats) {
            std::cout << "  - " << threat << std::endl;
        }
        
        std::cout << "\nMitigation strategies:" << std::endl;
        for (const auto& strategy : threat_report.mitigation_strategies) {
            std::cout << "  - " << strategy << std::endl;
        }
        
        // Generate recommendations
        std::cout << "\n=== Crypto Recommendations ===" << std::endl;
        auto rec_report = analyzer.generate_crypto_recommendations(crypto_report.crypto_patterns);
        
        std::cout << "Crypto recommendations:" << std::endl;
        for (const auto& rec : rec_report.crypto_recommendations) {
            std::cout << "  - " << rec << std::endl;
        }
        
        std::cout << "Performance improvements:" << std::endl;
        for (const auto& improvement : rec_report.performance_improvements) {
            std::cout << "  - " << improvement << std::endl;
        }
        
        std::cout << "Security enhancements:" << std::endl;
        for (const auto& enhancement : rec_report.security_enhancements) {
            std::cout << "  - " << enhancement << std::endl;
        }
        
        std::cout << "\nOSS Performance Security Analyzer completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}