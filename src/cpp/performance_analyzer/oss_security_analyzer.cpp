#include "oss_security_analyzer.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <ctime>

// OpenSSL includes
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// libsodium includes (if available)
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

namespace oss_security {

OSSSecurityAnalyzer::OSSSecurityAnalyzer() 
    : openssl_initialized_(false), libsodium_initialized_(false) {
    initialize_openssl();
    initialize_libsodium();
}

OSSSecurityAnalyzer::~OSSSecurityAnalyzer() {
    if (openssl_initialized_) {
        EVP_cleanup();
        ERR_free_strings();
    }
}

bool OSSSecurityAnalyzer::initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    openssl_initialized_ = true;
    return true;
}

bool OSSSecurityAnalyzer::initialize_libsodium() {
#ifdef HAVE_LIBSODIUM
    if (sodium_init() < 0) {
        return false;
    }
    libsodium_initialized_ = true;
    return true;
#else
    // libsodium not available, continue without it
    libsodium_initialized_ = false;
    return false;
#endif
}

SecurityPatternReport OSSSecurityAnalyzer::analyze_crypto_patterns(const std::string& codebase) {
    SecurityPatternReport report;
    
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    report.analysis_timestamp = ss.str();
    
    // Detect OpenSSL patterns
    auto openssl_patterns = detect_openssl_patterns(codebase);
    report.crypto_patterns.insert(report.crypto_patterns.end(), 
                                 openssl_patterns.begin(), openssl_patterns.end());
    
    // Detect libsodium patterns
    auto libsodium_patterns = detect_libsodium_patterns(codebase);
    report.crypto_patterns.insert(report.crypto_patterns.end(), 
                                 libsodium_patterns.begin(), libsodium_patterns.end());
    
    // Assess security levels for each pattern
    for (const auto& pattern : report.crypto_patterns) {
        SecurityLevel level = SecurityLevel::MEDIUM;
        if (pattern.algorithm != CryptoAlgorithm::UNKNOWN) {
            if (matches_openssl_pattern(pattern.context)) {
                level = assess_openssl_usage(pattern);
            } else if (matches_libsodium_pattern(pattern.context)) {
                level = assess_libsodium_usage(pattern);
            }
        }
        report.security_assessments[pattern.context] = level;
    }
    
    // Generate recommendations
    report.recommendations = generate_security_recommendations(report.crypto_patterns);
    
    // Benchmark performance for detected algorithms
    if (!report.crypto_patterns.empty()) {
        auto first_algorithm = report.crypto_patterns[0].algorithm;
        report.performance_metrics = benchmark_crypto_operations(first_algorithm, 1024);
    }
    
    return report;
}

PerformanceMetrics OSSSecurityAnalyzer::analyze_security_performance(const std::vector<uint8_t>& data) {
    PerformanceMetrics metrics;
    
    if (data.empty()) {
        return metrics;
    }
    
    // Benchmark AES-256-GCM encryption/decryption
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simulate encryption operation
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        unsigned char key[32] = {0}; // 256-bit key
        unsigned char iv[12] = {0};  // 96-bit IV for GCM
        
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) == 1) {
            unsigned char* ciphertext = new unsigned char[data.size() + 16];
            int len;
            
            // Encrypt data
            EVP_EncryptUpdate(ctx, ciphertext, &len, data.data(), data.size());
            
            auto encrypt_end = std::chrono::high_resolution_clock::now();
            metrics.encryption_time = std::chrono::duration_cast<std::chrono::microseconds>(
                encrypt_end - start);
            
            // Simulate decryption
            auto decrypt_start = std::chrono::high_resolution_clock::now();
            unsigned char* plaintext = new unsigned char[data.size()];
            EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, len);
            
            auto decrypt_end = std::chrono::high_resolution_clock::now();
            metrics.decryption_time = std::chrono::duration_cast<std::chrono::microseconds>(
                decrypt_end - decrypt_start);
            
            delete[] ciphertext;
            delete[] plaintext;
        }
        
        EVP_CIPHER_CTX_free(ctx);
    }
    
    // Calculate throughput
    auto total_time = metrics.encryption_time + metrics.decryption_time;
    if (total_time.count() > 0) {
        metrics.throughput_bytes_per_second = 
            (data.size() * 1000000) / total_time.count(); // bytes per second
    }
    
    // Estimate memory usage (simplified)
    metrics.memory_usage_bytes = data.size() * 2 + 1024; // data + overhead
    metrics.cpu_utilization = 0.1; // Simplified CPU usage estimate
    
    return metrics;
}

ThreatAssessmentReport OSSSecurityAnalyzer::assess_threat_patterns(const std::vector<std::string>& security_events) {
    ThreatAssessmentReport report;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    report.assessment_timestamp = ss.str();
    
    // Analyze security events for threat patterns
    for (const auto& event : security_events) {
        // Check for common threat indicators
        if (event.find("failed_login") != std::string::npos) {
            report.identified_threats.push_back("Brute force attack detected");
            report.threat_levels["brute_force"] = SecurityLevel::HIGH;
            report.mitigation_strategies.push_back("Implement account lockout policies");
        }
        
        if (event.find("sql_injection") != std::string::npos) {
            report.identified_threats.push_back("SQL injection attempt detected");
            report.threat_levels["sql_injection"] = SecurityLevel::CRITICAL_ISSUE;
            report.mitigation_strategies.push_back("Use parameterized queries and input validation");
        }
        
        if (event.find("xss") != std::string::npos) {
            report.identified_threats.push_back("Cross-site scripting attempt detected");
            report.threat_levels["xss"] = SecurityLevel::HIGH;
            report.mitigation_strategies.push_back("Implement proper output encoding and CSP headers");
        }
        
        if (event.find("crypto_weak") != std::string::npos) {
            report.identified_threats.push_back("Weak cryptographic implementation detected");
            report.threat_levels["weak_crypto"] = SecurityLevel::HIGH;
            report.mitigation_strategies.push_back("Upgrade to stronger cryptographic algorithms");
        }
    }
    
    // Add general security recommendations if no specific threats found
    if (report.identified_threats.empty()) {
        report.identified_threats.push_back("No immediate threats detected");
        report.threat_levels["baseline"] = SecurityLevel::LOW;
        report.mitigation_strategies.push_back("Continue regular security monitoring");
    }
    
    return report;
}

RecommendationReport OSSSecurityAnalyzer::generate_crypto_recommendations(const std::vector<CryptoUsagePattern>& patterns) {
    RecommendationReport report;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    report.report_timestamp = ss.str();
    
    for (const auto& pattern : patterns) {
        // Crypto-specific recommendations
        if (is_weak_algorithm(pattern.algorithm)) {
            report.crypto_recommendations.push_back(
                "Replace weak algorithm " + std::to_string(static_cast<int>(pattern.algorithm)) + 
                " with AES-256-GCM or ChaCha20-Poly1305");
        }
        
        if (!pattern.proper_initialization) {
            report.crypto_recommendations.push_back(
                "Ensure proper cryptographic context initialization in: " + pattern.context);
        }
        
        if (!pattern.secure_random_usage) {
            report.crypto_recommendations.push_back(
                "Use cryptographically secure random number generation in: " + pattern.context);
        }
        
        if (!has_proper_key_size(pattern.algorithm, pattern.key_size)) {
            report.crypto_recommendations.push_back(
                "Increase key size for algorithm in: " + pattern.context);
        }
        
        // Performance recommendations
        if (pattern.algorithm == CryptoAlgorithm::RSA_2048 || 
            pattern.algorithm == CryptoAlgorithm::RSA_4096) {
            report.performance_improvements.push_back(
                "Consider using ECDSA for better performance in: " + pattern.context);
        }
        
        // Security enhancements
        report.security_enhancements.push_back(
            "Implement proper key rotation for: " + pattern.context);
        report.security_enhancements.push_back(
            "Add integrity verification for: " + pattern.context);
    }
    
    // General recommendations if no patterns found
    if (patterns.empty()) {
        report.crypto_recommendations.push_back("No cryptographic patterns detected - consider adding encryption");
        report.security_enhancements.push_back("Implement comprehensive cryptographic security measures");
    }
    
    return report;
}

std::vector<CryptoUsagePattern> OSSSecurityAnalyzer::detect_openssl_patterns(const std::string& code) {
    std::vector<CryptoUsagePattern> patterns;
    
    // Regular expressions for OpenSSL patterns
    std::regex evp_cipher_regex(R"(EVP_(\w+)_(\w+)\(\))");
    std::regex evp_encrypt_regex(R"(EVP_Encrypt\w+)");
    std::regex evp_decrypt_regex(R"(EVP_Decrypt\w+)");
    std::regex rsa_regex(R"(RSA_(\w+))");
    
    std::istringstream stream(code);
    std::string line;
    int line_number = 0;
    
    while (std::getline(stream, line)) {
        line_number++;
        
        std::smatch match;
        
        // Check for EVP cipher usage
        if (std::regex_search(line, match, evp_cipher_regex)) {
            CryptoUsagePattern pattern;
            pattern.context = "Line " + std::to_string(line_number) + ": " + line;
            
            std::string cipher_name = match[1].str() + "_" + match[2].str();
            std::transform(cipher_name.begin(), cipher_name.end(), cipher_name.begin(), ::tolower);
            
            if (cipher_name.find("aes_256") != std::string::npos) {
                pattern.algorithm = CryptoAlgorithm::AES_256_GCM;
                pattern.key_size = 256;
            } else if (cipher_name.find("aes_128") != std::string::npos) {
                pattern.algorithm = CryptoAlgorithm::AES_128_GCM;
                pattern.key_size = 128;
            } else {
                pattern.algorithm = CryptoAlgorithm::UNKNOWN;
                pattern.key_size = 0;
            }
            
            pattern.proper_initialization = line.find("EVP_CIPHER_CTX_new") != std::string::npos;
            pattern.secure_random_usage = line.find("RAND_bytes") != std::string::npos;
            
            patterns.push_back(pattern);
        }
        
        // Check for RSA usage
        if (std::regex_search(line, match, rsa_regex)) {
            CryptoUsagePattern pattern;
            pattern.context = "Line " + std::to_string(line_number) + ": " + line;
            pattern.algorithm = CryptoAlgorithm::RSA_2048; // Default assumption
            pattern.key_size = 2048;
            pattern.proper_initialization = true; // Assume proper for RSA
            pattern.secure_random_usage = line.find("RAND_bytes") != std::string::npos;
            
            patterns.push_back(pattern);
        }
    }
    
    return patterns;
}

std::vector<CryptoUsagePattern> OSSSecurityAnalyzer::detect_libsodium_patterns(const std::string& code) {
    std::vector<CryptoUsagePattern> patterns;
    
    if (!libsodium_initialized_) {
        return patterns; // libsodium not available
    }
    
    // Regular expressions for libsodium patterns
    std::regex secretbox_regex(R"(crypto_secretbox\w*)");
    std::regex aead_regex(R"(crypto_aead_chacha20poly1305\w*)");
    std::regex sign_regex(R"(crypto_sign\w*)");
    
    std::istringstream stream(code);
    std::string line;
    int line_number = 0;
    
    while (std::getline(stream, line)) {
        line_number++;
        
        std::smatch match;
        
        // Check for secretbox usage (ChaCha20-Poly1305)
        if (std::regex_search(line, match, secretbox_regex)) {
            CryptoUsagePattern pattern;
            pattern.context = "Line " + std::to_string(line_number) + ": " + line;
            pattern.algorithm = CryptoAlgorithm::CHACHA20_POLY1305;
            pattern.key_size = 256; // ChaCha20 uses 256-bit keys
            pattern.proper_initialization = true; // libsodium handles initialization
            pattern.secure_random_usage = line.find("randombytes") != std::string::npos;
            
            patterns.push_back(pattern);
        }
        
        // Check for AEAD usage
        if (std::regex_search(line, match, aead_regex)) {
            CryptoUsagePattern pattern;
            pattern.context = "Line " + std::to_string(line_number) + ": " + line;
            pattern.algorithm = CryptoAlgorithm::CHACHA20_POLY1305;
            pattern.key_size = 256;
            pattern.proper_initialization = true;
            pattern.secure_random_usage = line.find("randombytes") != std::string::npos;
            
            patterns.push_back(pattern);
        }
        
        // Check for signing usage
        if (std::regex_search(line, match, sign_regex)) {
            CryptoUsagePattern pattern;
            pattern.context = "Line " + std::to_string(line_number) + ": " + line;
            pattern.algorithm = CryptoAlgorithm::ECDSA_P256; // Ed25519 is similar
            pattern.key_size = 256;
            pattern.proper_initialization = true;
            pattern.secure_random_usage = true; // libsodium handles this
            
            patterns.push_back(pattern);
        }
    }
    
    return patterns;
}

SecurityLevel OSSSecurityAnalyzer::assess_openssl_usage(const CryptoUsagePattern& pattern) {
    if (!pattern.proper_initialization) {
        return SecurityLevel::CRITICAL_ISSUE;
    }
    
    if (is_weak_algorithm(pattern.algorithm)) {
        return SecurityLevel::HIGH;
    }
    
    if (!pattern.secure_random_usage) {
        return SecurityLevel::HIGH;
    }
    
    if (!has_proper_key_size(pattern.algorithm, pattern.key_size)) {
        return SecurityLevel::MEDIUM;
    }
    
    return SecurityLevel::LOW; // Good security practices
}

SecurityLevel OSSSecurityAnalyzer::assess_libsodium_usage(const CryptoUsagePattern& pattern) {
    // libsodium generally has good defaults
    if (!pattern.secure_random_usage) {
        return SecurityLevel::MEDIUM;
    }
    
    return SecurityLevel::LOW; // libsodium is generally secure by default
}

PerformanceMetrics OSSSecurityAnalyzer::benchmark_crypto_operations(CryptoAlgorithm algorithm, size_t data_size) {
    PerformanceMetrics metrics;
    
    std::vector<uint8_t> test_data(data_size, 0x42);
    return analyze_security_performance(test_data);
}

std::vector<std::string> OSSSecurityAnalyzer::analyze_performance_bottlenecks(const PerformanceMetrics& metrics) {
    std::vector<std::string> bottlenecks;
    
    if (metrics.encryption_time.count() > 10000) { // > 10ms
        bottlenecks.push_back("Encryption operation is slow - consider hardware acceleration");
    }
    
    if (metrics.decryption_time.count() > 10000) { // > 10ms
        bottlenecks.push_back("Decryption operation is slow - consider optimized algorithms");
    }
    
    if (metrics.memory_usage_bytes > 1024 * 1024) { // > 1MB
        bottlenecks.push_back("High memory usage - consider streaming operations");
    }
    
    if (metrics.throughput_bytes_per_second < 1024 * 1024) { // < 1MB/s
        bottlenecks.push_back("Low throughput - consider algorithm optimization");
    }
    
    return bottlenecks;
}

std::vector<std::string> OSSSecurityAnalyzer::detect_weak_crypto_patterns(const std::string& code) {
    std::vector<std::string> weak_patterns;
    
    // Check for weak algorithms
    if (code.find("MD5") != std::string::npos) {
        weak_patterns.push_back("MD5 hash algorithm detected - use SHA-256 or better");
    }
    
    if (code.find("SHA1") != std::string::npos || code.find("SHA-1") != std::string::npos) {
        weak_patterns.push_back("SHA-1 hash algorithm detected - use SHA-256 or better");
    }
    
    if (code.find("DES") != std::string::npos && code.find("AES") == std::string::npos) {
        weak_patterns.push_back("DES encryption detected - use AES instead");
    }
    
    if (code.find("RC4") != std::string::npos) {
        weak_patterns.push_back("RC4 cipher detected - use AES-GCM or ChaCha20-Poly1305");
    }
    
    return weak_patterns;
}

std::vector<std::string> OSSSecurityAnalyzer::detect_insecure_random_usage(const std::string& code) {
    std::vector<std::string> insecure_patterns;
    
    if (code.find("rand()") != std::string::npos) {
        insecure_patterns.push_back("Insecure rand() function detected - use RAND_bytes() or randombytes()");
    }
    
    if (code.find("srand(") != std::string::npos) {
        insecure_patterns.push_back("Predictable srand() seeding detected - use cryptographic random");
    }
    
    if (code.find("time(") != std::string::npos && code.find("srand") != std::string::npos) {
        insecure_patterns.push_back("Time-based random seeding detected - use secure random source");
    }
    
    return insecure_patterns;
}

std::vector<std::string> OSSSecurityAnalyzer::detect_key_management_issues(const std::string& code) {
    std::vector<std::string> key_issues;
    
    if (code.find("hardcoded") != std::string::npos && code.find("key") != std::string::npos) {
        key_issues.push_back("Potential hardcoded key detected - use secure key storage");
    }
    
    if (code.find("password") != std::string::npos && code.find("=") != std::string::npos) {
        key_issues.push_back("Potential hardcoded password detected - use secure credential storage");
    }
    
    if (code.find("memset") == std::string::npos && code.find("key") != std::string::npos) {
        key_issues.push_back("Key material may not be properly cleared from memory");
    }
    
    return key_issues;
}

// Private helper methods
CryptoAlgorithm OSSSecurityAnalyzer::identify_algorithm(const std::string& algorithm_name) {
    std::string lower_name = algorithm_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("aes_256") != std::string::npos) {
        return CryptoAlgorithm::AES_256_GCM;
    } else if (lower_name.find("aes_128") != std::string::npos) {
        return CryptoAlgorithm::AES_128_GCM;
    } else if (lower_name.find("chacha20") != std::string::npos) {
        return CryptoAlgorithm::CHACHA20_POLY1305;
    } else if (lower_name.find("rsa") != std::string::npos) {
        if (lower_name.find("4096") != std::string::npos) {
            return CryptoAlgorithm::RSA_4096;
        } else {
            return CryptoAlgorithm::RSA_2048;
        }
    } else if (lower_name.find("ecdsa") != std::string::npos) {
        if (lower_name.find("384") != std::string::npos) {
            return CryptoAlgorithm::ECDSA_P384;
        } else {
            return CryptoAlgorithm::ECDSA_P256;
        }
    }
    
    return CryptoAlgorithm::UNKNOWN;
}

SecurityLevel OSSSecurityAnalyzer::calculate_overall_security_level(const std::vector<CryptoUsagePattern>& patterns) {
    if (patterns.empty()) {
        return SecurityLevel::MEDIUM;
    }
    
    SecurityLevel worst_level = SecurityLevel::LOW;
    
    for (const auto& pattern : patterns) {
        if (is_weak_algorithm(pattern.algorithm)) {
            worst_level = SecurityLevel::HIGH;
        }
        if (!pattern.proper_initialization || !pattern.secure_random_usage) {
            worst_level = SecurityLevel::CRITICAL_ISSUE;
            break; // Critical issues take precedence
        }
    }
    
    return worst_level;
}

std::vector<std::string> OSSSecurityAnalyzer::generate_security_recommendations(const std::vector<CryptoUsagePattern>& patterns) {
    std::vector<std::string> recommendations;
    
    for (const auto& pattern : patterns) {
        if (is_weak_algorithm(pattern.algorithm)) {
            recommendations.push_back("Upgrade weak cryptographic algorithm in: " + pattern.context);
        }
        
        if (!pattern.proper_initialization) {
            recommendations.push_back("Fix cryptographic initialization in: " + pattern.context);
        }
        
        if (!pattern.secure_random_usage) {
            recommendations.push_back("Use secure random number generation in: " + pattern.context);
        }
        
        for (const auto& vulnerability : pattern.vulnerabilities) {
            recommendations.push_back("Address vulnerability: " + vulnerability + " in: " + pattern.context);
        }
    }
    
    return recommendations;
}

bool OSSSecurityAnalyzer::matches_openssl_pattern(const std::string& line) {
    return line.find("EVP_") != std::string::npos || 
           line.find("RSA_") != std::string::npos ||
           line.find("RAND_bytes") != std::string::npos;
}

bool OSSSecurityAnalyzer::matches_libsodium_pattern(const std::string& line) {
    return line.find("crypto_") != std::string::npos ||
           line.find("randombytes") != std::string::npos;
}

bool OSSSecurityAnalyzer::is_weak_algorithm(CryptoAlgorithm algorithm) {
    return algorithm == CryptoAlgorithm::UNKNOWN;
}

bool OSSSecurityAnalyzer::has_proper_key_size(CryptoAlgorithm algorithm, size_t key_size) {
    switch (algorithm) {
        case CryptoAlgorithm::AES_256_GCM:
        case CryptoAlgorithm::CHACHA20_POLY1305:
            return key_size >= 256;
        case CryptoAlgorithm::AES_128_GCM:
            return key_size >= 128;
        case CryptoAlgorithm::RSA_2048:
            return key_size >= 2048;
        case CryptoAlgorithm::RSA_4096:
            return key_size >= 4096;
        case CryptoAlgorithm::ECDSA_P256:
            return key_size >= 256;
        case CryptoAlgorithm::ECDSA_P384:
            return key_size >= 384;
        default:
            return false;
    }
}

} // namespace oss_security