cmake_minimum_required(VERSION 3.10)
project(OSSPerformanceSecurityAnalyzer)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig QUIET)

# Check for libsodium (optional)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBSODIUM libsodium)
    if(LIBSODIUM_FOUND)
        add_definitions(-DHAVE_LIBSODIUM)
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Source files
set(SOURCES
    main.cpp
    oss_security_analyzer.cpp
)

set(PROPERTY_TEST_SOURCES
    oss_security_analyzer.cpp
    test_performance_analysis_properties.cpp
)

set(UNIT_TEST_SOURCES
    oss_security_analyzer.cpp
    test_unit_analyzer.cpp
)

# Create executable
add_executable(oss_performance_analyzer ${SOURCES})

# Create test executables
add_executable(test_performance_analyzer ${PROPERTY_TEST_SOURCES})
add_executable(test_unit_analyzer ${UNIT_TEST_SOURCES})

# Link libraries for main executable
target_link_libraries(oss_performance_analyzer 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Link libraries for test executables
target_link_libraries(test_performance_analyzer 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

target_link_libraries(test_unit_analyzer 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Link libsodium if available
if(LIBSODIUM_FOUND)
    target_link_libraries(oss_performance_analyzer ${LIBSODIUM_LIBRARIES})
    target_include_directories(oss_performance_analyzer PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_compile_options(oss_performance_analyzer PRIVATE ${LIBSODIUM_CFLAGS_OTHER})
    
    target_link_libraries(test_performance_analyzer ${LIBSODIUM_LIBRARIES})
    target_include_directories(test_performance_analyzer PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_compile_options(test_performance_analyzer PRIVATE ${LIBSODIUM_CFLAGS_OTHER})
    
    target_link_libraries(test_unit_analyzer ${LIBSODIUM_LIBRARIES})
    target_include_directories(test_unit_analyzer PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_compile_options(test_unit_analyzer PRIVATE ${LIBSODIUM_CFLAGS_OTHER})
endif()

# Compiler flags
target_compile_options(oss_performance_analyzer PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -O2
)

target_compile_options(test_performance_analyzer PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -O2
)

target_compile_options(test_unit_analyzer PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -O2
)

# Install target
install(TARGETS oss_performance_analyzer DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME performance_analysis_properties COMMAND test_performance_analyzer)
add_test(NAME unit_analyzer_tests COMMAND test_unit_analyzer)