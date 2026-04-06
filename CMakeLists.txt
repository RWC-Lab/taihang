cmake_minimum_required(VERSION 3.21)

project(taihang
    VERSION 0.1.0
    DESCRIPTION "Taihang Cryptography Library"
    LANGUAGES C CXX
)

# ------------------------------------------------------------
# 1. Build Options
# ------------------------------------------------------------
option(TAIHANG_BUILD_TESTS "Build test suite" ON)
option(TAIHANG_ENABLE_LTO "Enable Link Time Optimization" ON)
option(TAIHANG_ENABLE_SANITIZER "Enable AddressSanitizer" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    message(STATUS "No build type specified — defaulting to Debug")
endif()

# ------------------------------------------------------------
# 2. Dependencies
# ------------------------------------------------------------

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH
        "/opt/homebrew/opt/openssl@3"
        "/usr/local/opt/openssl@3"
        "/opt/homebrew"
        "/usr/local"
    )
endif()

find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(xxHash REQUIRED CONFIG)

# ------------------------------------------------------------
# 3. Library Definition
# ------------------------------------------------------------

file(GLOB_RECURSE TAIHANG_SOURCES
    CONFIGURE_DEPENDS
    ${PROJECT_SOURCE_DIR}/source/*.cpp
)

add_library(taihang STATIC ${TAIHANG_SOURCES})
add_library(taihang::taihang ALIAS taihang)

# ------------------------------------------------------------
# 4. Compiler Flags
# ------------------------------------------------------------

function(taihang_apply_arch_flags TARGET_NAME)

    if(MSVC)

        target_compile_options(${TARGET_NAME} PRIVATE /W4 /Ot /arch:AVX2)

    else()

        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wno-sign-conversion
            -Wno-unused-parameter
            -Wno-deprecated-declarations
            -O3
        )

        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")

            message(STATUS "Taihang: Adding x86_64 SIMD flags")

            target_compile_options(${TARGET_NAME} PRIVATE
                -maes -mpclmul -msse4.1 -mavx -mavx2 -mrdseed
            )

            target_compile_definitions(${TARGET_NAME} PRIVATE TAIHANG_ARCH_X64)

        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")

            message(STATUS "Taihang: Adding ARM64 Crypto flags")

            target_compile_options(${TARGET_NAME} PRIVATE
                -march=armv8-a+crypto+simd
            )

            target_compile_definitions(${TARGET_NAME} PRIVATE TAIHANG_ARCH_ARM)

        endif()

    endif()

endfunction()

taihang_apply_arch_flags(taihang)

# ------------------------------------------------------------
# 5. Includes & Linkage
# ------------------------------------------------------------

target_include_directories(taihang
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/robin_hood>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(taihang
    PUBLIC
        OpenSSL::Crypto
        OpenMP::OpenMP_CXX
        xxHash::xxhash
)

target_compile_features(taihang PUBLIC cxx_std_17)

# ------------------------------------------------------------
# 6. Optimization / Sanitizers
# ------------------------------------------------------------

if(TAIHANG_ENABLE_LTO)

    include(CheckIPOSupported)
    check_ipo_supported(RESULT result)

    if(result)
        set_property(TARGET taihang PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()

endif()

if(TAIHANG_ENABLE_SANITIZER AND NOT MSVC)

    target_compile_options(taihang PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(taihang PRIVATE -fsanitize=address)

endif()

# ------------------------------------------------------------
# 7. Tests
# ------------------------------------------------------------

if(TAIHANG_BUILD_TESTS)

    enable_testing()

    find_package(GTest REQUIRED)
    include(GoogleTest)

    file(GLOB TEST_FILES CONFIGURE_DEPENDS tests/test_*.cpp)

    foreach(test_source ${TEST_FILES})

        get_filename_component(test_name ${test_source} NAME_WE)

        add_executable(${test_name} ${test_source})

        taihang_apply_arch_flags(${test_name})

        target_link_libraries(${test_name}
            PRIVATE
                taihang
                GTest::gtest_main
        )

        gtest_discover_tests(${test_name})

    endforeach()

endif()

# ------------------------------------------------------------
# 8. Benchmarks
# ------------------------------------------------------------

option(TAIHANG_BUILD_BENCHMARKS "Build benchmark suite" ON)

if(TAIHANG_BUILD_BENCHMARKS)

    file(GLOB BENCH_FILES CONFIGURE_DEPENDS benchmarks/bench_*.cpp)

    foreach(bench_source ${BENCH_FILES})

        get_filename_component(bench_name ${bench_source} NAME_WE)

        add_executable(${bench_name} ${bench_source})

        taihang_apply_arch_flags(${bench_name})

        target_link_libraries(${bench_name}
            PRIVATE
                taihang
        )

    endforeach()

endif()

# ------------------------------------------------------------
# 9. Installation
# ------------------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS taihang
    EXPORT taihangTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    third_party/robin_hood/robin_hood.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT taihangTargets
    FILE taihangTargets.cmake
    NAMESPACE taihang::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/taihang
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/taihangConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/taihangConfig.cmake
"include(\${CMAKE_CURRENT_LIST_DIR}/taihangTargets.cmake)"
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/taihangConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/taihangConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/taihang
)