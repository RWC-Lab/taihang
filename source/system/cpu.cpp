/****************************************************************************
 * @file      cpu.cpp
 * @brief     CPU hardware utilities.
 ****************************************************************************/

#include <taihang/system/cpu.hpp>

#include <algorithm>
#include <thread>

#if (defined(__x86_64__) || defined(__i386__)) && \
    (defined(__GNUC__) || defined(__clang__))
#define TAIHANG_HAS_X86_CPUID 1
#include <cpuid.h>
#else
#define TAIHANG_HAS_X86_CPUID 0
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace taihang::system {

CpuFeatures get_cpu_features() noexcept
{
    CpuFeatures features{};
#if TAIHANG_HAS_X86_CPUID
    if (__get_cpuid_max(0, nullptr) < 1) {
        return features;
    }

    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    if ((ecx & bit_AVX) == 0 || (ecx & bit_OSXSAVE) == 0 ||
        __get_cpuid_max(0, nullptr) < 7) {
        return features;
    }

    unsigned int xcr0_low = 0, xcr0_high = 0;
    __asm__ volatile("xgetbv" : "=a"(xcr0_low), "=d"(xcr0_high) : "c"(0));
    (void)xcr0_high;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    features.avx2 = (xcr0_low & 0x6U) == 0x6U && (ebx & bit_AVX2) != 0;
    features.avx512_ifma =
        (xcr0_low & 0xe6U) == 0xe6U &&
        (ebx & bit_AVX512F) != 0 && (ebx & bit_AVX512IFMA) != 0;
#endif
    return features;
}

unsigned get_physical_core_count()
{
    unsigned logical  = std::thread::hardware_concurrency();
    unsigned physical = logical;

#if defined(__APPLE__)

    int value = 0;
    size_t len = sizeof(value);

    if (sysctlbyname("hw.physicalcpu",
                     &value,
                     &len,
                     nullptr,
                     0) == 0 &&
        value > 0)
    {
        physical = static_cast<unsigned>(value);
    }

#elif defined(__linux__)

    // Temporary fallback.
    // A topology-based implementation can replace this later.
    physical = logical;

#endif

    return std::max(1u, physical);
}

} // namespace taihang::system

#undef TAIHANG_HAS_X86_CPUID
