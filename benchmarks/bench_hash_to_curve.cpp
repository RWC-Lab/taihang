/****************************************************************************
 * @file      bench_hash_to_curve.cpp
 * @brief     Compare RFC 9380 P-256 SSWU with Taihang try-and-increment.
 *****************************************************************************/

#include <openssl/obj_mac.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <taihang/crypto/ec_group.hpp>

namespace {

using namespace taihang;
using Clock = std::chrono::steady_clock;

struct Statistics {
    double mean_us;
    double median_us;
    double p95_us;
    double p99_us;
    double minimum_us;
    double maximum_us;
};

Statistics summarize(std::vector<double> samples) {
    std::sort(samples.begin(), samples.end());
    double sum = 0.0;
    for (const double sample : samples) sum += sample;
    const auto percentile = [&](double p) {
        const std::size_t index = static_cast<std::size_t>(
            p * static_cast<double>(samples.size() - 1));
        return samples[index];
    };
    return {
        sum / static_cast<double>(samples.size()),
        percentile(0.50),
        percentile(0.95),
        percentile(0.99),
        samples.front(),
        samples.back()
    };
}

template <typename Mapping>
void measure_pass(const std::vector<std::string>& messages,
                  Mapping&& mapping,
                  std::vector<double>& samples,
                  std::uint64_t& checksum) {
    for (const auto& message : messages) {
        const auto start = Clock::now();
        ECPoint point = mapping(message);
        const auto end = Clock::now();
        samples.push_back(
            std::chrono::duration<double, std::micro>(end - start).count());
        checksum += point.to_bytes()[1];
    }
}

void print_row(const std::string& name, const Statistics& stats) {
    std::cout << std::left << std::setw(24) << name
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(12) << stats.mean_us
              << std::setw(12) << stats.median_us
              << std::setw(12) << stats.p95_us
              << std::setw(12) << stats.p99_us
              << std::setw(12) << stats.minimum_us
              << std::setw(12) << stats.maximum_us << '\n';
}

} // namespace

int main(int argc, char** argv) {
    const std::size_t message_count =
        argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 4096;
    const std::size_t rounds =
        argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 5;
    if (message_count == 0 || rounds == 0) return 1;

    const ECGroup group(NID_X9_62_prime256v1);
    const std::string dst =
        "TAIHANG-BENCHMARK-V01-P256_XMD:SHA-256_SSWU_RO_";
    std::vector<std::string> messages;
    messages.reserve(message_count);
    for (std::size_t i = 0; i < message_count; ++i) {
        std::string suffix = std::to_string(i);
        messages.push_back("taihang/hash-to-curve/" +
                           std::string(20 - std::min<std::size_t>(suffix.size(), 20), '0') +
                           suffix);
    }

    const auto fast_mapping = [&](const std::string& message) {
        return hash_to_curve_fast(message, group);
    };
    const auto standard_mapping = [&](const std::string& message) {
        return hash_to_curve_standard(message, dst, group);
    };

    std::uint64_t checksum = 0;
    for (std::size_t i = 0; i < std::min<std::size_t>(messages.size(), 128); ++i) {
        checksum += fast_mapping(messages[i]).to_bytes()[1];
        checksum += standard_mapping(messages[i]).to_bytes()[1];
    }

    std::vector<double> fast_samples;
    std::vector<double> standard_samples;
    fast_samples.reserve(messages.size() * rounds);
    standard_samples.reserve(messages.size() * rounds);
    for (std::size_t round = 0; round < rounds; ++round) {
        if (round % 2 == 0) {
            measure_pass(messages, fast_mapping, fast_samples, checksum);
            measure_pass(messages, standard_mapping, standard_samples, checksum);
        } else {
            measure_pass(messages, standard_mapping, standard_samples, checksum);
            measure_pass(messages, fast_mapping, fast_samples, checksum);
        }
    }
    const Statistics fast = summarize(std::move(fast_samples));
    const Statistics standard = summarize(std::move(standard_samples));

    std::cout << "P-256 hash-to-curve, " << message_count << " messages x "
              << rounds << " rounds\n";
    std::cout << std::left << std::setw(24) << "Mapping"
              << std::right << std::setw(12) << "Mean us"
              << std::setw(12) << "P50 us"
              << std::setw(12) << "P95 us"
              << std::setw(12) << "P99 us"
              << std::setw(12) << "Min us"
              << std::setw(12) << "Max us" << '\n';
    print_row("Try-and-increment", fast);
    print_row("RFC 9380 SSWU", standard);
    std::cout << "SSWU / try-and-increment mean ratio: "
              << std::fixed << std::setprecision(2)
              << standard.mean_us / fast.mean_us << "x\n";
    std::cout << "checksum: " << checksum << '\n';
    return 0;
}
