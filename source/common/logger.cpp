#include <taihang/common/logger.hpp>

namespace taihang {

// ============================================================================
// Logger
// ============================================================================

Logger& Logger::get_instance()
{
    static Logger instance;
    return instance;
}

Logger::Logger(): out_stream(&std::cout) {}

void Logger::set_output_stream(std::ostream& os)
{
    out_stream = &os;
}

void Logger::log(std::string_view tag, std::string_view message)
{
    (*out_stream)
        << "[" << tag << "] "
        << message
        << '\n';

    out_stream->flush();
}

// ============================================================================
// ScopedTimer
// ============================================================================

ScopedTimer::ScopedTimer(std::string_view tag, std::string_view label)
    : tag(tag),
      label(label),
      start_time(std::chrono::steady_clock::now())
{}

ScopedTimer::~ScopedTimer()
{
#ifdef TAIHANG_ENABLE_LOGGER

    auto end_time = std::chrono::steady_clock::now();

    double ms = std::chrono::duration<double,std::milli>(end_time - start_time).count();

    Logger::get_instance().log(tag, label + " took " + std::to_string(ms) + " ms");
#endif
}

} // namespace taihang