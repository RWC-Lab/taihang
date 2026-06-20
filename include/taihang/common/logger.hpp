#ifndef TAIHANG_LOGGER_HPP
#define TAIHANG_LOGGER_HPP

#include <iostream>
#include <string>
#include <string_view>
#include <chrono>


namespace taihang{

class Logger {
public:
    static Logger& get_instance();

    void set_output_stream(std::ostream& os);
    void log(std::string_view tag, std::string_view message);

private:
    Logger();
    ~Logger() = default;

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // set out_stream as a pointer is convenient cause it can be flexibly rebinding
    // rather than std::ostream or reference 
    std::ostream* out_stream; 
};


// ============================================================================
// Scoped Timer
// ============================================================================

class ScopedTimer {
public:
    ScopedTimer(std::string_view tag, std::string_view label);
    ~ScopedTimer();

private:
    std::string tag;
    std::string label;

    std::chrono::steady_clock::time_point start_time;
};

} // namespace taihang


// ============================================================================
// Compile-Time Switch
// ============================================================================

#ifdef TAIHANG_ENABLE_LOGGER

#define TAIHANG_LOG(tag, msg) \
    taihang::Logger::get_instance().log(tag, msg)

// using the macro __LINE__ to automatically naming timer object
#define TAIHANG_TIMER(tag, label) \
    taihang::ScopedTimer timer_##__LINE__(tag, label)

#else

#define TAIHANG_LOG(tag, msg) \
    do {} while(0)

#define TAIHANG_TIMER(tag, label) \
    do {} while(0)

#endif

#endif // TAIHANG_DIAGNOSTIC_HPP