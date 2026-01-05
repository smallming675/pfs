#pragma once
#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
enum class LogLevel { INFO, WARN, ERROR, DEBUG };

class Logger {
public:
    static void log(LogLevel level, const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::cerr << "[" << std::put_time(&tm, "%F %T") << "] "
                  << to_string(level) << ": " << msg << "\n";
    }

private:
    static const char* to_string(LogLevel lvl) {
        switch (lvl) {
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::DEBUG: return "DEBUG";
        }
        return "";
    }
};

