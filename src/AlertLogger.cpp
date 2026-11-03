#include "AlertLogger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

AlertLogger::AlertLogger(const std::string& filePath)
    : filePath_(filePath) {}

std::string AlertLogger::buildTimestamp() const {
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const std::time_t nowTime = clock::to_time_t(now);

    std::tm localTime{};
#if defined(_WIN32)
    localtime_s(&localTime, &nowTime);
#else
    localtime_r(&nowTime, &localTime);
#endif

    std::ostringstream stream;
    stream << '[' << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S") << ']';
    return stream.str();
}

std::string AlertLogger::formatEntry(const std::string& timestamp,
                                     const std::string& level,
                                     const std::string& message,
                                     uint16_t transId,
                                     uint8_t unitId) const {
    std::ostringstream stream;
    stream << timestamp
           << " [" << level << "]"
           << " TransID=" << transId
           << " UnitID=" << static_cast<unsigned int>(unitId)
           << " " << message;
    return stream.str();
}

void AlertLogger::logAlert(const std::string& level,
                           const std::string& message,
                           uint16_t transId,
                           uint8_t unitId) {
    const std::string timestamp = buildTimestamp();
    const std::string entry = formatEntry(timestamp, level, message, transId, unitId);

    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream file(filePath_, std::ios::app);
    if (file.is_open()) {
        file << entry << '\n';
    }

    std::cout << entry << std::endl;
}