#pragma once

#include <cstdint>
#include <mutex>
#include <string>

class AlertLogger {
public:
    explicit AlertLogger(const std::string& filePath = "alerts.log");

    void logAlert(const std::string& level,
                  const std::string& message,
                  uint16_t transId,
                  uint8_t unitId);

private:
    std::string buildTimestamp() const;
    std::string formatEntry(const std::string& timestamp,
                            const std::string& level,
                            const std::string& message,
                            uint16_t transId,
                            uint8_t unitId) const;

    std::string filePath_;
    mutable std::mutex mutex_;
};