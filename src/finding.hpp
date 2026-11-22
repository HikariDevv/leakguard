#ifndef LEAKGUARD_FINDING_HPP
#define LEAKGUARD_FINDING_HPP

#include <cstddef>
#include <string>

namespace leakguard {

enum class Severity {
    High,
    Medium,
    Low
};

struct Finding {
    std::string file;
    std::size_t line;
    std::string rule;
    Severity severity;
    std::string masked_secret;
    double entropy;
};

struct ScanStats {
    std::size_t files_scanned = 0;
    std::size_t lines_scanned = 0;
    double elapsed_ms = 0.0;
};

inline const char* severity_label(Severity s) {
    switch (s) {
        case Severity::High:
            return "HIGH";
        case Severity::Medium:
            return "MED";
        case Severity::Low:
            return "LOW";
    }
    return "LOW";
}

}

#endif
