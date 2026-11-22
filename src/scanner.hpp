#ifndef LEAKGUARD_SCANNER_HPP
#define LEAKGUARD_SCANNER_HPP

#include "finding.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace leakguard {

struct ScanOptions {
    std::string target_path = ".";
    bool json_output = false;
    bool no_color = false;
    bool check_entropy = true;
    double entropy_threshold = 4.5;
    std::size_t max_file_bytes = 2 * 1024 * 1024;
};

struct ScanResult {
    std::vector<Finding> findings;
    ScanStats stats;
};

ScanResult run_scan(const ScanOptions& options);

}

#endif
