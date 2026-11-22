#include "reporter.hpp"
#include "scanner.hpp"

#include <filesystem>
#include <iostream>
#include <string>

namespace {

constexpr const char* VERSION = "1.0.0";

void print_help() {
    std::cout
        << "leakguard " << VERSION << " — zero-dependency C++17 secret scanner\n\n"
        << "Usage:\n"
        << "  leakguard [path] [options]\n\n"
        << "Options:\n"
        << "  --json               Output scan results in JSON format\n"
        << "  --no-color           Disable ANSI terminal colors\n"
        << "  --no-entropy         Disable Shannon entropy heuristic checks\n"
        << "  --threshold <num>    Set entropy threshold (default: 4.5)\n"
        << "  -v, --version        Print version\n"
        << "  -h, --help           Show this help message\n";
}

}

int main(int argc, char* argv[]) {
    leakguard::ScanOptions options;
    bool path_set = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << "leakguard " << VERSION << '\n';
            return 0;
        }
        if (arg == "--json") {
            options.json_output = true;
        } else if (arg == "--no-color") {
            options.no_color = true;
        } else if (arg == "--no-entropy") {
            options.check_entropy = false;
        } else if (arg == "--threshold") {
            if (i + 1 >= argc) {
                std::cerr << "Error: missing value for --threshold\n";
                return 2;
            }
            try {
                options.entropy_threshold = std::stod(argv[++i]);
            } catch (...) {
                std::cerr << "Error: invalid numeric value for --threshold\n";
                return 2;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: unknown option '" << arg << "'\n";
            return 2;
        } else if (!path_set) {
            options.target_path = arg;
            path_set = true;
        } else {
            std::cerr << "Error: unexpected argument '" << arg << "'\n";
            return 2;
        }
    }

    if (!std::filesystem::exists(options.target_path)) {
        std::cerr << "Error: path does not exist: " << options.target_path << '\n';
        return 2;
    }

    leakguard::ScanResult result = leakguard::run_scan(options);
    if (options.json_output) {
        leakguard::print_json_report(result, std::cout);
    } else {
        leakguard::print_text_report(result, !options.no_color, std::cout);
    }

    return result.findings.empty() ? 0 : 1;
}
