#include "scanner.hpp"
#include "entropy.hpp"
#include "rules.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <regex>
#include <unordered_set>

namespace fs = std::filesystem;

namespace leakguard {

namespace {

bool is_ignored_directory(const std::string& name) {
    static const std::unordered_set<std::string> ignored = {
        ".git", "node_modules", "build", "dist", "out", "target",
        ".idea", ".vscode", "__pycache__", "vendor", ".gradle"
    };
    return ignored.count(name) > 0;
}

bool is_binary_extension(const fs::path& p) {
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    static const std::unordered_set<std::string> binary_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
        ".zip", ".tar", ".gz", ".7z", ".rar", ".jar", ".war",
        ".exe", ".dll", ".so", ".dylib", ".class", ".o", ".obj",
        ".pdf", ".mp4", ".mp3", ".wav", ".mov", ".woff", ".woff2", ".ttf"
    };
    return binary_exts.count(ext) > 0;
}

void scan_file(const fs::path& filepath,
               const fs::path& base_root,
               const std::vector<Rule>& rules,
               const ScanOptions& options,
               ScanResult& result) {
    std::error_code ec;
    const auto file_size = fs::file_size(filepath, ec);
    if (ec || file_size == 0 || file_size > options.max_file_bytes) {
        return;
    }

    std::ifstream in(filepath, std::ios::binary);
    if (!in.is_open()) {
        return;
    }

    std::string probe(std::min<std::size_t>(file_size, 1024), '\0');
    in.read(probe.data(), static_cast<std::streamsize>(probe.size()));
    if (is_binary_sample(probe)) {
        return;
    }

    in.clear();
    in.seekg(0);

    std::string display_path = filepath.string();
    fs::path rel = fs::relative(filepath, base_root, ec);
    if (!ec && !rel.empty()) {
        display_path = rel.generic_string();
    }

    static const std::regex quoted_literal(R"(["']([A-Za-z0-9+/=_\-]{20,})["'])");

    result.stats.files_scanned++;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(in, line)) {
        line_number++;
        result.stats.lines_scanned++;

        if (line.size() > 4096) {
            continue;
        }

        bool matched_rule = false;
        for (const auto& rule : rules) {
            std::smatch match;
            if (std::regex_search(line, match, rule.pattern)) {
                std::string raw = match.size() > 1 && match[1].matched ? match[1].str() : match[0].str();
                result.findings.push_back({
                    display_path,
                    line_number,
                    rule.name,
                    rule.severity,
                    mask_secret(raw),
                    shannon_entropy(raw)
                });
                matched_rule = true;
                break;
            }
        }

        if (!matched_rule && options.check_entropy && line_has_secret_keyword(line)) {
            auto begin = std::sregex_iterator(line.begin(), line.end(), quoted_literal);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                std::string candidate = (*it)[1].str();
                double ent = shannon_entropy(candidate);
                if (ent >= options.entropy_threshold) {
                    result.findings.push_back({
                        display_path,
                        line_number,
                        "High-Entropy Secret String",
                        Severity::Medium,
                        mask_secret(candidate),
                        ent
                    });
                    break;
                }
            }
        }
    }
}

}

ScanResult run_scan(const ScanOptions& options) {
    auto start = std::chrono::steady_clock::now();
    ScanResult result;
    std::vector<Rule> rules = build_default_rules();

    fs::path target(options.target_path);
    std::error_code ec;

    if (fs::is_regular_file(target, ec)) {
        scan_file(target, target.parent_path(), rules, options, result);
    } else if (fs::is_directory(target, ec)) {
        auto it = fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied, ec);
        auto end = fs::recursive_directory_iterator();
        while (it != end && !ec) {
            const fs::directory_entry& entry = *it;
            if (entry.is_directory(ec)) {
                if (is_ignored_directory(entry.path().filename().string())) {
                    it.disable_recursion_pending();
                }
            } else if (entry.is_regular_file(ec) && !is_binary_extension(entry.path())) {
                scan_file(entry.path(), target, rules, options, result);
            }
            it.increment(ec);
        }
    }

    auto finish = std::chrono::steady_clock::now();
    result.stats.elapsed_ms = std::chrono::duration<double, std::milli>(finish - start).count();
    return result;
}

}
