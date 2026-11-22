#include "reporter.hpp"

#include <iomanip>
#include <sstream>

namespace leakguard {

namespace {

std::string json_escape(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:   oss << c; break;
        }
    }
    return oss.str();
}

const char* severity_color(Severity s) {
    switch (s) {
        case Severity::High:   return "\033[1;31m";
        case Severity::Medium: return "\033[1;33m";
        case Severity::Low:    return "\033[1;36m";
    }
    return "";
}

}

void print_text_report(const ScanResult& result, bool use_color, std::ostream& out) {
    const char* reset = use_color ? "\033[0m" : "";
    const char* dim = use_color ? "\033[2m" : "";
    const char* green = use_color ? "\033[1;32m" : "";

    out << '\n';
    for (const auto& f : result.findings) {
        const char* col = use_color ? severity_color(f.severity) : "";
        out << "  " << col << "[" << std::left << std::setw(4) << severity_label(f.severity) << "]" << reset
            << "  " << f.file << ":" << f.line << '\n'
            << "          " << f.rule << "  " << dim << "-> " << f.masked_secret
            << " (entropy " << std::fixed << std::setprecision(2) << f.entropy << ")" << reset << "\n\n";
    }

    if (result.findings.empty()) {
        out << "  " << green << "No secrets detected." << reset << '\n';
    }

    out << "  " << dim << "Scanned " << result.stats.files_scanned << " files ("
        << result.stats.lines_scanned << " lines) in "
        << std::fixed << std::setprecision(1) << result.stats.elapsed_ms << " ms — "
        << result.findings.size() << " potential leak(s) found." << reset << "\n\n";
}

void print_json_report(const ScanResult& result, std::ostream& out) {
    out << "{\n";
    out << "  \"stats\": {\n";
    out << "    \"files_scanned\": " << result.stats.files_scanned << ",\n";
    out << "    \"lines_scanned\": " << result.stats.lines_scanned << ",\n";
    out << "    \"elapsed_ms\": " << std::fixed << std::setprecision(2) << result.stats.elapsed_ms << ",\n";
    out << "    \"leaks_found\": " << result.findings.size() << "\n";
    out << "  },\n";
    out << "  \"findings\": [\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& f = result.findings[i];
        out << "    {\n";
        out << "      \"severity\": \"" << severity_label(f.severity) << "\",\n";
        out << "      \"file\": \"" << json_escape(f.file) << "\",\n";
        out << "      \"line\": " << f.line << ",\n";
        out << "      \"rule\": \"" << json_escape(f.rule) << "\",\n";
        out << "      \"secret\": \"" << json_escape(f.masked_secret) << "\",\n";
        out << "      \"entropy\": " << std::fixed << std::setprecision(2) << f.entropy << "\n";
        out << "    }" << (i + 1 < result.findings.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

}
