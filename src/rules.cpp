#include "rules.hpp"

#include <algorithm>
#include <cctype>

namespace leakguard {

std::vector<Rule> build_default_rules() {
    return {
        {
            "GitHub Personal Access Token",
            Severity::High,
            std::regex(R"(ghp_[A-Za-z0-9]{36})")
        },
        {
            "GitHub Fine-Grained Token",
            Severity::High,
            std::regex(R"(github_pat_[A-Za-z0-9_]{22,})")
        },
        {
            "AWS Access Key ID",
            Severity::High,
            std::regex(R"(AKIA[0-9A-Z]{16})")
        },
        {
            "Stripe Secret Key",
            Severity::High,
            std::regex(R"(sk_(live|test)_[0-9a-zA-Z]{24,})")
        },
        {
            "OpenAI API Key",
            Severity::High,
            std::regex(R"(sk-(proj-)?[A-Za-z0-9_-]{20,})")
        },
        {
            "Google API Key",
            Severity::High,
            std::regex(R"(AIza[0-9A-Za-z\-_]{35})")
        },
        {
            "Slack Token",
            Severity::High,
            std::regex(R"(xox[baprs]-[0-9A-Za-z\-]{10,})")
        },
        {
            "Private Key Header",
            Severity::High,
            std::regex(R"(-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")
        },
        {
            "Hardcoded Credential Assignment",
            Severity::Medium,
            std::regex(R"((?:api_key|apikey|secret|token|password|passwd|access_key)\s*[:=]\s*["']([^"'\s]{12,})["'])", std::regex::icase)
        }
    };
}

bool line_has_secret_keyword(const std::string& line) {
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    static const std::vector<std::string> keywords = {
        "secret", "token", "apikey", "api_key", "password", "passwd", "auth", "bearer", "private_key"
    };

    for (const auto& kw : keywords) {
        if (lower.find(kw) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}
