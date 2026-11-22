#ifndef LEAKGUARD_RULES_HPP
#define LEAKGUARD_RULES_HPP

#include "finding.hpp"

#include <regex>
#include <string>
#include <vector>

namespace leakguard {

struct Rule {
    std::string name;
    Severity severity;
    std::regex pattern;
};

std::vector<Rule> build_default_rules();
bool line_has_secret_keyword(const std::string& line);

}

#endif
