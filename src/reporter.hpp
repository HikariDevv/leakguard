#ifndef LEAKGUARD_REPORTER_HPP
#define LEAKGUARD_REPORTER_HPP

#include "scanner.hpp"

#include <ostream>

namespace leakguard {

void print_text_report(const ScanResult& result, bool use_color, std::ostream& out);
void print_json_report(const ScanResult& result, std::ostream& out);

}

#endif
