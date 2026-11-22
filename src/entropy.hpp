#ifndef LEAKGUARD_ENTROPY_HPP
#define LEAKGUARD_ENTROPY_HPP

#include <string>

namespace leakguard {

double shannon_entropy(const std::string& input);
std::string mask_secret(const std::string& secret);
bool is_binary_sample(const std::string& data);

}

#endif
