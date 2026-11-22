#include "entropy.hpp"

#include <array>
#include <cmath>
#include <cstddef>

namespace leakguard {

double shannon_entropy(const std::string& input) {
    if (input.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> freq{};
    for (unsigned char c : input) {
        freq[c]++;
    }

    double entropy = 0.0;
    const double len = static_cast<double>(input.size());
    for (std::size_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / len;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

std::string mask_secret(const std::string& secret) {
    const std::size_t len = secret.size();
    if (len <= 8) {
        return std::string(len, '*');
    }
    const std::size_t prefix = std::min<std::size_t>(4, len / 4);
    const std::size_t suffix = std::min<std::size_t>(3, len / 4);
    const std::size_t hidden = len - prefix - suffix;
    return secret.substr(0, prefix) + std::string(std::min<std::size_t>(hidden, 12), '*') + secret.substr(len - suffix);
}

bool is_binary_sample(const std::string& data) {
    for (char c : data) {
        if (c == '\0') {
            return true;
        }
    }
    return false;
}

}
