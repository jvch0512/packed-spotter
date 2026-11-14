#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace spotter {

struct Section {
    std::string name;
    uint32_t virt_size = 0, raw_size = 0, raw_off = 0, flags = 0;
    double entropy = 0;
    std::vector<std::string> notes;
};

struct Report {
    uint64_t size = 0;
    double entropy = 0;
    bool is_pe = false;
    std::vector<Section> sections;
    std::vector<double> windows;      // entropy per window
    uint32_t window = 512;
    int score = 0;                     // 0..100
    std::string verdict;               // "likely packed or encrypted" / "suspicious" / "looks normal"
    std::vector<std::string> reasons;
};

double entropy(const uint8_t* p, size_t n);                 // Shannon, bits per byte (0..8)
Report analyze(const std::vector<uint8_t>& data, uint32_t window = 512);
std::string render_text(const Report&);
std::string render_html(const Report&, const std::string& title);

}  // namespace spotter
