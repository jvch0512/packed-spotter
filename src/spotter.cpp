#include "spotter.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace spotter {

double entropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0;
    uint64_t c[256] = {0};
    for (size_t i = 0; i < n; i++) c[p[i]]++;
    double h = 0;
    for (int i = 0; i < 256; i++) if (c[i]) { double f = double(c[i]) / double(n); h -= f * std::log2(f); }
    return h;
}

static uint32_t u32(const std::vector<uint8_t>& d, size_t o) { return uint32_t(d[o]) | uint32_t(d[o + 1]) << 8 | uint32_t(d[o + 2]) << 16 | uint32_t(d[o + 3]) << 24; }
static uint16_t u16(const std::vector<uint8_t>& d, size_t o) { return uint16_t(d[o] | d[o + 1] << 8); }

static const char* kPackerNames[] = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite", ".nsp0", ".nsp1", "MPRESS1", "MPRESS2", ".enigma1"};

static void parse_pe(const std::vector<uint8_t>& d, Report& r) {
    if (d.size() < 0x40 || d[0] != 'M' || d[1] != 'Z') return;
    uint32_t pe = u32(d, 0x3c);
    if (pe > d.size() || d.size() - pe < 24 || std::memcmp(&d[pe], "PE\0\0", 4) != 0) return;
    r.is_pe = true;
    uint16_t n = u16(d, pe + 6), opt = u16(d, pe + 20);
    size_t tab = size_t(pe) + 24 + opt;
    if (n > 96) n = 96;
    for (uint16_t i = 0; i < n; i++) {
        size_t o = tab + size_t(i) * 40;
        if (o + 40 > d.size()) break;
        Section s;
        s.name.assign(reinterpret_cast<const char*>(&d[o]), strnlen(reinterpret_cast<const char*>(&d[o]), 8));
        for (char& c : s.name) if (c < 32 || c > 126) c = '?';
        s.virt_size = u32(d, o + 8); s.raw_size = u32(d, o + 16); s.raw_off = u32(d, o + 20); s.flags = u32(d, o + 36);
        if (s.raw_off <= d.size()) {
            size_t len = std::min<size_t>(s.raw_size, d.size() - s.raw_off);
            s.entropy = entropy(d.data() + s.raw_off, len);
            if (len < s.raw_size) s.notes.push_back("section runs past the end of the file");
        }
        bool x = s.flags & 0x20000000u, w = s.flags & 0x80000000u;
        if (x && w) s.notes.push_back("writable and executable");
        if (s.raw_size >= 1024 && s.entropy >= 7.2) s.notes.push_back("high entropy (compressed or encrypted)");
        if (s.raw_size == 0 && s.virt_size >= 4096) s.notes.push_back("empty on disk, large in memory (unpacking target)");
        for (const char* k : kPackerNames) if (s.name == k) s.notes.push_back("known packer section name");
        r.sections.push_back(s);
    }
}

Report analyze(const std::vector<uint8_t>& d, uint32_t window) {
    Report r; r.size = d.size(); r.window = window ? window : 512;
    r.entropy = entropy(d.data(), d.size());
    for (size_t o = 0; o < d.size(); o += r.window) r.windows.push_back(entropy(d.data() + o, std::min<size_t>(r.window, d.size() - o)));
    parse_pe(d, r);

    int score = 0;
    size_t hot = 0;
    for (double w : r.windows) if (w >= 7.2) hot++;
    double hot_ratio = r.windows.empty() ? 0 : double(hot) / double(r.windows.size());
    if (hot_ratio >= 0.7) { score += 45; r.reasons.push_back("most of the file is near-random data (" + std::to_string(int(hot_ratio * 100)) + "% of windows at 7.2+ bits/byte)"); }
    else if (hot_ratio >= 0.35) { score += 25; r.reasons.push_back("a large part of the file is near-random data (" + std::to_string(int(hot_ratio * 100)) + "% of windows)"); }
    if (r.is_pe) {
        bool packer = false, wx = false, hi = false, empty = false;
        for (auto& s : r.sections) for (auto& n : s.notes) {
            if (n.rfind("known packer", 0) == 0) packer = true;
            if (n.rfind("writable and exec", 0) == 0) wx = true;
            if (n.rfind("high entropy", 0) == 0) hi = true;
            if (n.rfind("empty on disk", 0) == 0) empty = true;
        }
        if (packer) { score += 30; r.reasons.push_back("section names used by known packers"); }
        if (empty) { score += 15; r.reasons.push_back("a section with no data on disk but a large virtual size: the classic unpacking target"); }
        if (wx) { score += 15; r.reasons.push_back("writable and executable section"); }
        if (hi) { score += 15; r.reasons.push_back("high-entropy section"); }
        if (r.sections.size() <= 2) { score += 5; r.reasons.push_back("very few sections"); }
    }
    r.score = std::min(100, score);
    r.verdict = r.score >= 60 ? "likely packed or encrypted" : r.score >= 30 ? "suspicious" : "looks normal";
    if (r.reasons.empty()) r.reasons.push_back("no packing indicators found");
    return r;
}

std::string render_text(const Report& r) {
    std::ostringstream o; char b[160];
    std::snprintf(b, sizeof b, "size %llu bytes, entropy %.2f bits/byte, %s\n", (unsigned long long)r.size, r.entropy, r.is_pe ? "PE file" : "raw file");
    o << b;
    std::snprintf(b, sizeof b, "verdict: %s (score %d/100)\n", r.verdict.c_str(), r.score);
    o << b;
    for (auto& s : r.reasons) o << "  - " << s << "\n";
    if (!r.sections.empty()) {
        o << "\nsections\n";
        for (auto& s : r.sections) {
            std::snprintf(b, sizeof b, "  %-9s raw %7u  virt %7u  entropy %.2f", s.name.c_str(), s.raw_size, s.virt_size, s.entropy);
            o << b;
            for (size_t i = 0; i < s.notes.size(); i++) o << (i ? "; " : "  <- ") << s.notes[i];
            o << "\n";
        }
    }
    static const char* ramp = " .:-=+*#%@";
    o << "\nentropy map (one character per " << r.window << " bytes)\n";
    for (size_t i = 0; i < r.windows.size(); i++) {
        if (i % 64 == 0) o << (i ? "\n" : "") << "  ";
        int k = int(r.windows[i] / 8.0 * 9.999); o << ramp[std::max(0, std::min(9, k))];
    }
    o << "\n";
    return o.str();
}

static std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else if (c == '"') o += "&quot;"; else o += c; }
    return o;
}

std::string render_html(const Report& r, const std::string& title) {
    std::ostringstream o; char b[200];
    o << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>packed-spotter</title>"
         "<style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}h2{margin:24px 0 6px;font-size:16px}.sub{color:#8b98a8}"
         ".map{display:grid;grid-template-columns:repeat(64,1fr);gap:2px;max-width:900px}.c{aspect-ratio:1;border-radius:2px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2a3441}th{color:#8b98a8}.bad{color:#f85149;font-weight:700}.mid{color:#e3b341;font-weight:700}.ok{color:#3fb950;font-weight:700}</style></head><body>";
    o << "<h1>packed-spotter</h1><p class=\"sub\">Packed and encrypted binary spotter in C++17, no dependencies. Sample: " << esc(title) << " (synthetic, not real malware).</p>";
    std::snprintf(b, sizeof b, "<p class=\"%s\">%s, score %d/100</p>", r.score >= 60 ? "bad" : r.score >= 30 ? "mid" : "ok", r.verdict.c_str(), r.score);
    o << b << "<ul>";
    for (auto& s : r.reasons) o << "<li>" << esc(s) << "</li>";
    o << "</ul><h2>Entropy map</h2><div class=\"map\">";
    for (double w : r.windows) {
        int hue = int(120 - (w / 8.0) * 120); if (hue < 0) hue = 0;
        std::snprintf(b, sizeof b, "<div class=\"c\" style=\"background:hsl(%d,70%%,%d%%)\" title=\"%.2f\"></div>", hue, 30 + int(w * 3), w);
        o << b;
    }
    o << "</div><p class=\"sub\">One cell per " << r.window << " bytes. Green is structured data, red is close to random.</p>";
    if (!r.sections.empty()) {
        o << "<h2>Sections</h2><table><tr><th>Name</th><th>Raw</th><th>Virtual</th><th>Entropy</th><th>Notes</th></tr>";
        for (auto& s : r.sections) {
            std::string notes; for (size_t i = 0; i < s.notes.size(); i++) notes += (i ? "; " : "") + s.notes[i];
            std::snprintf(b, sizeof b, "<td>%u</td><td>%u</td><td>%.2f</td>", s.raw_size, s.virt_size, s.entropy);
            o << "<tr><td>" << esc(s.name) << "</td>" << b << "<td>" << esc(notes) << "</td></tr>";
        }
        o << "</table>";
    }
    o << "<p class=\"sub\">High entropy also appears in legitimate files (archives, media, installers). Treat the score as a reason to look closer, not as a verdict.</p></body></html>\n";
    return o.str();
}

}  // namespace spotter
