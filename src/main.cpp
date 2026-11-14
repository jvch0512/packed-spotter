#include "spotter.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>

int main(int argc, char** argv) {
    const char* usage = "usage: packed-spotter <file> [--html] [--window N] [--fail-on-packed]\nExit: 0 ok, 1 likely packed with --fail-on-packed, 2 bad input.\n";
    if (argc < 2 || argv[1][0] == '-') { std::fputs(usage, stderr); return 2; }
    bool html = false, fail = false; unsigned window = 512;
    for (int i = 2; i < argc; i++) {
        if (!std::strcmp(argv[i], "--html")) html = true;
        else if (!std::strcmp(argv[i], "--fail-on-packed")) fail = true;
        else if (!std::strcmp(argv[i], "--window") && i + 1 < argc) { long v = std::strtol(argv[++i], nullptr, 10); if (v < 64 || v > 1 << 20) { std::fputs("error: --window must be 64..1048576\n", stderr); return 2; } window = unsigned(v); }
        else { std::fprintf(stderr, "error: unknown option %s\n%s", argv[i], usage); return 2; }
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { std::fprintf(stderr, "error: cannot open %s\n", argv[1]); return 2; }
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (d.size() > (512u << 20)) { std::fputs("error: file too large (limit 512 MB)\n", stderr); return 2; }
    auto r = spotter::analyze(d, window);
    std::string out = html ? spotter::render_html(r, argv[1]) : spotter::render_text(r);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return (fail && r.score >= 60) ? 1 : 0;
}
