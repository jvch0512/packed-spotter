#include "../src/spotter.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
using namespace spotter;

static int n = 0, failed = 0;
#define CHECK(name, cond) do { n++; if (!(cond)) { failed++; std::printf("FAIL: %s\n", name); } } while (0)

static std::vector<uint8_t> load(const char* p) { std::ifstream f(p, std::ios::binary); return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()); }
static std::vector<uint8_t> noise(size_t len, uint64_t x) { std::vector<uint8_t> v; for (size_t i = 0; i < len; i++) { x = x * 6364136223846793005ULL + 1442695040888963407ULL; v.push_back(uint8_t(x >> 33)); } return v; }

int main() {
    uint8_t z[256] = {0};
    CHECK("entropy of zeros is 0", entropy(z, 256) == 0);
    uint8_t all[256]; for (int i = 0; i < 256; i++) all[i] = uint8_t(i);
    CHECK("entropy of all byte values is 8", entropy(all, 256) > 7.999);
    uint8_t two[4] = {0, 1, 0, 1};
    CHECK("two equiprobable symbols give 1 bit", entropy(two, 4) > 0.999 && entropy(two, 4) < 1.001);
    CHECK("empty input is 0", entropy(z, 0) == 0);

    auto empty = analyze({});
    CHECK("empty file does not crash", empty.windows.empty() && empty.verdict == "looks normal");
    auto rnd = analyze(noise(20000, 5));
    CHECK("random data is flagged", rnd.score >= 30 && rnd.entropy > 7.9);
    std::vector<uint8_t> text; for (int i = 0; i < 20000; i++) text.push_back("hello world, this is plain text. "[i % 33]);
    CHECK("plain text is normal", analyze(text).verdict == "looks normal");

    auto nrm = load("examples/normal.exe");
    if (!nrm.empty()) {
        auto r = analyze(nrm);
        CHECK("sample normal: PE with 4 sections", r.is_pe && r.sections.size() == 4);
        CHECK("sample normal: score 0", r.score == 0);
        CHECK("sample normal: .data is empty on disk half", r.sections[2].raw_size == 2048 && r.sections[2].virt_size == 4096 && r.sections[2].notes.empty());
        auto u = analyze(load("examples/upx-like.exe"));
        CHECK("sample upx-like: likely packed", u.score >= 60 && u.verdict == "likely packed or encrypted");
        bool sawName = false, sawEmpty = false, sawWX = false;
        for (auto& s : u.sections) for (auto& t : s.notes) { if (t.find("known packer") == 0) sawName = true; if (t.find("empty on disk") == 0) sawEmpty = true; if (t.find("writable and executable") == 0) sawWX = true; }
        CHECK("sample upx-like: packer name, empty section, W+X", sawName && sawEmpty && sawWX);
        auto b = analyze(load("examples/encrypted-blob.bin"));
        CHECK("sample blob: not PE, high entropy", !b.is_pe && b.entropy > 7.9 && b.score >= 30);

        auto html = render_html(u, "<img src=x onerror=1>");
        CHECK("html escapes the title", html.find("<img src=x") == std::string::npos && html.find("&lt;img") != std::string::npos);
        CHECK("html has a strict CSP", html.find("default-src 'none'") != std::string::npos);

        /* robustness: truncated and corrupted PE files must not crash (run under ASan/UBSan in CI) */
        uint64_t x = 1; bool ok = true;
        for (int it = 0; it < 3000; it++) {
            auto m = load("examples/upx-like.exe");
            for (int j = 0; j < 6; j++) { x = x * 6364136223846793005ULL + 1; m[(x >> 20) % m.size()] = uint8_t(x >> 9); }
            x = x * 6364136223846793005ULL + 1; if (it % 3 == 0) m.resize((x >> 20) % m.size());
            auto r2 = analyze(m, 64 + unsigned(it % 5) * 100);
            if (r2.score < 0 || r2.score > 100) ok = false;
        }
        CHECK("fuzz: 3000 corrupted PE files, no crash", ok);
    } else std::printf("skipped sample tests (run from repo root)\n");

    std::printf(failed ? "%d of %d failed\n" : "all %d passed\n", failed ? failed : n, n);
    return failed ? 1 : 0;
}
