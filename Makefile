CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2

packed-spotter: src/spotter.cpp src/main.cpp src/spotter.hpp
	$(CXX) $(CXXFLAGS) -o $@ src/spotter.cpp src/main.cpp

test: tests/test.cpp src/spotter.cpp src/spotter.hpp
	$(CXX) $(CXXFLAGS) -g -fsanitize=address,undefined -o tests/run tests/test.cpp src/spotter.cpp
	./tests/run

sample: packed-spotter
	python3 examples/make_samples.py
	( for f in normal.exe upx-like.exe encrypted-blob.bin; do echo "== $$f"; ./packed-spotter examples/$$f; echo; done ) > docs/sample-output.txt
	./packed-spotter examples/upx-like.exe --html > site/index.html

clean:
	rm -f packed-spotter tests/run
