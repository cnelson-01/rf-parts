# SPDX-License-Identifier: MIT
# w1700k-ble: every src/*.cpp builds into the binary; each tests/test_*.cpp is its own test
# binary linked with every src object except main.o; each tools/*.cpp is its own tool.
# Add files, not rules: agents should not need to edit this.

CXX      ?= clang++
ARCH_FLAGS := $(if $(filter arm64 aarch64,$(shell uname -m)),-mcpu=native,-march=native)
CXXFLAGS ?= -O3 $(ARCH_FLAGS) -g
override CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-unused-parameter -pthread -Isrc -Ithird_party/w1700k \
            $(shell pkg-config --cflags fftw3f)
LDLIBS   += $(shell pkg-config --libs fftw3f) -lfftw3f_threads -pthread

BUILD    ?= build
SRCS     := $(wildcard src/*.cpp)
OBJS     := $(SRCS:src/%.cpp=$(BUILD)/%.o)
LIBOBJS  := $(filter-out $(BUILD)/main.o,$(OBJS))
TESTS    := $(patsubst tests/%.cpp,$(BUILD)/%,$(wildcard tests/test_*.cpp))
TOOLS    := $(patsubst tools/%.cpp,$(BUILD)/%,$(wildcard tools/*.cpp))

.PHONY: all test clean
all: $(BUILD)/w1700k-ble $(TESTS) $(TOOLS)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.cpp $(wildcard src/*.h) | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/w1700k-ble: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/test_%: tests/test_%.cpp $(LIBOBJS) $(wildcard src/*.h)
	$(CXX) $(CXXFLAGS) $< $(LIBOBJS) -o $@ $(LDLIBS)

$(BUILD)/%: tools/%.cpp $(LIBOBJS) $(wildcard src/*.h)
	$(CXX) $(CXXFLAGS) $< $(LIBOBJS) -o $@ $(LDLIBS)

# Each test binary exits non-zero on failure. Python tests: tests/test_*.py (system python3).
test: all
	@set -e; for t in $(TESTS); do echo "== $$t"; $$t; done
	@set -e; for t in $(wildcard tests/test_*.py); do echo "== $$t"; W1700K_BLE_BUILD="$(abspath $(BUILD))" /usr/bin/python3 $$t; done

clean:
	rm -rf $(BUILD)
