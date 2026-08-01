# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include ../config.mk

LDLIBS += $(shell pkg-config --libs benchmark)

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS)

# Build and run this directory's test suite.  Deliberately does not depend on
# `all`: the benchmarks need google-benchmark, but the conformance model is pure
# Python, so the root `make test` can run it without that dependency.
test:
	@command -v python3 >/dev/null || { echo 'make test: python3 is required for spec-conformance.py'; exit 1; }
	python3 spec-conformance.py

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	@$(RM) --verbose -- $(DEPS) $(BINS)

lint:
	-clang-tidy --quiet $(SRCS) -- $(LINT_CPPFLAGS) $(LINT_CXXFLAGS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all test clean lint

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
