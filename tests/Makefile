# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include ../config.mk

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS)

# `./kat` recomputes each digest from that line's own fields, so it cannot see
# KAT.txt drifting from generate()'s sweeps; the diff does.  On a difference,
# regenerate with `./kat --generate > KAT.txt` and re-run spec-conformance.py.
test: all
	@command -v python3 >/dev/null || { echo 'make test: python3 is required for duplex-diff-fuzz.py'; exit 1; }
	./tests
	./kat
	./kat --generate | diff - KAT.txt
	./equivalence-tests
	./permute-equivalence
	python3 duplex-diff-fuzz.py

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
