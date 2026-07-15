# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include config.mk

# Subdirectories that need nothing beyond a C++23 compiler
SUBDIRS = examples hash-programs tests

# Subdirectories with extra dependencies: research needs google-benchmark;
# http-prng-service needs spdlog and downloads httplib.h if missing
EXTRA_SUBDIRS = http-prng-service research

# Any .cpp files in the repository root build against the library headers
# (handy for scratch programs; a clean checkout has none).
SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS) $(SUBDIRS)

everything: all $(EXTRA_SUBDIRS)

$(SUBDIRS) $(EXTRA_SUBDIRS):
	$(MAKE) -C $@

# Build and run every test suite
test: hash-programs tests
	cd tests && ./tests && ./kat && ./equivalence-tests
	cd hash-programs && bash test-correctness.bash

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
ifneq ($(strip $(DEPS) $(BINS)),)
	@$(RM) --verbose -- $(DEPS) $(BINS)
endif
	for dir in $(SUBDIRS) $(EXTRA_SUBDIRS); do $(MAKE) -C $$dir $@; done

lint:
ifneq ($(strip $(SRCS)),)
	-clang-tidy --quiet $(SRCS) -- $(CPPFLAGS) $(CXXFLAGS)
endif
	for dir in $(SUBDIRS) $(EXTRA_SUBDIRS); do $(MAKE) -C $$dir $@; done

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all everything test clean lint $(SUBDIRS) $(EXTRA_SUBDIRS)

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
