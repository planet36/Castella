# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include config.mk

SUBDIRS = examples hash-programs tests

# Subdirectories with extra dependencies:
#   - research needs google-benchmark
#   - http-prng-service needs spdlog and downloads httplib.h if missing
EXTRA_SUBDIRS = http-prng-service research

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS) $(SUBDIRS)

everything: all $(EXTRA_SUBDIRS)

$(SUBDIRS) $(EXTRA_SUBDIRS):
	$(MAKE) -C $@

test:
	$(MAKE) -C tests test
	$(MAKE) -C examples test
	$(MAKE) -C hash-programs test
	$(MAKE) -C research test

# Build and run every test suite under the sanitizers.
# halt_on_error makes UBSan exit nonzero instead of only printing a diagnostic.
# Release and debug builds share binary names, so clean first.  The sanitizer
# binaries are left in place afterward.
test-san: export ASAN_OPTIONS = detect_stack_use_after_return=1:strict_string_checks=1
test-san: export UBSAN_OPTIONS = print_stacktrace=1:halt_on_error=1
test-san:
	$(MAKE) clean
	$(MAKE) BUILD=debug test

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
	-clang-tidy --quiet $(SRCS) -- $(LINT_CPPFLAGS) $(LINT_CXXFLAGS)
endif
	-for dir in $(SUBDIRS) $(EXTRA_SUBDIRS); do $(MAKE) -C $$dir $@; done

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all everything test test-san clean lint $(SUBDIRS) $(EXTRA_SUBDIRS)

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
