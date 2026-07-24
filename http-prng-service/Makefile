# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

include ../config.mk

# for SSL (not supported yet)
#CPPFLAGS += -DCPPHTTPLIB_OPENSSL_SUPPORT

# for SSL (not supported yet)
#LDLIBS +=  -lssl -lcrypto

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

# https://github.com/yhirose/cpp-httplib
HTTPLIB_URL = https://raw.githubusercontent.com/yhirose/cpp-httplib/refs/heads/master/httplib.h
HTTPLIB_H = $(notdir $(HTTPLIB_URL))

all: $(BINS)

$(BINS): $(HTTPLIB_H)

$(HTTPLIB_H):
	curl --fail -O $(HTTPLIB_URL)

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	@$(RM) --verbose -- $(DEPS) $(BINS)

lint: $(HTTPLIB_H)
	-clang-tidy --quiet --exclude-header-filter=$(HTTPLIB_H) $(SRCS) -- $(CPPFLAGS) $(LINT_CPPFLAGS) $(CXXFLAGS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all clean lint

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
