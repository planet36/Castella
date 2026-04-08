# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

ROOT := $(shell git rev-parse --show-cdup)

CPPFLAGS = -MMD -MP
CPPFLAGS += -I $(ROOT)
# for SSL (not supported yet)
#CPPFLAGS += -DCPPHTTPLIB_OPENSSL_SUPPORT

CXXFLAGS = -std=c++26
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -O3 -flto=auto -march=native
CXXFLAGS += -maes -mvaes -mavx2
CXXFLAGS += -Wno-unused-function
#CXXFLAGS += -march=raptorlake

#LDFLAGS =

LDLIBS = -lfmt
# for SSL (not supported yet)
#LDLIBS +=  -lssl -lcrypto

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS)

$(BINS): httplib.h

# https://github.com/yhirose/cpp-httplib
httplib.h:
	curl -O https://raw.githubusercontent.com/yhirose/cpp-httplib/refs/heads/master/httplib.h

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	@$(RM) --verbose -- $(DEPS) $(BINS)

distclean: clean
	@$(RM) --verbose -- httplib.h

lint: httplib.h
	-clang-tidy --quiet --exclude-header-filter=httplib.h $(SRCS) -- $(CPPFLAGS) $(CXXFLAGS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all clean lint

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
