# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

CPPFLAGS = -MMD -MP
CPPFLAGS += -I $(shell git rev-parse --show-cdup) -I $(shell git rev-parse --show-cdup)research

CXXFLAGS = -std=c++26
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -O3 -flto=auto -march=native
CXXFLAGS += -maes -mvaes -mavx2
CXXFLAGS += -Wno-unused-function
#CXXFLAGS += -march=raptorlake

#LDFLAGS =

LDLIBS = -lfmt

SRCS = $(wildcard *.cpp)
DEPS = $(addsuffix .d,$(basename $(SRCS)))
BINS = $(basename $(SRCS))

all: $(BINS)

# The built-in recipe for the implicit rule uses $^ instead of $<
%: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	@$(RM) --verbose -- $(DEPS) $(BINS)

lint:
	-clang-tidy --quiet $(SRCS) -- $(CPPFLAGS) $(CXXFLAGS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all clean lint

# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-removing-targets-on-failure
.DELETE_ON_ERROR:

-include $(DEPS)
