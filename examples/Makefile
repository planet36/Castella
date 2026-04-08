# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

ARCH := $(shell uname -m)

ROOT := $(shell git rev-parse --show-cdup)

CPPFLAGS = -MMD -MP
CPPFLAGS += -I $(ROOT) -I $(ROOT)research

CXXFLAGS = -std=c++26
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -O3 -flto=auto
CXXFLAGS += -Wno-unused-function

ifeq ($(ARCH), aarch64)
    CXXFLAGS += -march=armv8-a+aes
else ifeq ($(ARCH), x86_64)
    #CXXFLAGS += -march=native
    CXXFLAGS += -march=x86-64-v3 -maes -mvaes
    #CXXFLAGS += -march=raptorlake
endif

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
