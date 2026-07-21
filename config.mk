# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

ARCH := $(shell uname -m)

ROOT := ./$(shell git rev-parse --show-cdup)

CPPFLAGS = -MMD -MP
CPPFLAGS += -I $(ROOT)include

CXXFLAGS = -std=c++23
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -Wno-unused-function

ifeq ($(ARCH), aarch64)
    CXXFLAGS += -march=armv8-a+aes
else ifeq ($(ARCH), x86_64)
    #CXXFLAGS += -march=native
    CXXFLAGS += -march=x86-64-v3 -maes -mvaes # x86-64-v3 implies avx, avx2
else
    $(error Unsupported architecture: $(ARCH))
endif

# Build type: release (default) or debug
# Run `make clean` before switching between release and debug.
BUILD ?= release
ifeq ($(BUILD), release)
    CXXFLAGS += -O3 -flto=auto
else ifeq ($(BUILD), debug)
    CXXFLAGS += -Og -g3
    CXXFLAGS += -fhardened
    CXXFLAGS += -fsanitize=address -fsanitize=undefined
    CPPFLAGS += -DDEBUG -UNDEBUG
    CPPFLAGS += -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -D_GLIBCXX_SANITIZE_VECTOR
    # _FORTIFY_SOURCE=3 and _GLIBCXX_ASSERTIONS are enabled by -fhardened
else
    $(error Unknown BUILD=$(BUILD); use "release" (default) or "debug")
endif

#LDFLAGS =

#LDLIBS =

