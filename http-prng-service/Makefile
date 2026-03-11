# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL = C

CPPFLAGS = -MMD -MP
CPPFLAGS += -I ../include
# for SSL (not supported yet)
#CPPFLAGS += -DCPPHTTPLIB_OPENSSL_SUPPORT

CXXFLAGS = -std=c++26
CXXFLAGS += -pipe -Wall -Wextra -Wpedantic -Wfatal-errors
CXXFLAGS += -Os -flto=auto -march=native
CXXFLAGS += -maes
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

lint:
	-clang-tidy --quiet --exclude-header-filter=httplib.h $(SRCS) -- $(CPPFLAGS) $(CXXFLAGS) $(LDLIBS)

# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: all clean lint

-include $(DEPS)
