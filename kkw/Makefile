CMAKE ?= cmake
N ?= 4
W ?= 16
BENCH_ITERS ?= 10
BUILD_DIR = build/n$(N)-w$(W)

BENCH_NS := 4 8 16 32 64

BENCH_MAIN_N := 16

CMAKE_CONFIGURE = $(CMAKE) -S . -B $(BUILD_DIR) \
	-DBLIND_MSS_N=$(N) \
	-DBLIND_MSS_GRIND_W=$(W) \
	-DBLIND_MSS_BENCH_ITERS=$(BENCH_ITERS) \
	$(CMAKE_ARGS)

.PHONY: all lib cli test bench configure clean help _bench-build

all: lib

configure:
	$(CMAKE_CONFIGURE)

lib: configure
	$(CMAKE) --build $(BUILD_DIR) --target blindmss --parallel

cli: configure
	$(CMAKE) --build $(BUILD_DIR) --target blindsig --parallel

test: configure
	$(CMAKE) --build $(BUILD_DIR) --target check --parallel

_bench-build: configure
	$(CMAKE) --build $(BUILD_DIR) --target bench_bin --parallel

bench:
	@for n in $(BENCH_NS) $(BENCH_MAIN_N); do \
		$(MAKE) --no-print-directory N=$$n _bench-build >/dev/null; \
	done
	@build/n$(firstword $(BENCH_NS))-w$(W)/bench_bin --header
	@for n in $(BENCH_NS); do \
		build/n$$n-w$(W)/bench_bin --row; \
	done
	@build/n$(BENCH_MAIN_N)-w$(W)/bench_bin

clean:
	$(CMAKE) -E remove_directory build

help:
	@echo "Usage: make <target> [N=<N>] [W=<W>] [BENCH_ITERS=<n>]"
	@echo
	@echo "Targets:"
	@echo "  make            Build libblindmss.a"
	@echo "  cli             Build the blindsig CLI  ($(BUILD_DIR)/blindsig)"
	@echo "  test            Build and run the regression suite"
	@echo "  bench           Run every benchmark the paper reports"
	@echo "  clean           Remove the CMake build tree"
	@echo
	@echo "Options:"
	@echo "  N=<N>           Parties: 4,8,...,32,64,128,256 (default 4)"
	@echo "  W=<W>           Grinding bits: 0,16,24 (default 16)"
	@echo "  BENCH_ITERS=<n> Iterations per benchmark point (default 10)"
	@echo "  CMAKE_ARGS=...  Additional CMake configuration arguments"
