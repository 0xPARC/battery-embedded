# ---- pick platform: host | dev-gnu | dev-musl ----
PLATFORM ?= host

RUST_TARGET_host     := $(shell rustc -vV | sed -n 's/^host: //p')
RUST_TARGET_dev-gnu  := aarch64-unknown-linux-gnu
RUST_TARGET_dev-musl := aarch64-unknown-linux-musl
RUST_TARGET := $(RUST_TARGET_$(PLATFORM))

RUST_LIB := ../../target/$(RUST_TARGET)/release/libbattery_embedded.a
INCLUDE  := ../../include
C_SRC    := e2e.c
OUT      := e2e

# ---- toolchains per platform ----
CC_host      ?= cc
CFLAGS_host  ?= -O2 -Wall -Wextra -I$(INCLUDE)

CC_dev-gnu   ?= zig cc
CFLAGS_dev-gnu  ?= -target aarch64-linux-gnu -O2 -Wall -Wextra -I$(INCLUDE) -lunwind
CC_dev-musl     ?= zig cc
CFLAGS_dev-musl ?= -target aarch64-linux-musl -static -O2 -Wall -Wextra -I$(INCLUDE) -lunwind

# select active
CC     := $(CC_$(PLATFORM))
CFLAGS := $(CFLAGS_$(PLATFORM))

.PHONY: all build rustlib clean
all: build

rustlib:
	cargo build --release --target $(RUST_TARGET) --no-default-features --features ffi

build: rustlib $(C_SRC) $(RUST_LIB)
	$(CC) $(CFLAGS) -o $(OUT) $(C_SRC) $(RUST_LIB)

clean:
	rm -f $(OUT)
