# Najm OS - build orchestration.
#
# Three separate Cargo projects, stitched together here:
#
#   kernel/         bare-metal x86_64-unknown-none, the kernel itself
#   userland/hello/ bare-metal x86_64-unknown-none, a Ring 3 program
#   runner/         a normal host binary that packages the other two into
#                   a bootable image and launches QEMU
#
# They are intentionally not one workspace - see runner/Cargo.toml for
# why. Both bare-metal crates are built *first*, and their output paths
# handed to runner's build script via KERNEL_PATH / USERLAND_PATH, rather
# than having that build script invoke cargo itself (a nested cargo run
# contends for the same package-cache lock).
#
# All path variables are quoted throughout (`"$(VAR)"`) because CURDIR can
# contain spaces or other shell-special characters - e.g. a folder named
# `najm-os (1)` from a duplicate download/extract. Without quoting, make
# passes that straight to `/bin/sh` and it breaks on the space/parens.

KERNEL_TARGET := x86_64-unknown-none
KERNEL_BIN_DEBUG   := $(CURDIR)/kernel/target/$(KERNEL_TARGET)/debug/najm-kernel
KERNEL_BIN_RELEASE := $(CURDIR)/kernel/target/$(KERNEL_TARGET)/release/najm-kernel

USERLAND_MANIFEST   := userland/hello/Cargo.toml
USERLAND_BIN_DEBUG   := $(CURDIR)/userland/hello/target/$(KERNEL_TARGET)/debug/najm-hello
USERLAND_BIN_RELEASE := $(CURDIR)/userland/hello/target/$(KERNEL_TARGET)/release/najm-hello

.PHONY: build userland run run-release run-no-kvm check clean

## Compile the kernel only (debug profile), without launching QEMU.
build:
	cargo build --manifest-path kernel/Cargo.toml --target $(KERNEL_TARGET)

## Compile the userland test program (debug profile). Built as its own
## target rather than folded into `build` so a userland failure is
## reported as a userland failure, not a kernel one.
userland:
	cargo build --manifest-path $(USERLAND_MANIFEST) --target $(KERNEL_TARGET)

## Fast type-check of the kernel, no codegen - useful while iterating.
check:
	cargo check --manifest-path kernel/Cargo.toml --target $(KERNEL_TARGET)

## Build everything (debug) and boot it in QEMU.
run: build userland
	KERNEL_PATH="$(KERNEL_BIN_DEBUG)" USERLAND_PATH="$(USERLAND_BIN_DEBUG)" \
		cargo run --manifest-path runner/Cargo.toml

## Build everything (release, optimized + LTO) and boot it in QEMU.
run-release:
	cargo build --manifest-path kernel/Cargo.toml --target $(KERNEL_TARGET) --release
	cargo build --manifest-path $(USERLAND_MANIFEST) --target $(KERNEL_TARGET) --release
	KERNEL_PATH="$(KERNEL_BIN_RELEASE)" USERLAND_PATH="$(USERLAND_BIN_RELEASE)" \
		cargo run --manifest-path runner/Cargo.toml --release

## Boot without KVM acceleration (software emulation) - useful for
## comparing behavior, or if /dev/kvm isn't available.
run-no-kvm: build userland
	KERNEL_PATH="$(KERNEL_BIN_DEBUG)" USERLAND_PATH="$(USERLAND_BIN_DEBUG)" \
		cargo run --manifest-path runner/Cargo.toml -- --no-kvm

clean:
	cargo clean --manifest-path kernel/Cargo.toml
	cargo clean --manifest-path $(USERLAND_MANIFEST)
	cargo clean --manifest-path runner/Cargo.toml
