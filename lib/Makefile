MATURIN ?= $(HOME)/.cargo/bin/maturin
RUST_TOOLCHAIN_BIN ?= $(HOME)/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin

ifneq ($(wildcard $(RUST_TOOLCHAIN_BIN)/cargo),)
export PATH := $(RUST_TOOLCHAIN_BIN):$(PATH)
endif

.PHONY: wheel install clean

wheel:
	$(RM) target/release/deps/libconfido.so target/release/libconfido.so
	$(RM) -r target/maturin target/wheels/confido-*.whl
	$(MATURIN) build --release --out target/wheels

install: wheel
	python3 -m pip install --force-reinstall --no-index target/wheels/confido-*.whl

clean:
	cargo clean