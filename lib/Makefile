MATURIN ?= maturin
CARGO ?= cargo
PYTHON ?= python3
MATURIN_FLAGS ?= --compatibility pypi
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct)

.PHONY: wheel install clean

wheel:
	# Maturin repair can patch the hard-linked cdylib; relink our crate before repair.
	$(CARGO) clean --release --package confido
	$(RM) -r target/maturin target/wheels/confido*.whl
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(MATURIN) build --locked --release --interpreter $(PYTHON) --out target/wheels $(MATURIN_FLAGS)

install: wheel
	$(PYTHON) -m pip install --force-reinstall --no-index target/wheels/confido*.whl

clean:
	$(CARGO) clean
