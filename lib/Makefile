MATURIN ?= maturin
CARGO ?= cargo
PYTHON ?= python3
MATURIN_FLAGS ?= --compatibility pypi

.PHONY: wheel install clean

wheel:
	$(CARGO) clean --release --package confido
	$(RM) -r target/maturin target/wheels/confido*.whl
	$(MATURIN) build --release --interpreter $(PYTHON) --out target/wheels $(MATURIN_FLAGS)

install: wheel
	$(PYTHON) -m pip install --force-reinstall --no-index target/wheels/confido*.whl

clean:
	$(CARGO) clean
