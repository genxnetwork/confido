MATURIN ?= maturin
PYTHON ?= python3
.PHONY: wheel install
wheel:
	$(MATURIN) build --locked --release --interpreter $(PYTHON) --out dist
install: wheel
	$(PYTHON) -m pip install --force-reinstall --no-index --no-deps dist/confido_verifier-0.4.0-*.whl
