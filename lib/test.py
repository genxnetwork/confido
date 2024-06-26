import confido
import traceback

try:
    confido.aTLS_connect_py("http://127.0.0.1:8000")
except RuntimeError as e:
    print(f"RuntimeError: {e}")
    traceback.print_exc()

