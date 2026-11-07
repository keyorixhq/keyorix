"""JSONTestSuite table for the Python decoder as the Keyorix Python SDK calls it: json.loads(resp.read()) on bytes."""
import json
import os
import sys

d = sys.argv[1]
for n in sorted(os.listdir(d)):
    if not n.endswith(".json"):
        continue
    with open(os.path.join(d, n), "rb") as f:
        b = f.read()
    try:
        json.loads(b)
        r = "accept"
    except RecursionError:
        r = "crash:RecursionError"
    except MemoryError:
        r = "crash:MemoryError"
    except Exception:  # noqa: BLE001
        r = "reject"
    print(n + "\t" + r)
