import shutil
from pathlib import Path

folders = ["clientkeys", "serverkeys", "received_logs", "hostkeys", "__pycache__"]
files = list(Path().rglob("*.log"))

for f in folders:
    shutil.rmtree(f, ignore_errors=True)

for f in files:
    f.unlink(missing_ok=True)

print("✅ Project cleaned.")
