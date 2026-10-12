"""NEXORA PH office-PC document mirror sync agent.
Configure NEXORA_BASE_URL and NEXORA_SYNC_TOKEN in a private .env file.
Run periodically on the office PC. HTTPS is required outside localhost.
"""
import hashlib, os, re
from pathlib import Path
import requests
from dotenv import load_dotenv
load_dotenv()
BASE = os.environ.get("NEXORA_BASE_URL", "").rstrip("/")
TOKEN = os.environ.get("NEXORA_SYNC_TOKEN", "")
DEST = Path(os.environ.get("NEXORA_LOCAL_COPY", str(Path.home() / "Documents" / "NEXORA_PH_Local_Copy"))).expanduser()
if not BASE or not TOKEN:
    raise SystemExit("Set NEXORA_BASE_URL and NEXORA_SYNC_TOKEN in the sync agent .env file first.")
if not BASE.startswith("https://") and not ("127.0.0.1" in BASE or "localhost" in BASE):
    raise SystemExit("Use HTTPS for remote synchronization.")
DEST.mkdir(parents=True, exist_ok=True)
sess = requests.Session(); sess.headers.update({"Authorization": f"Bearer {TOKEN}"})
resp = sess.get(f"{BASE}/api/sync/manifest", timeout=45); resp.raise_for_status()
files = resp.json().get("files", [])
for item in files:
    name = Path(item["stored_name"]).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,240}", name):
        print("Skipping unsafe filename:", name); continue
    target = DEST / name
    if target.exists() and item.get("sha256"):
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest == item["sha256"]:
            continue
    r = sess.get(f"{BASE}/api/sync/file/{item['kind']}/{int(item['id'])}", timeout=180); r.raise_for_status()
    digest = hashlib.sha256(r.content).hexdigest()
    expected = item.get("sha256") or r.headers.get("X-Nexora-SHA256")
    if expected and digest != expected:
        print("Checksum mismatch; not saving:", name); continue
    temp = target.with_suffix(target.suffix + ".part")
    temp.write_bytes(r.content); temp.replace(target)
    print("Synced:", name)
print(f"Sync complete. {len(files)} cloud attachment(s) in manifest. Local folder: {DEST}")
