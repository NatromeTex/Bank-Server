import json
from pathlib import Path


class IPCBridge:
    """
    Writes enforcement state to a JSON file that the bank server middleware polls.
    Uses atomic write (tmp → rename) to avoid partial reads.
    """

    def __init__(self, config):
        self.path = Path(config.ipc_file_path)
        self.enabled = config.enforcement_mode

    async def write_state(self, snapshot: dict):
        if not self.enabled:
            return
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(snapshot))
            tmp.rename(self.path)
        except Exception:
            pass

    async def clear(self):
        try:
            self.path.unlink(missing_ok=True)
        except Exception:
            pass
