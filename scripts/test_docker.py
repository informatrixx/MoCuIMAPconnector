"""Isolated Docker smoke test using synthetic secrets and disposable owned resources."""
from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.STDOUT).strip()


def main() -> None:
    name = "mocu-smoke-" + uuid.uuid4().hex
    volume = name + "-data"
    created = False
    with tempfile.TemporaryDirectory(prefix="mocu-docker-test-") as folder:
        key = Path(folder) / "synthetic.key"
        key.write_bytes(base64.urlsafe_b64encode(bytes(range(32))))
        key.chmod(0o444)
        docker("volume", "create", "--label", "mocu.smoke=" + name, volume)
        try:
            docker("run", "-d", "--name", name, "--label", "mocu.smoke=" + name,
                   "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                   "--tmpfs", "/tmp:noexec,nosuid,size=16m", "-p", "127.0.0.1::8765",
                   "--mount", f"type=bind,source={key},target=/run/secrets/mocu_master_key,readonly",
                   "--mount", f"type=volume,source={volume},target=/data",
                   "-e", "MCP_BIND=0.0.0.0", "mocu-imap:multi-account-review")
            created = True
            info = json.loads(docker("inspect", name))[0]
            assert info["Config"]["User"] == "10001:10001"
            assert info["HostConfig"]["ReadonlyRootfs"] is True

            def healthy() -> None:
                current = json.loads(docker("inspect", name))[0]
                port = current["NetworkSettings"]["Ports"]["8765/tcp"][0]["HostPort"]
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                            assert json.load(response) == {"status": "ok"}
                        return
                    except OSError:
                        time.sleep(0.2)
                raise RuntimeError("Container did not become healthy")

            healthy()
            docker("exec", name, "python", "-c",
                   "import os,pathlib; assert os.getuid()==10001; "
                   "assert not os.access('/app',os.W_OK); "
                   "assert os.access('/run/secrets/mocu_master_key',os.R_OK); "
                   "assert not os.access('/run/secrets/mocu_master_key',os.W_OK); "
                   "assert pathlib.Path('/data/mocu-imap.sqlite3').exists(); "
                   "pathlib.Path('/data/smoke').write_text('fixture')")
            docker("restart", name)
            healthy()
            docker("exec", name, "python", "-c",
                   "from pathlib import Path; assert Path('/data/smoke').read_text()=='fixture'")
            print("Docker runtime: OK (non-root, read-only, secret mount, health, persistence)")
        finally:
            if created:
                info = json.loads(docker("inspect", name))[0]
                if info["Config"]["Labels"].get("mocu.smoke") != name:
                    raise RuntimeError("Container ownership mismatch")
                docker("rm", "-f", name)
            info = json.loads(docker("volume", "inspect", volume))[0]
            if info["Labels"].get("mocu.smoke") != name:
                raise RuntimeError("Volume ownership mismatch")
            docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
