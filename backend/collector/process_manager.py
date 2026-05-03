from __future__ import annotations

import asyncio
from typing import Any


class EBPFProcessManager:
    """
    Starts and stops the userspace libbpf binaries.

    Each binary prints JSON events to stdout.
    """

    def __init__(self):
        self.processes: list[tuple[str, Any]] = []

    async def start_binary(self, cmd: list[str], name: str):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        except FileNotFoundError:
            print(f"[runner] failed to start {name}: binary not found: {cmd}")
            return None

        except PermissionError:
            print(f"[runner] failed to start {name}: permission denied: {cmd}")
            return None

        except Exception as exc:
            print(f"[runner] failed to start {name}: {exc}")
            return None

        await asyncio.sleep(1)

        if proc.returncode is not None:
            err = await proc.stderr.read()
            print(f"{name} userspace binary failed:")
            print(err.decode(errors="replace"))
            return None

        self.processes.append((name, proc))
        print(f"[runner] started {name}: {' '.join(cmd)}")

        return proc

    async def shutdown(self) -> None:
        for name, proc in self.processes:
            try:
                proc.terminate()
                print(f"[runner] terminating {name}")

            except ProcessLookupError:
                pass

            except Exception as exc:
                print(f"[runner] failed to terminate {name}: {exc}")

        for name, proc in self.processes:
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
                print(f"[runner] stopped {name}")

            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    print(f"[runner] killed {name}")

                except ProcessLookupError:
                    pass

                except Exception as exc:
                    print(f"[runner] failed to kill {name}: {exc}")

        self.processes.clear()
