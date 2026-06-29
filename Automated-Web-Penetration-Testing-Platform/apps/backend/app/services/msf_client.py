"""
Metasploit RPC Client — Singleton wrapper around pymetasploit3.
Manages connection lifecycle, workspace isolation, and safe module execution.

Prerequisites (Kali VM):
    msfrpcd -P sentinel_msf -S -a 127.0.0.1 -p 55553
"""
import logging
import asyncio
from typing import Optional
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError

logger = logging.getLogger(__name__)


class MetasploitClient:
    """Thread-safe singleton for Metasploit RPC interactions."""

    _instance: Optional["MetasploitClient"] = None

    def __init__(self, config: dict):
        self.host = config.get("msf_rpc_host", "127.0.0.1")
        self.port = config.get("msf_rpc_port", 55553)
        self.password = config.get("msf_rpc_password", "sentinel_msf")
        self.ssl = config.get("msf_rpc_ssl", True)
        self.workspace = config.get("msf_workspace", "sentinel")
        self._client: Optional[MsfRpcClient] = None
        self._connected = False

        # Safety configuration
        self.allowed_prefixes = config.get("msf_allowed_module_prefixes", [
            "auxiliary/scanner/",
            "auxiliary/gather/",
        ])
        self.blocked_modules = config.get("msf_blocked_modules", [
            "auxiliary/dos/",
        ])
        self.max_attempts = config.get("msf_max_exploit_attempts", 5)

    async def connect(self) -> bool:
        """Establish connection to msfrpcd."""
        loop = asyncio.get_event_loop()
        try:
            self._client = await loop.run_in_executor(
                None,
                lambda: MsfRpcClient(
                    self.password,
                    server=self.host,
                    port=self.port,
                    ssl=self.ssl,
                )
            )
            self._connected = True
            logger.info(f"[MSF] Connected to msfrpcd at {self.host}:{self.port}")

            # Create/switch workspace for isolation
            await self._ensure_workspace()
            return True

        except Exception as e:
            logger.error(f"[MSF] Connection failed: {e}")
            self._connected = False
            return False

    async def _ensure_workspace(self):
        """Create Sentinel workspace if it doesn't exist."""
        loop = asyncio.get_event_loop()
        try:
            workspaces = await loop.run_in_executor(
                None, lambda: self._client.db.workspaces.list
            )
            ws_names = [w["name"] for w in workspaces] if workspaces else []

            if self.workspace not in ws_names:
                await loop.run_in_executor(
                    None,
                    lambda: self._client.db.workspaces.add(self.workspace)
                )
                logger.info(f"[MSF] Created workspace: {self.workspace}")

            await loop.run_in_executor(
                None,
                lambda: self._client.db.workspaces.set(self.workspace)
            )
        except Exception as e:
            logger.warning(f"[MSF] Workspace setup failed: {e}")

    def is_module_allowed(self, module_path: str) -> bool:
        """Check if a module is in the allow list and not blocked."""
        if any(module_path.startswith(blocked) for blocked in self.blocked_modules):
            return False
        return any(module_path.startswith(prefix) for prefix in self.allowed_prefixes)

    async def run_auxiliary_scanner(
        self, module_path: str, rhosts: str, options: dict = None
    ) -> dict:
        """
        Run a Metasploit auxiliary scanner module.
        Returns: dict with 'success', 'output', 'job_id'.
        """
        if not self.is_module_allowed(module_path):
            return {"success": False, "output": f"Module blocked: {module_path}"}

        loop = asyncio.get_event_loop()
        try:
            module = await loop.run_in_executor(
                None,
                lambda: self._client.modules.use("auxiliary", module_path)
            )
            module["RHOSTS"] = rhosts

            if options:
                for key, value in options.items():
                    module[key] = value

            # Create console for output capture
            console_id = await loop.run_in_executor(
                None,
                lambda: self._client.consoles.console().cid
            )
            console = self._client.consoles.console(console_id)

            output = await loop.run_in_executor(
                None,
                lambda: console.run_module_with_output(module, timeout=120)
            )

            # Clean up console
            await loop.run_in_executor(
                None, lambda: console.destroy()
            )

            return {"success": True, "output": output, "module": module_path}

        except Exception as e:
            logger.error(f"[MSF] Scanner {module_path} failed: {e}")
            return {"success": False, "output": str(e), "module": module_path}

    async def run_exploit(
        self, module_path: str, rhosts: str, payload: str, options: dict = None
    ) -> dict:
        """
        Run an exploit module. Returns session info if successful.
        """
        if not self.is_module_allowed(module_path):
            return {"success": False, "output": f"Module blocked: {module_path}"}

        loop = asyncio.get_event_loop()
        try:
            exploit = await loop.run_in_executor(
                None,
                lambda: self._client.modules.use("exploit", module_path)
            )
            exploit["RHOSTS"] = rhosts
            exploit["PAYLOAD"] = payload

            if options:
                for key, value in options.items():
                    exploit[key] = value

            console_id = await loop.run_in_executor(
                None,
                lambda: self._client.consoles.console().cid
            )
            console = self._client.consoles.console(console_id)

            output = await loop.run_in_executor(
                None,
                lambda: console.run_module_with_output(
                    exploit, payload=payload, timeout=120
                )
            )

            # Check for new sessions
            sessions = await loop.run_in_executor(
                None, lambda: self._client.sessions.list
            )

            await loop.run_in_executor(None, lambda: console.destroy())

            return {
                "success": bool(sessions),
                "output": output,
                "sessions": sessions,
                "module": module_path,
            }

        except Exception as e:
            logger.error(f"[MSF] Exploit {module_path} failed: {e}")
            return {"success": False, "output": str(e), "module": module_path}

    async def get_sessions(self) -> dict:
        """List all active Metasploit sessions."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: self._client.sessions.list
        )

    async def run_post_module(self, session_id: str, module_path: str) -> dict:
        """Run a post-exploitation module on an active session."""
        loop = asyncio.get_event_loop()
        try:
            post = await loop.run_in_executor(
                None,
                lambda: self._client.modules.use("post", module_path)
            )
            post["SESSION"] = session_id

            result = await loop.run_in_executor(
                None, lambda: post.execute()
            )
            return {"success": True, "output": result, "module": module_path}

        except Exception as e:
            logger.error(f"[MSF] Post module {module_path} failed: {e}")
            return {"success": False, "output": str(e)}

    async def cleanup_sessions(self):
        """Close all active sessions — mandatory after post-exploitation."""
        loop = asyncio.get_event_loop()
        sessions = await self.get_sessions()
        for sid in sessions:
            try:
                session = self._client.sessions.session(sid)
                await loop.run_in_executor(None, lambda: session.stop())
                logger.info(f"[MSF] Closed session {sid}")
            except Exception:
                pass

    async def disconnect(self):
        """Disconnect from msfrpcd."""
        if self._client:
            await self.cleanup_sessions()
            self._client = None
            self._connected = False