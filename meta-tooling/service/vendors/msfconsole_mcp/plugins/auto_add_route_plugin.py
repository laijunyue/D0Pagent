"""
Auto Add Route Plugin for MSF Console MCP
Automatically adds routes for new sessions to enable pivoting
"""

import asyncio
import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Set

from msf_plugin_system import PluginInterface, PluginMetadata, PluginCategory, PluginContext
from msf_stable_integration import OperationResult, OperationStatus

logger = logging.getLogger(__name__)


class AutoAddRoutePlugin(PluginInterface):
    """Automatically add routes when sessions are created"""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="auto_add_route",
            description="Automatically add routes for new sessions to enable pivoting",
            category=PluginCategory.SESSION,
            version="1.0.0",
            author="MSF MCP",
            dependencies=[],
            commands={
                "enable": "Enable automatic route addition",
                "disable": "Disable automatic route addition",
                "status": "Show auto-route status",
                "list_routes": "List all automatically added routes",
                "add_subnet": "Add subnet to auto-route list",
                "remove_subnet": "Remove subnet from auto-route list",
                "clear_routes": "Clear all automatically added routes"
            },
            capabilities={"routing", "pivoting", "session_management", "automation"},
            auto_load=True,
            priority=85
        )
        
    def __init__(self, context: PluginContext):
        super().__init__(context)
        self._enabled = True
        self._auto_routes: Dict[str, List[str]] = {}  # session_id -> [routes]
        self._subnet_whitelist: Set[str] = set()
        self._subnet_blacklist: Set[str] = {
            "127.0.0.0/8",      # Loopback
            "169.254.0.0/16",   # Link-local
            "224.0.0.0/4",      # Multicast
            "255.255.255.255/32" # Broadcast
        }
        self._monitoring = False
        self._monitor_task = None
        
    async def initialize(self) -> OperationResult:
        """Initialize auto-route plugin"""
        start_time = time.time()
        try:
            # Register session event hooks
            self.register_hook("session_opened", self._on_session_opened)
            self.register_hook("session_closed", self._on_session_closed)
            
            # Start session monitoring
            self._monitoring = True
            self._monitor_task = asyncio.create_task(self._monitor_sessions())
            
            self._initialized = True
            return OperationResult(
                OperationStatus.SUCCESS,
                {"status": "initialized", "enabled": self._enabled, "plugin": "auto_add_route"},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize auto-route plugin: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def cleanup(self) -> OperationResult:
        """Cleanup auto-route plugin resources"""
        start_time = time.time()
        try:
            # Stop monitoring
            self._monitoring = False
            if self._monitor_task:
                self._monitor_task.cancel()
                
            # Clear routes if requested
            if self._auto_routes:
                logger.info(f"Keeping {len(self._auto_routes)} auto-routes active")
                
            return OperationResult(
                OperationStatus.SUCCESS,
                {"status": "cleaned_up", "routes_kept": len(self._auto_routes), "plugin": "auto_add_route"},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to cleanup auto-route plugin: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def cmd_enable(self, **kwargs) -> OperationResult:
        """Enable automatic route addition"""
        self._enabled = True
        return OperationResult(
            OperationStatus.SUCCESS,
            {"enabled": True, "action": "auto_route_enable"},
            0.0
        )
        
    async def cmd_disable(self, **kwargs) -> OperationResult:
        """Disable automatic route addition"""
        self._enabled = False
        return OperationResult(
            OperationStatus.SUCCESS,
            {"enabled": False, "action": "auto_route_disable"},
            0.0
        )
        
    async def cmd_status(self, **kwargs) -> OperationResult:
        """Show auto-route status"""
        return OperationResult(
            OperationStatus.SUCCESS,
            {
                "enabled": self._enabled,
                "monitoring": self._monitoring,
                "active_routes": sum(len(routes) for routes in self._auto_routes.values()),
                "sessions_tracked": len(self._auto_routes),
                "whitelisted_subnets": list(self._subnet_whitelist),
                "blacklisted_subnets": list(self._subnet_blacklist),
                "action": "auto_route_status"
            },
            0.0
        )
        
    async def cmd_list_routes(self, **kwargs) -> OperationResult:
        """List all automatically added routes"""
        routes_info = []
        
        for session_id, routes in self._auto_routes.items():
            for route in routes:
                routes_info.append({
                    "session_id": session_id,
                    "subnet": route,
                    "auto_added": True
                })
                
        return OperationResult(
            OperationStatus.SUCCESS,
            {"routes": routes_info, "action": "auto_route_list", "count": len(routes_info)},
            0.0
        )
        
    async def cmd_add_subnet(self, subnet: str, **kwargs) -> OperationResult:
        """Add subnet to auto-route whitelist"""
        start_time = time.time()
        try:
            # Validate subnet
            ipaddress.ip_network(subnet)
            self._subnet_whitelist.add(subnet)
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {"subnet": subnet, "whitelisted": True, "action": "auto_route_add_subnet"},
                time.time() - start_time
            )
            
        except ValueError as e:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                f"Invalid subnet: {str(e)}"
            )
            
    async def cmd_clear_routes(self, **kwargs) -> OperationResult:
        """Clear all automatically added routes"""
        start_time = time.time()
        try:
            cleared = 0
            
            for session_id, routes in self._auto_routes.items():
                for route in routes:
                    # Remove route via MSF
                    cmd = f"route remove {route} {session_id}"
                    await self.msf.execute_command(cmd)
                    cleared += 1
                    
            self._auto_routes.clear()
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {"routes_cleared": cleared, "action": "auto_route_clear"},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to clear routes: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def _monitor_sessions(self) -> None:
        """Monitor for new sessions and add routes"""
        known_sessions = set()
        
        while self._monitoring:
            try:
                # Get current sessions
                result = await self.msf.execute_command("sessions -l")
                stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
                current_sessions = self._parse_sessions(stdout)
                
                # Check for new sessions
                for session_id, session_info in current_sessions.items():
                    if session_id not in known_sessions:
                        known_sessions.add(session_id)
                        
                        # Emit session opened event
                        if self._enabled:
                            await self.emit_event("session_opened", {
                                "session_id": session_id,
                                "info": session_info
                            })
                            
                # Check for closed sessions
                closed_sessions = known_sessions - set(current_sessions.keys())
                for session_id in closed_sessions:
                    known_sessions.remove(session_id)
                    
                    # Emit session closed event
                    await self.emit_event("session_closed", {
                        "session_id": session_id
                    })
                    
            except Exception as e:
                logger.error(f"Session monitoring error: {e}")
                
            await asyncio.sleep(5)  # Check every 5 seconds
            
    async def _on_session_opened(self, data: Dict[str, Any]) -> None:
        """Handle new session event"""
        if not self._enabled:
            return
            
        session_id = data["session_id"]
        session_info = data.get("info", {})
        
        # Only process meterpreter sessions
        if session_info.get("type") != "meterpreter":
            logger.info(f"Skipping non-meterpreter session {session_id}")
            return
            
        try:
            # Get network interfaces from session
            result = await self.msf.execute_command(f"sessions -i {session_id} -c 'ifconfig'")
            stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
            subnets = self._extract_subnets(stdout)
            
            # Add routes for valid subnets
            added_routes = []
            for subnet in subnets:
                if self._should_add_route(subnet):
                    route_cmd = f"route add {subnet} {session_id}"
                    route_result = await self.msf.execute_command(route_cmd)
                    
                    if route_result.status == OperationStatus.SUCCESS:
                        added_routes.append(subnet)
                        logger.info(f"Added route {subnet} via session {session_id}")
                        
            if added_routes:
                self._auto_routes[session_id] = added_routes
                
        except Exception as e:
            logger.error(f"Failed to add routes for session {session_id}: {e}")
            
    async def _on_session_closed(self, data: Dict[str, Any]) -> None:
        """Handle session closed event"""
        session_id = data["session_id"]
        
        # Remove auto-added routes for this session
        if session_id in self._auto_routes:
            routes = self._auto_routes[session_id]
            for route in routes:
                try:
                    cmd = f"route remove {route} {session_id}"
                    await self.msf.execute_command(cmd)
                    logger.info(f"Removed route {route} (session {session_id} closed)")
                except Exception as e:
                    logger.error(f"Failed to remove route {route}: {e}")
                    
            del self._auto_routes[session_id]
            
    def _parse_sessions(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse session list from MSF output"""
        sessions = {}
        lines = output.strip().split('\n')
        
        for line in lines:
            if 'Active sessions' in line or '===' in line or not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                sessions[parts[0]] = {
                    "type": parts[1],
                    "info": ' '.join(parts[2:])
                }
                
        return sessions
        
    def _extract_subnets(self, ifconfig_output: str) -> List[str]:
        """Extract subnets from ifconfig output"""
        subnets = []
        import re
        
        # Match IPv4 addresses and masks
        ip_pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+).*?mask\s+(\d+\.\d+\.\d+\.\d+)'
        matches = re.findall(ip_pattern, ifconfig_output)
        
        for ip, mask in matches:
            try:
                # Convert to CIDR notation
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                subnets.append(str(network))
            except Exception as e:
                logger.error(f"Failed to parse network {ip}/{mask}: {e}")
                
        return subnets
        
    def _should_add_route(self, subnet: str) -> bool:
        """Check if route should be added for subnet"""
        try:
            network = ipaddress.ip_network(subnet)
            
            # Check blacklist
            for blacklisted in self._subnet_blacklist:
                if network.overlaps(ipaddress.ip_network(blacklisted)):
                    return False
                    
            # Check whitelist (if configured)
            if self._subnet_whitelist:
                for whitelisted in self._subnet_whitelist:
                    if network.overlaps(ipaddress.ip_network(whitelisted)):
                        return True
                return False
                
            # Default: add route if not blacklisted
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate subnet {subnet}: {e}")
            return False