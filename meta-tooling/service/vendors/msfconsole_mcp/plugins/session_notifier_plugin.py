"""
Session Notifier Plugin for MSF Console MCP
Sends notifications when new sessions are established
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from msf_plugin_system import PluginInterface, PluginMetadata, PluginCategory, PluginContext
from msf_stable_integration import OperationResult, OperationStatus

logger = logging.getLogger(__name__)


class SessionNotifierPlugin(PluginInterface):
    """Multi-channel session notification plugin"""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="session_notifier",
            description="Send notifications when new sessions are established",
            category=PluginCategory.NOTIFICATION,
            version="1.0.0",
            author="MSF MCP",
            dependencies=[],
            commands={
                "enable": "Enable session notifications",
                "disable": "Disable session notifications",
                "status": "Show notifier status",
                "config": "Configure notification settings",
                "test": "Send test notification",
                "add_filter": "Add IP range filter",
                "remove_filter": "Remove IP range filter",
                "list_filters": "List active IP filters",
                "history": "Show notification history"
            },
            capabilities={"notifications", "session_monitoring", "filtering", "multi_channel"},
            auto_load=True,
            priority=80
        )
        
    def __init__(self, context: PluginContext):
        super().__init__(context)
        self._enabled = True
        self._channels = {
            "console": True,
            "file": False,
            "webhook": False
        }
        self._config = {
            "file_path": "/tmp/msf_session_notifications.log",
            "webhook_url": None,
            "notification_format": "detailed",
            "include_timestamp": True,
            "include_session_info": True
        }
        self._ip_filters: Set[str] = set()
        self._notification_history: List[Dict[str, Any]] = []
        self._max_history = 100
        
    async def initialize(self) -> OperationResult:
        """Initialize session notifier plugin"""
        start_time = time.time()
        try:
            # Register session event hooks
            self.register_hook("session_opened", self._on_session_opened)
            self.register_hook("session_closed", self._on_session_closed)
            self.register_hook("session_upgraded", self._on_session_upgraded)
            
            # Load configuration if exists
            await self._load_config()
            
            self._initialized = True
            return OperationResult(
                OperationStatus.SUCCESS,
                {
                    "status": "initialized",
                    "enabled": self._enabled,
                    "channels": self._channels,
                    "plugin": "session_notifier"
                },
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize session notifier: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def cleanup(self) -> OperationResult:
        """Cleanup session notifier resources"""
        start_time = time.time()
        try:
            # Save configuration
            await self._save_config()
            
            # Final notification if enabled
            if self._enabled and self._channels["file"]:
                await self._write_to_file({
                    "event": "plugin_shutdown",
                    "timestamp": datetime.now().isoformat()
                })
                
            return OperationResult(
                OperationStatus.SUCCESS,
                {"status": "cleaned_up", "plugin": "session_notifier"},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to cleanup session notifier: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def cmd_enable(self, **kwargs) -> OperationResult:
        """Enable session notifications"""
        self._enabled = True
        return OperationResult(
            OperationStatus.SUCCESS,
            {"enabled": True, "action": "notifier_enable"},
            0.0
        )
        
    async def cmd_disable(self, **kwargs) -> OperationResult:
        """Disable session notifications"""
        self._enabled = False
        return OperationResult(
            OperationStatus.SUCCESS,
            {"enabled": False, "action": "notifier_disable"},
            0.0
        )
        
    async def cmd_status(self, **kwargs) -> OperationResult:
        """Show notifier status"""
        return OperationResult(
            OperationStatus.SUCCESS,
            {
                "enabled": self._enabled,
                "active_channels": [ch for ch, active in self._channels.items() if active],
                "ip_filters": list(self._ip_filters),
                "notifications_sent": len(self._notification_history),
                "configuration": self._config,
                "action": "notifier_status"
            },
            0.0
        )
        
    async def cmd_config(self, channel: Optional[str] = None, 
                        key: Optional[str] = None, 
                        value: Optional[str] = None, **kwargs) -> OperationResult:
        """Configure notification settings"""
        start_time = time.time()
        try:
            if channel and key is None:
                # Toggle channel
                if channel in self._channels:
                    self._channels[channel] = not self._channels[channel]
                    return OperationResult(
                        OperationStatus.SUCCESS,
                        {
                            "channel": channel,
                            "enabled": self._channels[channel],
                            "action": "notifier_config_channel"
                        },
                        time.time() - start_time
                    )
                else:
                    return OperationResult(
                        OperationStatus.FAILURE,
                        None,
                        time.time() - start_time,
                        f"Unknown channel: {channel}"
                    )
                    
            elif key and value:
                # Set configuration value
                self._config[key] = value
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {
                        "key": key,
                        "value": value,
                        "action": "notifier_config_set"
                    },
                    time.time() - start_time
                )
                
            else:
                # Show current configuration
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {
                        "channels": self._channels,
                        "configuration": self._config,
                        "action": "notifier_config_show"
                    },
                    time.time() - start_time
                )
                
        except Exception as e:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                str(e)
            )
            
    async def cmd_test(self, message: Optional[str] = None, **kwargs) -> OperationResult:
        """Send test notification"""
        test_notification = {
            "event": "test_notification",
            "message": message or "This is a test notification from MSF Session Notifier",
            "timestamp": datetime.now().isoformat(),
            "session_id": "test",
            "source": "0.0.0.0"
        }
        
        await self._send_notification(test_notification)
        
        return OperationResult(
            OperationStatus.SUCCESS,
            {"notification_sent": True, "channels": [ch for ch, active in self._channels.items() if active], "action": "notifier_test"},
            0.0
        )
        
    async def cmd_add_filter(self, ip_range: str, **kwargs) -> OperationResult:
        """Add IP range filter"""
        start_time = time.time()
        try:
            # Validate IP range
            import ipaddress
            ipaddress.ip_network(ip_range)
            
            self._ip_filters.add(ip_range)
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {"filter_added": ip_range, "total_filters": len(self._ip_filters), "action": "notifier_add_filter"},
                time.time() - start_time
            )
            
        except ValueError as e:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                time.time() - start_time,
                f"Invalid IP range: {str(e)}"
            )
            
    async def cmd_history(self, limit: int = 10, **kwargs) -> OperationResult:
        """Show notification history"""
        history = self._notification_history[-limit:]
        
        return OperationResult(
            OperationStatus.SUCCESS,
            {
                "history": history,
                "total_notifications": len(self._notification_history),
                "action": "notifier_history", 
                "limit": limit
            },
            0.0
        )
        
    async def _on_session_opened(self, data: Dict[str, Any]) -> None:
        """Handle new session event"""
        if not self._enabled:
            return
            
        session_info = data.get("info", {})
        session_id = data.get("session_id")
        
        # Check IP filters
        if not self._check_ip_filter(session_info.get("tunnel_peer", "")):
            return
            
        notification = {
            "event": "session_opened",
            "session_id": session_id,
            "session_type": session_info.get("type", "unknown"),
            "target_host": session_info.get("tunnel_peer", "unknown"),
            "info": session_info.get("info", ""),
            "timestamp": datetime.now().isoformat()
        }
        
        await self._send_notification(notification)
        
    async def _on_session_closed(self, data: Dict[str, Any]) -> None:
        """Handle session closed event"""
        if not self._enabled:
            return
            
        notification = {
            "event": "session_closed",
            "session_id": data.get("session_id"),
            "timestamp": datetime.now().isoformat()
        }
        
        await self._send_notification(notification)
        
    async def _on_session_upgraded(self, data: Dict[str, Any]) -> None:
        """Handle session upgraded event"""
        if not self._enabled:
            return
            
        notification = {
            "event": "session_upgraded",
            "session_id": data.get("session_id"),
            "from_type": data.get("from_type", "shell"),
            "to_type": data.get("to_type", "meterpreter"),
            "timestamp": datetime.now().isoformat()
        }
        
        await self._send_notification(notification)
        
    async def _send_notification(self, notification: Dict[str, Any]) -> None:
        """Send notification through active channels"""
        # Add to history
        self._notification_history.append(notification)
        if len(self._notification_history) > self._max_history:
            self._notification_history.pop(0)
            
        # Console notification
        if self._channels["console"]:
            await self._console_notification(notification)
            
        # File notification
        if self._channels["file"]:
            await self._write_to_file(notification)
            
        # Webhook notification
        if self._channels["webhook"] and self._config.get("webhook_url"):
            await self._send_webhook(notification)
            
    async def _console_notification(self, notification: Dict[str, Any]) -> None:
        """Send console notification"""
        event = notification["event"]
        
        if event == "session_opened":
            message = f"[+] New session opened: {notification['session_id']} ({notification['session_type']}) from {notification['target_host']}"
        elif event == "session_closed":
            message = f"[-] Session closed: {notification['session_id']}"
        elif event == "session_upgraded":
            message = f"[*] Session upgraded: {notification['session_id']} from {notification['from_type']} to {notification['to_type']}"
        else:
            message = f"[*] {event}: {notification.get('message', '')}"
            
        print(f"\n{message}\n")
        
    async def _write_to_file(self, notification: Dict[str, Any]) -> None:
        """Write notification to file"""
        try:
            file_path = Path(self._config["file_path"])
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'a') as f:
                f.write(json.dumps(notification) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write notification to file: {e}")
            
    async def _send_webhook(self, notification: Dict[str, Any]) -> None:
        """Send webhook notification"""
        # Webhook implementation would go here
        # For now, just log it
        logger.info(f"Webhook notification: {notification}")
        
    def _check_ip_filter(self, ip_address: str) -> bool:
        """Check if IP address passes filters"""
        if not self._ip_filters:
            return True  # No filters = allow all
            
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address.split(':')[0])  # Handle IP:port format
            
            for filter_range in self._ip_filters:
                if ip in ipaddress.ip_network(filter_range):
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Failed to check IP filter: {e}")
            return True  # Allow on error
            
    async def _load_config(self) -> None:
        """Load configuration from file"""
        config_path = Path.home() / ".msf_notifier_config.json"
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    saved_config = json.load(f)
                    self._config.update(saved_config.get("config", {}))
                    self._channels.update(saved_config.get("channels", {}))
                    self._ip_filters = set(saved_config.get("ip_filters", []))
                    
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            
    async def _save_config(self) -> None:
        """Save configuration to file"""
        config_path = Path.home() / ".msf_notifier_config.json"
        
        try:
            config_data = {
                "config": self._config,
                "channels": self._channels,
                "ip_filters": list(self._ip_filters)
            }
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")