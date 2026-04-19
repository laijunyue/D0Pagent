"""
MSF Plugin System v5.0 - Dynamic Plugin Framework
Provides extensible plugin architecture for MSF Console MCP Server
"""

import asyncio
import importlib
import inspect
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union

from msf_stable_integration import MSFConsoleStableWrapper, OperationResult, OperationStatus

logger = logging.getLogger(__name__)


class PluginCategory(Enum):
    """Plugin categories matching MSF architecture"""
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    POST = "post"
    AUXILIARY = "auxiliary"
    INTEGRATION = "integration"
    SESSION = "session"
    NOTIFICATION = "notification"
    AUTOMATION = "automation"
    REPORTING = "reporting"
    UTILITY = "utility"


@dataclass
class PluginMetadata:
    """Plugin metadata and registration information"""
    name: str
    description: str
    category: PluginCategory
    version: str = "1.0.0"
    author: str = "MSF MCP"
    dependencies: List[str] = field(default_factory=list)
    commands: Dict[str, str] = field(default_factory=dict)
    capabilities: Set[str] = field(default_factory=set)
    auto_load: bool = True
    priority: int = 50  # 0-100, higher = load first


@dataclass
class PluginContext:
    """Context passed to plugin operations"""
    msf: MSFConsoleStableWrapper
    framework_data: Dict[str, Any]
    session_data: Dict[str, Any] = field(default_factory=dict)
    workspace: str = "default"
    user_data: Dict[str, Any] = field(default_factory=dict)


class PluginInterface(ABC):
    """Abstract base class for all MSF plugins"""
    
    def __init__(self, context: PluginContext):
        self.context = context
        self.msf = context.msf
        self._initialized = False
        self._hooks: Dict[str, List[Callable]] = {}
        
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
        
    @abstractmethod
    async def initialize(self) -> OperationResult:
        """Initialize plugin resources"""
        pass
        
    @abstractmethod
    async def cleanup(self) -> OperationResult:
        """Cleanup plugin resources"""
        pass
        
    async def execute_command(self, command: str, args: Dict[str, Any]) -> OperationResult:
        """Execute a plugin command"""
        if command not in self.metadata.commands:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Unknown command: {command}"
            )
            
        method_name = f"cmd_{command}"
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            return await method(**args)
        else:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Command not implemented: {command}"
            )
            
    def register_hook(self, event: str, callback: Callable) -> None:
        """Register event hook"""
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append(callback)
        
    async def emit_event(self, event: str, data: Any) -> None:
        """Emit event to registered hooks"""
        if event in self._hooks:
            for callback in self._hooks[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    logger.error(f"Hook error in {self.metadata.name}: {e}")


class PluginRegistry:
    """Central plugin registry with dynamic discovery and management"""
    
    def __init__(self, msf: MSFConsoleStableWrapper):
        self.msf = msf
        self._plugins: Dict[str, PluginInterface] = {}
        self._plugin_classes: Dict[str, Type[PluginInterface]] = {}
        self._categories: Dict[PluginCategory, List[str]] = {cat: [] for cat in PluginCategory}
        self._load_order: List[str] = []
        self._event_subscribers: Dict[str, List[str]] = {}
        
    def register_plugin_class(self, plugin_class: Type[PluginInterface]) -> None:
        """Register a plugin class for instantiation"""
        # Create temporary instance to get metadata
        temp_context = PluginContext(self.msf, {})
        temp_instance = plugin_class(temp_context)
        metadata = temp_instance.metadata
        
        self._plugin_classes[metadata.name] = plugin_class
        logger.info(f"Registered plugin class: {metadata.name}")
        
    async def load_plugin(self, name: str, context: Optional[PluginContext] = None) -> OperationResult:
        """Load and initialize a plugin"""
        if name in self._plugins:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Plugin already loaded: {name}"
            )
            
        if name not in self._plugin_classes:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Unknown plugin: {name}"
            )
            
        try:
            # Create plugin context if not provided
            if context is None:
                context = PluginContext(self.msf, {})
                
            # Instantiate plugin
            plugin_class = self._plugin_classes[name]
            plugin = plugin_class(context)
            
            # Initialize plugin
            result = await plugin.initialize()
            if result.status != OperationStatus.SUCCESS:
                return result
                
            # Register plugin
            self._plugins[name] = plugin
            self._categories[plugin.metadata.category].append(name)
            self._load_order.append(name)
            
            logger.info(f"Loaded plugin: {name} v{plugin.metadata.version}")
            return OperationResult(
                OperationStatus.SUCCESS,
                {"plugin": name, "metadata": plugin.metadata},
                0.0
            )
            
        except Exception as e:
            logger.error(f"Failed to load plugin {name}: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def unload_plugin(self, name: str) -> OperationResult:
        """Unload and cleanup a plugin"""
        if name not in self._plugins:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Plugin not loaded: {name}"
            )
            
        try:
            plugin = self._plugins[name]
            
            # Cleanup plugin
            result = await plugin.cleanup()
            if result.status != OperationStatus.SUCCESS:
                logger.warning(f"Plugin cleanup failed: {name}")
                
            # Remove from registry
            del self._plugins[name]
            self._categories[plugin.metadata.category].remove(name)
            self._load_order.remove(name)
            
            logger.info(f"Unloaded plugin: {name}")
            return OperationResult(
                OperationStatus.SUCCESS,
                {"plugin": name},
                0.0
            )
            
        except Exception as e:
            logger.error(f"Failed to unload plugin {name}: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def reload_plugin(self, name: str) -> OperationResult:
        """Reload a plugin (unload and load)"""
        # Get current context if plugin is loaded
        context = None
        if name in self._plugins:
            context = self._plugins[name].context
            
        # Unload if loaded
        if name in self._plugins:
            unload_result = await self.unload_plugin(name)
            if unload_result.status != OperationStatus.SUCCESS:
                return unload_result
                
        # Load plugin
        return await self.load_plugin(name, context)
        
    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """Get loaded plugin instance"""
        return self._plugins.get(name)
        
    def list_plugins(self, category: Optional[PluginCategory] = None, 
                    loaded_only: bool = False) -> List[Dict[str, Any]]:
        """List available or loaded plugins"""
        plugins = []
        
        if loaded_only:
            # List only loaded plugins
            for name, plugin in self._plugins.items():
                if category is None or plugin.metadata.category == category:
                    plugins.append({
                        "name": name,
                        "metadata": plugin.metadata,
                        "loaded": True
                    })
        else:
            # List all registered plugins
            for name, plugin_class in self._plugin_classes.items():
                temp_context = PluginContext(self.msf, {})
                temp_instance = plugin_class(temp_context)
                metadata = temp_instance.metadata
                
                if category is None or metadata.category == category:
                    plugins.append({
                        "name": name,
                        "metadata": metadata,
                        "loaded": name in self._plugins
                    })
                    
        return sorted(plugins, key=lambda p: (p["metadata"].priority, p["name"]), reverse=True)
        
    async def execute_plugin_command(self, plugin_name: str, command: str, 
                                   args: Dict[str, Any]) -> OperationResult:
        """Execute command on a loaded plugin"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                f"Plugin not loaded: {plugin_name}"
            )
            
        return await plugin.execute_command(command, args)
        
    async def broadcast_event(self, event: str, data: Any) -> None:
        """Broadcast event to all loaded plugins"""
        for plugin in self._plugins.values():
            try:
                await plugin.emit_event(event, data)
            except Exception as e:
                logger.error(f"Event broadcast error for {plugin.metadata.name}: {e}")
                
    async def discover_plugins(self, plugin_dir: Union[str, Path]) -> List[str]:
        """Discover plugins in directory"""
        plugin_dir = Path(plugin_dir)
        discovered = []
        
        if not plugin_dir.exists():
            logger.warning(f"Plugin directory not found: {plugin_dir}")
            return discovered
            
        for file_path in plugin_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
                
            try:
                # Import module
                spec = importlib.util.spec_from_file_location(
                    file_path.stem, file_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find plugin classes
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, PluginInterface) and 
                        obj != PluginInterface):
                        self.register_plugin_class(obj)
                        discovered.append(obj.__name__)
                        
            except Exception as e:
                logger.error(f"Failed to discover plugins in {file_path}: {e}")
                
        logger.info(f"Discovered {len(discovered)} plugins in {plugin_dir}")
        return discovered
        
    async def load_auto_plugins(self) -> List[str]:
        """Load all plugins marked for auto-loading"""
        loaded = []
        
        for name, plugin_class in self._plugin_classes.items():
            temp_context = PluginContext(self.msf, {})
            temp_instance = plugin_class(temp_context)
            
            if temp_instance.metadata.auto_load:
                result = await self.load_plugin(name)
                if result.status == OperationStatus.SUCCESS:
                    loaded.append(name)
                    
        return loaded


class PluginManager:
    """High-level plugin management interface"""
    
    def __init__(self, msf: MSFConsoleStableWrapper):
        self.msf = msf
        self.registry = PluginRegistry(msf)
        self._plugin_dirs: List[Path] = []
        
    async def initialize(self, plugin_dirs: Optional[List[Union[str, Path]]] = None) -> OperationResult:
        """Initialize plugin manager"""
        try:
            # Set default plugin directories
            if plugin_dirs:
                self._plugin_dirs = [Path(d) for d in plugin_dirs]
            else:
                # Default to plugins subdirectory
                self._plugin_dirs = [Path(__file__).parent / "plugins"]
                
            # Discover plugins in all directories
            discovered = []
            for plugin_dir in self._plugin_dirs:
                discovered.extend(await self.registry.discover_plugins(plugin_dir))
                
            # Load auto-load plugins
            loaded = await self.registry.load_auto_plugins()
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {
                    "discovered": discovered,
                    "loaded": loaded,
                    "plugin_dirs": [str(d) for d in self._plugin_dirs]
                },
                0.0
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize plugin manager: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def execute_command(self, plugin_name: str, command: str, 
                            args: Optional[Dict[str, Any]] = None) -> OperationResult:
        """Execute plugin command with validation"""
        if args is None:
            args = {}
            
        return await self.registry.execute_plugin_command(plugin_name, command, args)
        
    def list_plugins(self, **kwargs) -> List[Dict[str, Any]]:
        """List plugins with filtering options"""
        return self.registry.list_plugins(**kwargs)
        
    async def load_plugin(self, name: str) -> OperationResult:
        """Load a specific plugin"""
        return await self.registry.load_plugin(name)
        
    async def unload_plugin(self, name: str) -> OperationResult:
        """Unload a specific plugin"""
        return await self.registry.unload_plugin(name)
        
    async def reload_plugin(self, name: str) -> OperationResult:
        """Reload a specific plugin"""
        return await self.registry.reload_plugin(name)
        
    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed plugin information"""
        plugin = self.registry.get_plugin(name)
        if plugin:
            return {
                "name": name,
                "metadata": plugin.metadata,
                "loaded": True,
                "commands": list(plugin.metadata.commands.keys()),
                "capabilities": list(plugin.metadata.capabilities)
            }
        return None