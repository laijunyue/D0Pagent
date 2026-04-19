"""
WMAP Web Application Scanner Plugin for MSF Console MCP
Provides web application mapping and vulnerability scanning
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from msf_plugin_system import PluginInterface, PluginMetadata, PluginCategory, PluginContext
from msf_stable_integration import OperationResult, OperationStatus

logger = logging.getLogger(__name__)


class WMAPPlugin(PluginInterface):
    """Web application mapping and scanning plugin"""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="wmap",
            description="Web application mapping and vulnerability scanner",
            category=PluginCategory.SCANNER,
            version="1.0.0",
            author="MSF MCP",
            dependencies=[],
            commands={
                "enable": "Enable WMAP scanner",
                "disable": "Disable WMAP scanner",
                "status": "Check WMAP status",
                "sites": "List discovered sites",
                "targets": "Manage scan targets",
                "modules": "List available WMAP modules",
                "run": "Run WMAP scan",
                "nodes": "Manage distributed scanning nodes",
                "reports": "Generate scan reports",
                "vulns": "List discovered vulnerabilities"
            },
            capabilities={"web_scanning", "vulnerability_detection", "site_mapping", "distributed_scanning"},
            auto_load=True,
            priority=85
        )
        
    def __init__(self, context: PluginContext):
        super().__init__(context)
        self._enabled = False
        self._sites = {}
        self._targets = []
        self._scan_results = {}
        self._available_modules = []
        
    async def initialize(self) -> OperationResult:
        """Initialize WMAP plugin"""
        start_time = time.time()
        try:
            # Load WMAP in MSF
            result = await self.msf.execute_command("load wmap")
            
            if result.status == OperationStatus.SUCCESS and "loaded" in result.data.get("stdout", "").lower():
                self._initialized = True
                
                # Get available WMAP modules
                await self._refresh_modules()
                
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {"status": "initialized", "modules": len(self._available_modules), "plugin": "wmap"},
                    time.time() - start_time
                )
            else:
                return OperationResult(
                    OperationStatus.FAILURE,
                    None,
                    time.time() - start_time,
                    "Failed to load WMAP plugin in MSF"
                )
                
        except Exception as e:
            logger.error(f"Failed to initialize WMAP: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def cleanup(self) -> OperationResult:
        """Cleanup WMAP plugin"""
        start_time = time.time()
        try:
            # Unload from MSF
            await self.msf.execute_command("unload wmap")
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {"status": "cleaned_up", "plugin": "wmap"},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Failed to cleanup WMAP: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def cmd_enable(self, **kwargs) -> OperationResult:
        """Enable WMAP scanner"""
        self._enabled = True
        return OperationResult(
            OperationStatus.SUCCESS,
            {"enabled": True, "action": "wmap_enable"},
            0.0
        )
        
    async def cmd_sites(self, action: str = "list", url: Optional[str] = None, **kwargs) -> OperationResult:
        """Manage discovered sites"""
        start_time = time.time()
        try:
            if action == "list":
                result = await self.msf.execute_command("wmap_sites -l")
                stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
                sites = self._parse_sites(stdout)
                
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {"sites": sites, "action": "wmap_sites_list", "count": len(sites)},
                    time.time() - start_time
                )
                
            elif action == "add" and url:
                result = await self.msf.execute_command(f"wmap_sites -a {url}")
                stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
                
                success = "Added" in stdout
                return OperationResult(
                    OperationStatus.SUCCESS if success else OperationStatus.FAILURE,
                    {"url": url, "added": success, "action": "wmap_sites_add"},
                    time.time() - start_time
                )
                
            else:
                return OperationResult(
                    OperationStatus.FAILURE,
                    None,
                    time.time() - start_time,
                    "Invalid sites action or missing URL"
                )
                
        except Exception as e:
            logger.error(f"WMAP sites error: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def cmd_targets(self, action: str = "list", index: Optional[int] = None, **kwargs) -> OperationResult:
        """Manage scan targets"""
        start_time = time.time()
        try:
            if action == "list":
                result = await self.msf.execute_command("wmap_targets -l")
                stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
                targets = self._parse_targets(stdout)
                self._targets = targets
                
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {"targets": targets, "action": "wmap_targets_list", "count": len(targets)},
                    time.time() - start_time
                )
                
            elif action == "add" and index is not None:
                result = await self.msf.execute_command(f"wmap_targets -t {index}")
                stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
                
                success = "Added" in stdout
                return OperationResult(
                    OperationStatus.SUCCESS if success else OperationStatus.FAILURE,
                    {"index": index, "added": success, "action": "wmap_targets_add"},
                    time.time() - start_time
                )
                
            elif action == "clear":
                result = await self.msf.execute_command("wmap_targets -c")
                self._targets.clear()
                
                return OperationResult(
                    OperationStatus.SUCCESS,
                    {"cleared": True, "action": "wmap_targets_clear"},
                    time.time() - start_time
                )
                
            else:
                return OperationResult(
                    OperationStatus.FAILURE,
                    None,
                    time.time() - start_time,
                    "Invalid targets action"
                )
                
        except Exception as e:
            logger.error(f"WMAP targets error: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def cmd_run(self, test_mode: bool = False, modules: Optional[List[str]] = None, **kwargs) -> OperationResult:
        """Run WMAP scan"""
        start_time = time.time()
        try:
            if not self._enabled:
                return OperationResult(
                    OperationStatus.FAILURE,
                    None,
                    time.time() - start_time,
                    "WMAP scanner is not enabled"
                )
                
            if not self._targets:
                return OperationResult(
                    OperationStatus.FAILURE,
                    None,
                    time.time() - start_time,
                    "No targets configured"
                )
                
            # Run scan
            cmd = "wmap_run"
            if test_mode:
                cmd += " -t"
            if modules:
                cmd += f" -m {','.join(modules)}"
            else:
                cmd += " -e"  # Run all enabled modules
                
            result = await self.msf.execute_command(cmd, timeout=600)  # 10 minute timeout
            stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
            
            # Parse results
            vulns = self._parse_scan_results(stdout)
            self._scan_results[datetime.now().isoformat()] = vulns
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {
                    "scan_complete": True,
                    "vulnerabilities": len(vulns),
                    "targets_scanned": len(self._targets),
                    "action": "wmap_run",
                    "test_mode": test_mode
                },
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"WMAP run error: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def cmd_vulns(self, **kwargs) -> OperationResult:
        """List discovered vulnerabilities"""
        start_time = time.time()
        try:
            result = await self.msf.execute_command("wmap_vulns -l")
            stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
            vulns = self._parse_vulnerabilities(stdout)
            
            return OperationResult(
                OperationStatus.SUCCESS,
                {"vulnerabilities": vulns, "action": "wmap_vulns", "count": len(vulns)},
                time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"WMAP vulns error: {e}")
            return OperationResult(
                OperationStatus.FAILURE,
                None,
                0.0,
                str(e)
            )
            
    async def _refresh_modules(self) -> None:
        """Refresh available WMAP modules"""
        try:
            result = await self.msf.execute_command("wmap_modules -l")
            stdout = result.data.get("stdout", "") if result.status == OperationStatus.SUCCESS else ""
            self._available_modules = self._parse_modules(stdout)
        except Exception as e:
            logger.error(f"Failed to refresh WMAP modules: {e}")
            
    def _parse_sites(self, output: str) -> List[Dict[str, Any]]:
        """Parse sites from WMAP output"""
        sites = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if 'http' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    sites.append({
                        "id": parts[0],
                        "url": parts[1],
                        "vhost": parts[2] if len(parts) > 2 else ""
                    })
                    
        return sites
        
    def _parse_targets(self, output: str) -> List[Dict[str, Any]]:
        """Parse targets from WMAP output"""
        targets = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('['):
                parts = line.split()
                if len(parts) >= 2:
                    targets.append({
                        "index": len(targets),
                        "url": parts[0],
                        "status": parts[1] if len(parts) > 1 else "pending"
                    })
                    
        return targets
        
    def _parse_scan_results(self, output: str) -> List[Dict[str, Any]]:
        """Parse scan results from WMAP output"""
        vulns = []
        current_vuln = None
        
        for line in output.split('\n'):
            if '[+]' in line and 'found' in line.lower():
                if current_vuln:
                    vulns.append(current_vuln)
                current_vuln = {
                    "finding": line.strip(),
                    "details": []
                }
            elif current_vuln and line.strip():
                current_vuln["details"].append(line.strip())
                
        if current_vuln:
            vulns.append(current_vuln)
            
        return vulns
        
    def _parse_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from WMAP output"""
        vulns = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('['):
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    vulns.append({
                        "timestamp": parts[0],
                        "host": parts[1],
                        "port": parts[2],
                        "vulnerability": parts[3]
                    })
                    
        return vulns
        
    def _parse_modules(self, output: str) -> List[str]:
        """Parse available modules from WMAP output"""
        modules = []
        
        for line in output.split('\n'):
            if 'auxiliary/' in line:
                module = line.strip().split()[0]
                modules.append(module)
                
        return modules