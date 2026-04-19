# MSF Console MCP Server v5.0

Production-ready Model Context Protocol (MCP) server implementation for Metasploit Framework Console, providing 48 specialized penetration testing tools through a structured AI assistant interface.

## 🚀 Features

### Core Capabilities (48 Tools)
- **Exploitation Framework** - Complete exploit/payload management
- **Session Management** - Advanced interaction with compromised systems  
- **Post-Exploitation** - Privilege escalation, persistence, lateral movement
- **Network Analysis** - Scanning, enumeration, service discovery
- **Vulnerability Assessment** - Automated vulnerability identification
- **Credential Management** - Centralized credential storage and testing
- **Reporting Engine** - Professional penetration testing reports
- **Evasion Suite** - AV bypass and obfuscation techniques

### Key Components
- `mcp_server_stable.py` - Main MCP server with 48 tools
- `msf_stable_integration.py` - MSF console integration layer
- `msf_plugin_system.py` - Plugin architecture
- `msf_advanced_session_manager.py` - Session handling
- `msf_enhanced_tools.py` - Enhanced tool implementations
- `msf_extended_tools.py` - Extended functionality

## 📦 Installation

1. **Clone the repository:**
```bash
# Personal Repository
git clone https://github.com/PreistlyPython/msfconsole-mcp.git

# Organization Repository
git clone https://github.com/LYFTIUM-INC/msfconsole-mcp.git

cd msfconsole-mcp
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure Claude Desktop:**

Add to `~/.config/claude-code/mcp_servers.json`:
```json
{
  "msfconsole-full": {
    "command": "python",
    "args": ["/path/to/msfconsole-mcp/mcp_server_stable.py"]
  }
}
```

4. **Restart Claude Desktop** to load the MCP server

## 🛠️ Usage

### Available Tools (48 Total)

#### Primary Operations
- `msf_execute_command` - Execute MSFConsole commands
- `msf_module_manager` - Complete module lifecycle management
- `msf_session_interact` - Advanced session interaction
- `msf_exploit_chain` - Multi-stage exploitation workflows
- `msf_handler_manager` - Payload handler management

#### Scanning & Discovery
- `msf_scanner_suite` - Comprehensive scanning operations
- `msf_vulnerability_tracker` - Vulnerability tracking
- `msf_credential_manager` - Credential management
- `msf_pivot_manager` - Network pivoting and routing

#### Post-Exploitation
- `msf_post_exploitation` - Post-exploitation modules
- `msf_loot_collector` - Automated loot collection
- `msf_session_persistence` - Persistence mechanisms
- `msf_session_upgrader` - Shell to Meterpreter upgrade

#### Advanced Features
- `msf_evasion_suite` - AV bypass techniques
- `msf_listener_orchestrator` - Advanced listener management
- `msf_workspace_automator` - Workspace automation
- `msf_reporting_engine` - Report generation

### Example Usage in Claude

```
User: "Scan the network 192.168.1.0/24"
Claude: [Uses msf_module_manager to load and run network discovery]

User: "Exploit the vulnerable service on port 8080"
Claude: [Uses msf_exploit_chain for automated exploitation]

User: "Generate a report of findings"
Claude: [Uses msf_reporting_engine for professional documentation]
```

## 🔒 Security Notice

**IMPORTANT**: This tool is for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Ensure proper network isolation during testing
- Use workspaces to separate engagements
- Review all commands before execution
- Comply with all applicable laws and regulations

## 🧪 Testing

Validate the installation:
```bash
python test_mcp_server.py
```

## 📊 Performance

- **Tools Available**: 48
- **Average Response Time**: 15.7 seconds
- **Success Rate**: 87% in production testing
- **Tested Against**: Real network infrastructure

## 🤝 Contributing

This is a specialized security tool. Contributions should focus on:
- Bug fixes and stability improvements
- Additional MSF module support
- Enhanced error handling
- Documentation improvements

## 📄 License

For authorized security testing and educational purposes only. Users are responsible for compliance with all applicable laws and regulations.

## ⚠️ Disclaimer

This tool can perform actions that may be illegal if used without authorization. Never use this tool on systems you do not own or without explicit written permission. The authors assume no liability for misuse.

---
**Version**: 5.0  
**Status**: Production Ready  
**Tools**: 48 Specialized MSF Console Tools  
**Framework**: Metasploit Framework Integration via MCP