# cSharpQL

A C# tool for SQL Server enumeration, privilege escalation, and lateral movement during penetration testing engagements.

## Limitations
- Linked servers work... kinda... just don't ask it to link to more than 2 servers... ;) 

## Overview

cSharpQL is a .NET console application that helps security professionals interact with SQL Server instances. It enables SQL Server enumeration, including linked servers, authentication relaying, permission checks, and command execution through various methods.

## Features

* **Server Enumeration**: Discover SQL Servers in a domain
* **Permission Enumeration**: Check SQL Server permissions and role memberships
* **Linked Server Support**: Enumerate and interact with linked SQL Servers
* **Linked Server Chain Traversal**: Traverse through chains of linked servers
* **Authentication Relays**: Coerce SQL Server to authenticate to an attacker-controlled SMB share
* **Command Execution**: Execute commands via:
  * xp_cmdshell
  * OLE Automation
  * CLR assemblies
* **Impersonation**: Leverage impersonation capabilities for privilege escalation
* **Automated Enablement**: Automatically enable required features if they're disabled

## Usage

```
cSharpQL.exe [flags] [options]
```

### Main Commands

| Command | Description |
|---------|-------------|
| `/enum <subcommand>` | Enumeration commands (servers, perms, impersonate, linked) |
| `/impersonate <type>` | Impersonate a SQL login or user (user, login) |
| `/hash` | Coerce SQL server to authenticate to SMB share |
| `/relay` | Create command for ntlmrelayx and coerce auth |
| `/linked <server>` | Execute commands on a linked server |
| `/enable <type>` | Enable command execution method (xpcmd, ole, clr) |
| `/clr <action>` | Manage CLR assemblies (enable, create, drop) |
| `/cmd-exec <type>` | Execute OS commands (xpcmd, ole, clr) |

### Connection Options

| Option | Description |
|--------|-------------|
| `/u <username>` | SQL Server username (default: Windows auth) |
| `/p <password>` | SQL Server password |
| `/d <domain>` | Target domain for enumeration |
| `/db <database>` | Target database (default: master) |
| `/tgt <server>` | Target SQL server (default: localhost) |

### Additional Options

| Option | Description |
|--------|-------------|
| `/ea <account>` | Execute as account (default: USER=dbo, LOGIN=sa) |
| `/sp <procedure>` | Stored procedure name (default: cmdExec) |
| `/assembly-file <path>` | Path to CLR assembly file |
| `/command <cmd>` | OS command to execute |

## Example Usage

### Enumeration

Find SQL servers in a domain:
```
cSharpQL.exe /enum servers /d example.com
```

Check permissions on a SQL server:
```
cSharpQL.exe /tgt sql01.example.com /enum perms
```

Check which accounts can be impersonated:
```
cSharpQL.exe /tgt sql01.example.com /enum impersonate
```

Enumerate linked servers:
```
cSharpQL.exe /tgt sql01.example.com /enum linked
```

### Linked Server Operations

Enumerate a linked server:
```
cSharpQL.exe /tgt sql01.example.com /linked sql02.example.com
```

Execute a command on a linked server:
```
cSharpQL.exe /tgt sql01.example.com /linked sql02.example.com /command "whoami"
```

Work with a linked server chain:
```
cSharpQL.exe /tgt sql01.example.com /linked sql02.example.com,sql03.example.com
```

### Privilege Escalation

Impersonate the SA account:
```
cSharpQL.exe /tgt sql01.example.com /impersonate login /ea sa
```

Enable xp_cmdshell and execute a command:
```
cSharpQL.exe /tgt sql01.example.com /enable xpcmd /cmd-exec xpcmd /command "whoami"
```

Create a CLR assembly and execute a command:
```
cSharpQL.exe /tgt sql01.example.com /clr create /assembly-file evil.dll /cmd-exec clr /command "whoami"
```

### Authentication Relays

Capture NTLM hash using Responder:
```
cSharpQL.exe /tgt sql01.example.com /hash
```

Relay authentication using ntlmrelayx:
```
cSharpQL.exe /tgt sql01.example.com /relay
```

## Notes

* This tool is designed for legitimate penetration testing and security assessment purposes only.
* Some functionality requires elevated privileges on the SQL Server.
* Linked server chain traversal is limited to the capabilities provided by the SQL Server and may not work in all environments.

## Requirements

* .NET Framework 4.7.3 or higher
* Appropriate permissions on target SQL Servers
* For domain enumeration: Windows domain environment
