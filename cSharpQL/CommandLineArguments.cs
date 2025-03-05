using System;
using System.Collections.Generic;

/// <summary>
/// Class to handle command line arguments parsing
/// </summary>
public class CommandLineArguments
{
    // Connection options
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Database { get; set; } = "master";
    public string SqlServer { get; set; } = "localhost";
    public string Domain { get; set; } = "";

    // Authentication options
    public bool UseHash { get; set; } = false;
    public bool UseRelay { get; set; } = false;

    // Enumeration options
    public bool EnumerateServers { get; set; } = false;
    public bool EnumeratePermissions { get; set; } = false;
    public bool EnumerateLinkedServers { get; set; } = false;
    public bool EnumerateImpersonation { get; set; } = false;

    // Privilege escalation options
    public string ImpersonateType { get; set; } = ""; // USER or LOGIN
    public string ImpersonateAccount { get; set; } = "";

    // Command execution options
    public bool EnableXpCmd { get; set; } = false;
    public bool EnableOle { get; set; } = false;
    public bool EnableClr { get; set; } = false;
    public bool CreateClr { get; set; } = false;
    public bool DropClr { get; set; } = false;
    public bool ExecuteCommand { get; set; } = false;
    public string CommandExecType { get; set; } = "";
    public string OsCommand { get; set; } = "";

    // CLR options
    public string AssemblyFile { get; set; } = "";
    public string ProcedureName { get; set; } = "cmdExec";

    // Linked server options
    public string LinkedServer { get; set; } = "";
    public List<string> LinkedServerChain { get; set; } = new List<string>();
    public bool UseOpenQuery { get; set; } = false;
    public bool ExecuteOnLinked { get; set; } = false;

    // Flags
    public bool ShowHelp { get; set; } = true;

    /// <summary>
    /// Parse command line arguments
    /// </summary>
    public static CommandLineArguments Parse(string[] args)
    {
        var arguments = new CommandLineArguments();

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i].ToUpper();

            if (arg == "/HELP" || arg == "/?")
            {
                arguments.ShowHelp = true;
                return arguments;
            }

            // Main operation modes
            if (arg == "/HASH")
            {
                arguments.UseHash = true;
                arguments.ShowHelp = false;
            }
            else if (arg == "/RELAY")
            {
                arguments.UseHash = true;
                arguments.UseRelay = true;
                arguments.ShowHelp = false;
            }
            else if (arg == "/ENUM")
            {
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    // Handle subcommands
                    string subCmd = args[++i].ToUpper();

                    switch (subCmd)
                    {
                        case "SERVERS":
                            arguments.EnumerateServers = true;
                            break;
                        case "PERMS":
                            arguments.EnumeratePermissions = true;
                            break;
                        case "IMPERSONATE":
                            arguments.EnumerateImpersonation = true;
                            break;
                        case "LINKED":
                            arguments.EnumerateLinkedServers = true;
                            break;
                        default:
                            Console.WriteLine($"ERROR - Invalid enum subcommand: {subCmd}");
                            arguments.ShowHelp = true;
                            break;
                    }
                }
                else
                {
                    // Legacy behavior for backward compatibility
                    arguments.EnumerateServers = true;
                }
            }
            else if (arg == "/PERMS")
            {
                arguments.EnumeratePermissions = true;
                arguments.ShowHelp = false;
            }
            else if (arg == "/IMPERSONATE")
            {
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    string impersonateType = args[++i].ToUpper();

                    if (impersonateType == "USER" || impersonateType == "LOGIN")
                    {
                        arguments.ImpersonateType = impersonateType;
                    }
                    else
                    {
                        Console.WriteLine($"ERROR - Invalid impersonate type: {impersonateType}");
                        arguments.ShowHelp = true;
                    }
                }
                else
                {
                    Console.WriteLine("ERROR - Impersonate type not specified (USER/LOGIN)");
                    arguments.ShowHelp = true;
                }
            }
            else if (arg == "/ENABLE")
            {
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    string enableType = args[++i].ToUpper();

                    switch (enableType)
                    {
                        case "XPCMD":
                            arguments.EnableXpCmd = true;
                            break;
                        case "OLE":
                            arguments.EnableOle = true;
                            break;
                        case "CLR":
                            arguments.EnableClr = true;
                            break;
                        default:
                            Console.WriteLine($"ERROR - Invalid enable type: {enableType}");
                            arguments.ShowHelp = true;
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("ERROR - Enable type not specified (XPCMD/OLE/CLR)");
                    arguments.ShowHelp = true;
                }
            }
            else if (arg == "/CLR")
            {
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    string clrAction = args[++i].ToUpper();

                    switch (clrAction)
                    {
                        case "ENABLE":
                            arguments.EnableClr = true;
                            break;
                        case "CREATE":
                            arguments.CreateClr = true;
                            break;
                        case "DROP":
                            arguments.DropClr = true;
                            break;
                        default:
                            Console.WriteLine($"ERROR - Invalid CLR action: {clrAction}");
                            arguments.ShowHelp = true;
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("ERROR - CLR action not specified (ENABLE/CREATE/DROP)");
                    arguments.ShowHelp = true;
                }
            }
            else if (arg == "/CMD-EXEC")
            {
                arguments.ExecuteCommand = true;
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    string cmdExecType = args[++i].ToUpper();

                    if (cmdExecType == "XPCMD" || cmdExecType == "OLE" || cmdExecType == "CLR")
                    {
                        arguments.CommandExecType = cmdExecType;
                    }
                    else
                    {
                        Console.WriteLine($"ERROR - Invalid command execution type: {cmdExecType}");
                        arguments.ShowHelp = true;
                    }
                }
                else
                {
                    Console.WriteLine("ERROR - Command execution type not specified (XPCMD/OLE/CLR)");
                    arguments.ShowHelp = true;
                }
            }
            else if (arg == "/LINKED")
            {
                arguments.ShowHelp = false;

                if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                {
                    string linkedServerArg = args[++i];

                    // Check if we have a chain of linked servers (comma-separated list)
                    if (linkedServerArg.Contains(","))
                    {
                        string[] servers = linkedServerArg.Split(',');
                        arguments.LinkedServerChain.AddRange(servers);
                        arguments.LinkedServer = servers[0]; // Set the first one as primary
                    }
                    else
                    {
                        arguments.LinkedServer = linkedServerArg;
                        arguments.LinkedServerChain.Add(linkedServerArg);
                    }

                    arguments.ExecuteOnLinked = true;

                    // Check if there's an additional parameter for query type
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("/"))
                    {
                        string queryType = args[++i].ToUpper();
                        if (queryType == "OPENQUERY")
                        {
                            arguments.UseOpenQuery = true;
                        }
                        else if (queryType != "EXECAT")
                        {
                            Console.WriteLine($"WARNING: Unknown query type '{queryType}', defaulting to EXECAT");
                            i--; // Step back as this might be another parameter
                        }
                    }
                }
                else
                {
                    Console.WriteLine("ERROR - Linked server name not specified");
                    arguments.ShowHelp = true;
                }
            }

            // Common parameters
            else if (arg.StartsWith("/U") && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.Username = args[++i];
            }
            else if (arg.StartsWith("/P") && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.Password = args[++i];
            }
            else if (arg.StartsWith("/DB") && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.Database = args[++i];
            }
            else if (arg.StartsWith("/TGT") && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.SqlServer = args[++i];
                arguments.ShowHelp = false;
            }
            else if (arg.StartsWith("/D") && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.Domain = args[++i];
            }
            else if (arg == "/EA" && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.ImpersonateAccount = args[++i];
            }
            else if (arg == "/SP" && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.ProcedureName = args[++i];
            }
            else if (arg == "/ASSEMBLY-FILE" && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.AssemblyFile = args[++i];
            }
            else if (arg == "/COMMAND" && i + 1 < args.Length && !args[i + 1].StartsWith("/"))
            {
                arguments.OsCommand = args[++i];
            }
            else if (!arg.StartsWith("/"))
            {
                // Skip non-flag arguments
                continue;
            }
            else
            {
                Console.WriteLine($"ERROR - Invalid flag: {arg}");
                arguments.ShowHelp = true;
            }
        }

        return arguments;
    }

    /// <summary>
    /// Display help information
    /// </summary>
    public static void ShowHelpText()
    {
        Console.WriteLine("SQL Server Tool");
        Console.WriteLine("");
        Console.WriteLine("Tool for SQL Server enumeration, privilege escalation, and lateral movement\n");
        Console.WriteLine("Format: cSharpQL.exe /flag value\n");

        Console.WriteLine("MAIN COMMANDS:");
        Console.WriteLine("  /enum <subcommand>   - Enumeration commands:");
        Console.WriteLine("     servers           - Find SQL servers in domain using setspn");
        Console.WriteLine("     perms            - Check SQL Server permissions");
        Console.WriteLine("     impersonate      - Check which accounts can be impersonated");
        Console.WriteLine("     linked           - Enumerate linked servers");
        Console.WriteLine("  /perms              - Legacy: Check permissions (same as /enum perms)");
        Console.WriteLine("  /impersonate <type> - Impersonate a SQL login or user:");
        Console.WriteLine("     user             - EXECUTE AS USER");
        Console.WriteLine("     login            - EXECUTE AS LOGIN");
        Console.WriteLine("  /hash               - Coerce SQL server to authenticate to SMB share");
        Console.WriteLine("  /relay              - Create command for ntlmrelayx and coerce auth");
        Console.WriteLine("  /linked <server>    - Execute commands on a linked server");
        Console.WriteLine("     [server]         - Single server or comma-separated chain (server1,server2,server3)");
        Console.WriteLine("     [execat]         - Use EXEC AT syntax (default)");
        Console.WriteLine("     [openquery]      - Use OPENQUERY syntax");

        Console.WriteLine("\nCOMMAND EXECUTION:");
        Console.WriteLine("  /enable <type>       - Enable command execution method:");
        Console.WriteLine("     xpcmd            - Enable xp_cmdshell");
        Console.WriteLine("     ole              - Enable OLE Automation Procedures");
        Console.WriteLine("     clr              - Enable CLR integration");
        Console.WriteLine("  /clr <action>        - Manage CLR assemblies:");
        Console.WriteLine("     enable           - Enable CLR (same as /enable clr)");
        Console.WriteLine("     create           - Import DLL and create stored procedure");
        Console.WriteLine("     drop             - Drop a stored procedure and assembly");
        Console.WriteLine("  /cmd-exec <type>     - Execute OS commands via:");
        Console.WriteLine("     xpcmd            - Execute via xp_cmdshell");
        Console.WriteLine("     ole              - Execute via OLE object");
        Console.WriteLine("     clr              - Execute via CLR stored procedure");

        Console.WriteLine("\nCONNECTION OPTIONS:");
        Console.WriteLine("  /u <username>        - SQL Server username (default: Windows auth)");
        Console.WriteLine("  /p <password>        - SQL Server password");
        Console.WriteLine("  /d <domain>          - Target domain for enumeration");
        Console.WriteLine("  /db <database>       - Target database (default: master)");
        Console.WriteLine("  /tgt <server>        - Target SQL server (default: localhost)");

        Console.WriteLine("\nADDITIONAL OPTIONS:");
        Console.WriteLine("  /ea <account>        - Execute as account (default: USER=dbo, LOGIN=sa)");
        Console.WriteLine("  /sp <procedure>      - Stored procedure name (default: cmdExec)");
        Console.WriteLine("  /assembly-file <path> - Path to CLR assembly file");
        Console.WriteLine("  /command <cmd>       - OS command to execute");
        Console.WriteLine("");
    }
}