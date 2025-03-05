using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Text;

public static class SqlHelper
{
    /// <summary>
    /// Executes a scalar query and returns the first column of the first row
    /// </summary>
    public static object ExecuteScalarQuery(SqlConnection con, string query)
    {
        try
        {
            using (SqlCommand command = new SqlCommand(query, con))
            {
                return command.ExecuteScalar();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing scalar query: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Executes a reader query and processes each row with the provided action
    /// </summary>
    public static void ExecuteReaderQuery(SqlConnection con, string query, Action<SqlDataReader> processRow)
    {
        try
        {
            using (SqlCommand command = new SqlCommand(query, con))
            using (SqlDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    processRow(reader);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing reader query: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if the current user is a member of the specified server role
    /// </summary>
    public static bool IsServerRoleMember(SqlConnection con, string roleName)
    {
        string query = $"SELECT IS_SRVROLEMEMBER('{roleName}');";
        var result = ExecuteScalarQuery(con, query);
        return result != null && Convert.ToInt32(result) == 1;
    }

    /// <summary>
    /// Gets the current system user
    /// </summary>
    public static string GetCurrentUser(SqlConnection con)
    {
        return ExecuteScalarQuery(con, "SELECT SYSTEM_USER;")?.ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the current SQL user name
    /// </summary>
    public static string GetSqlUserName(SqlConnection con)
    {
        return ExecuteScalarQuery(con, "SELECT USER_NAME();")?.ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the current server name
    /// </summary>
    public static string GetServerName(SqlConnection con)
    {
        return ExecuteScalarQuery(con, "SELECT @@SERVERNAME;")?.ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets all linked servers
    /// </summary>
    public static List<string> GetLinkedServers(SqlConnection con)
    {
        var linkedServers = new List<string>();
        ExecuteReaderQuery(con, "EXEC sp_linkedservers;", reader =>
        {
            linkedServers.Add(reader["SRV_NAME"].ToString());
        });
        return linkedServers;
    }

    /// <summary>
    /// Executes a query on a linked server using EXEC AT format
    /// </summary>
    public static void ExecuteLinkedServerQueryUsingExecAt(SqlConnection con, string linkedServer, string query, Action<SqlDataReader> processRow = null)
    {
        string linkedQuery = $"EXEC('{EscapeQueryForLinkedExecution(query)}') AT [{linkedServer}];";

        if (processRow != null)
        {
            ExecuteReaderQuery(con, linkedQuery, processRow);
        }
        else
        {
            ExecuteScalarQuery(con, linkedQuery);
        }
    }

    /// <summary>
    /// Executes a query on a linked server using OPENQUERY format
    /// </summary>
    public static void ExecuteLinkedServerQueryUsingOpenQuery(SqlConnection con, string linkedServer, string query, Action<SqlDataReader> processRow = null)
    {
        string linkedQuery = $"SELECT * FROM OPENQUERY([{linkedServer}], '{EscapeQueryForLinkedExecution(query)}')";

        if (processRow != null)
        {
            ExecuteReaderQuery(con, linkedQuery, processRow);
        }
        else
        {
            ExecuteScalarQuery(con, linkedQuery);
        }
    }

    /// <summary>
    /// Escapes a query for linked server execution (handles single quotes)
    /// </summary>
    private static string EscapeQueryForLinkedExecution(string query)
    {
        return query.Replace("'", "''");
    }

    /// <summary>
    /// Enables xp_cmdshell on a linked server
    /// </summary>
    public static bool EnableXpCmdShellOnLinkedServer(SqlConnection con, string linkedServer)
    {
        try
        {
            ExecuteLinkedServerQueryUsingExecAt(con, linkedServer, "sp_configure 'show advanced options', 1; RECONFIGURE;");
            ExecuteLinkedServerQueryUsingExecAt(con, linkedServer, "sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error enabling xp_cmdshell on linked server: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Execute command on linked server via xp_cmdshell
    /// </summary>
    public static void ExecuteCommandOnLinkedServer(SqlConnection con, string linkedServer, string command, bool useOpenQuery = false)
    {
        string escapedCommand = command.Replace("'", "''");
        string query = $"EXEC master..xp_cmdshell '{escapedCommand}'";

        if (useOpenQuery)
        {
            Console.WriteLine($"Executing on {linkedServer} using OPENQUERY:");
            ExecuteLinkedServerQueryUsingOpenQuery(con, linkedServer, query, reader =>
            {
                if (reader[0] != null)
                {
                    Console.WriteLine(reader[0]);
                }
            });
        }
        else
        {
            Console.WriteLine($"Executing on {linkedServer} using EXEC AT:");
            ExecuteLinkedServerQueryUsingExecAt(con, linkedServer, query, reader =>
            {
                if (reader[0] != null)
                {
                    Console.WriteLine(reader[0]);
                }
            });
        }
    }

    /// <summary>
    /// Check if a feature is enabled
    /// </summary>
    public static bool IsFeatureEnabled(SqlConnection con, string featureName)
    {
        string query = $"SELECT CONVERT(INT, value) FROM sys.configurations WHERE name = '{featureName}'";
        var result = ExecuteScalarQuery(con, query);
        return result != null && Convert.ToInt32(result) == 1;
    }

    /// <summary>
    /// Check if CLR is enabled
    /// </summary>
    public static bool IsClrEnabled(SqlConnection con)
    {
        return IsFeatureEnabled(con, "clr enabled");
    }

    /// <summary>
    /// Check if xp_cmdshell is enabled
    /// </summary>
    public static bool IsXpCmdShellEnabled(SqlConnection con)
    {
        return IsFeatureEnabled(con, "xp_cmdshell");
    }

    /// <summary>
    /// Check if OLE Automation Procedures are enabled
    /// </summary>
    public static bool IsOleAutomationEnabled(SqlConnection con)
    {
        return IsFeatureEnabled(con, "Ole Automation Procedures");
    }

    /// <summary>
    /// Check if a CLR stored procedure exists
    /// </summary>
    public static bool ClrStoredProcedureExists(SqlConnection con, string procedureName)
    {
        string query = $"SELECT COUNT(*) FROM sys.procedures WHERE name = '{procedureName}' AND type = 'PC'";
        var result = ExecuteScalarQuery(con, query);
        return result != null && Convert.ToInt32(result) > 0;
    }

    
}