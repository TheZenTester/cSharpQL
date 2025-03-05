using System;
using System.IO;
using System.Text;

/// <summary>
/// Helper class for file operations
/// </summary>
public static class FileHelper
{
    /// <summary>
    /// Reads a file and returns its contents as a hex string
    /// </summary>
    public static string ReadFileAsHex(string filePath)
    {
        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            StringBuilder hexString = new StringBuilder(fileBytes.Length * 2);
            
            foreach (byte b in fileBytes)
            {
                hexString.AppendFormat("{0:X2}", b);
            }
            
            return hexString.ToString();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading file: {ex.Message}");
            return string.Empty;
        }
    }
}
