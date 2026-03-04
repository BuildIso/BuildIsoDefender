using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0 || args[0] != "--scan")
        {
            Console.WriteLine("Usage: BuildIsoDefender --scan");
            return;
        }

        Console.WriteLine("=== BuildIso Defender ===");
        Console.WriteLine("Scanning system for BuildIso.exe...\n");

        var files = FindBuildIsoFiles();
        if (files.Count == 0)
        {
            Console.WriteLine("No BuildIso.exe found on this system.");
            return;
        }

        Console.WriteLine($"Found {files.Count} file(s).\n");

        string officialHash = await GetOfficialDigestFromAllReleases();

        if (officialHash == null)
        {
            Console.WriteLine("[ERROR] Unable to retrieve any official digest from GitHub.");
            return;
        }

        Console.WriteLine($"Official SHA256: {officialHash}\n");

        foreach (var file in files)
        {
            Console.WriteLine($"Checking: {file}");

            string localHash = ComputeSHA256(file);
            long size = new FileInfo(file).Length;

            Console.WriteLine($"Local SHA256: {localHash}");
            Console.WriteLine($"Size: {size} bytes");

            if (localHash.Equals(officialHash, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[STATUS] OFFICIAL — File is authentic.\n");
            }
            else
            {
                Console.WriteLine("[STATUS] WARNING — File does NOT match the official version!");

                if (size < 100_000)
                    Console.WriteLine("[THREAT] Possible phishing stub.");

                if (size > 20_000_000)
                    Console.WriteLine("[THREAT] Possible malware injection.");

                Console.WriteLine();
            }
        }
    }

    static List<string> FindBuildIsoFiles()
    {
        var results = new List<string>();
        string filename = "BuildIso.exe";

        string[] paths = {
            Directory.GetCurrentDirectory(),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };

        foreach (var path in paths)
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(path, filename, SearchOption.AllDirectories))
                    results.Add(file);
            }
            catch { }
        }

        return results;
    }

    static async Task<string> GetOfficialDigestFromAllReleases()
    {
        string[] urls = {
            "https://api.github.com/repos/BuildIso/BuildIso/releases/tags/v2026.5",
            "https://api.github.com/repos/BuildIso/BuildIso/releases/tags/v2026.4",
            "https://api.github.com/repos/BuildIso/BuildIso/releases/tags/v2026.3",
            "https://api.github.com/repos/BuildIso/BuildIso/releases/tags/v2026.2",
            "https://api.github.com/repos/BuildIso/BuildIso/releases/tags/v2026.1"
        };

        foreach (var url in urls)
        {
            string digest = await GetDigestFromRelease(url);
            if (digest != null)
            {
                Console.WriteLine($"Matched release: {url}");
                return digest;
            }
        }

        return null;
    }

    static async Task<string> GetDigestFromRelease(string url)
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BuildIsoDefender");

        try
        {
            string json = await client.GetStringAsync(url);
            using var doc = JsonDocument.Parse(json);

            foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
            {
                string name = asset.GetProperty("name").GetString();

                if (name == "BuildIso.exe")
                {
                    if (asset.TryGetProperty("digest", out var digestProp))
                    {
                        string digest = digestProp.GetString();

                        if (digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                            return digest.Substring("sha256:".Length).Trim();
                    }
                }
            }
        }
        catch
        {
            // ignore errors and continue to next URL
        }

        return null;
    }

    static string ComputeSHA256(string file)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(file);
        return Convert.ToHexString(sha.ComputeHash(stream));
    }
}
