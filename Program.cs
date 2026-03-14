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

        var allDigests = await GetAllDigestsFromReleases();

        if (allDigests.Count == 0)
        {
            Console.WriteLine("[ERROR] No official digests found on GitHub.");
            return;
        }

        Console.WriteLine("Official versions found:");
        foreach (var kv in allDigests)
            Console.WriteLine($" - {kv.Key}: {kv.Value}");
        Console.WriteLine();

        foreach (var file in files)
        {
            Console.WriteLine($"Checking: {file}");

            string localHash = ComputeSHA256(file);
            long size = new FileInfo(file).Length;

            Console.WriteLine($"Local SHA256: {localHash}");
            Console.WriteLine($"Size: {size} bytes");

            bool match = false;

            foreach (var kv in allDigests)
            {
                if (localHash.Equals(kv.Value, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"[STATUS] OFFICIAL — Matches version {kv.Key}\n");
                    match = true;
                    break;
                }
            }

            if (!match)
            {
                Console.WriteLine("[STATUS] WARNING — File does NOT match ANY official version!");

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

    static async Task<Dictionary<string, string>> GetAllDigestsFromReleases()
    {
        string[] versions = {
            "v2026.8",
            "v2026.7",
            "v2026.6",
            "v2026.5",
            "v2026.4",
            "v2026.3",
            "v2026.2",
            "v2026.1"
        };

        var dict = new Dictionary<string, string>();

        foreach (var version in versions)
        {
            string url = $"https://api.github.com/repos/BuildIso/BuildIso/releases/tags/{version}";
            Console.WriteLine($"Checking release: {url}");

            string digest = await GetDigestFromRelease(url);

            if (!string.IsNullOrWhiteSpace(digest))
            {
                Console.WriteLine($" → Found digest for {version}\n");
                dict[version] = digest;
            }
            else
            {
                Console.WriteLine($" → No digest for {version}\n");
            }
        }

        return dict;
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

                if (name.Equals("BuildIso.exe", StringComparison.OrdinalIgnoreCase))
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
            return null;
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
