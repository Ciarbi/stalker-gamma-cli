using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Serilog;

namespace Stalker.Gamma.Services;

public interface IModDbSessionService
{
    string? GetCookieHeader(string? url);
    bool IsModDbUrl(string? url);
    string CookiesPath { get; }
    IReadOnlyList<string> CandidateCookiePaths { get; }
    int CaptureWithFirefox(string firefoxPath, string url = "https://www.moddb.com/");
    string? FindFirefox(string? explicitPath = null);
    ModDbCookieLoadResult LoadCookies();
    string ModDb403Message(string? url = null);
}

public record ModDbCookieEntry(
    [property: JsonPropertyName("domain")] string? Domain,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("value")] string? Value,
    [property: JsonPropertyName("path")] string? PathValue
);

public record ModDbCookieFile(
    [property: JsonPropertyName("cookies")] List<ModDbCookieEntry>? Cookies,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("profile")] string? Profile
);

public record ModDbCookieLoadResult(int Count, string? LoadedFrom, bool HasCfClearance);

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(ModDbCookieFile))]
internal partial class ModDbCookieFileJsonContext : JsonSerializerContext;

public class ModDbSessionService(ILogger logger) : IModDbSessionService
{
    private const string GetScHint =
        "Run `stalker-gamma get-sc` to capture ModDB session cookies with a real browser (Firefox). If you already used gamma-launcher, its `~/.config/gamma-launcher/moddb_cookies.json` is also read automatically.";

    private readonly object _lock = new();
    private string? _cachedHeader;
    private DateTime _cachedAt;
    private string? _cachedFrom;

    public bool IsModDbUrl(string? url) => !string.IsNullOrWhiteSpace(url) && url.Contains("moddb.com", StringComparison.OrdinalIgnoreCase);

    public string CookiesPath => Path.Join(AppDataDir, "moddb_cookies.json");

    public IReadOnlyList<string> CandidateCookiePaths
    {
        get
        {
            var list = new List<string> { CookiesPath };
            var gammaLauncher = GammaLauncherCookiesPath();
            if (!string.IsNullOrWhiteSpace(gammaLauncher) && !list.Contains(gammaLauncher, StringComparer.OrdinalIgnoreCase))
                list.Add(gammaLauncher);
            return list;
        }
    }

    private static string AppDataDir =>
        Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "stalker-gamma");

    private static string? GammaLauncherCookiesPath()
    {
        // Linux/macOS: ~/.config/gamma-launcher/moddb_cookies.json (platformdirs user_config_path)
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        var configBase = !string.IsNullOrWhiteSpace(xdg)
            ? xdg
            : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                : Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var p = Path.Join(configBase, "gamma-launcher", "moddb_cookies.json");
        return p;
    }

    public string? GetCookieHeader(string? url)
    {
        if (!IsModDbUrl(url))
            return null;
        lock (_lock)
        {
            // Cache for a short time to avoid re-reading/parsing on every request
            if (_cachedAt != default && DateTime.UtcNow - _cachedAt < TimeSpan.FromSeconds(30))
                return _cachedHeader;

            var result = LoadCookiesCore();
            _cachedHeader = result.Header;
            _cachedFrom = result.LoadedFrom;
            _cachedAt = DateTime.UtcNow;
            if (result.Count > 0)
                logger.Debug("Loaded {Count} ModDB cookie(s) from {Path}", result.Count, result.LoadedFrom);
            return _cachedHeader;
        }
    }

    public ModDbCookieLoadResult LoadCookies()
    {
        lock (_lock)
        {
            var result = LoadCookiesCore();
            _cachedHeader = result.Header;
            _cachedFrom = result.LoadedFrom;
            _cachedAt = DateTime.UtcNow;
            return new ModDbCookieLoadResult(result.Count, result.LoadedFrom, result.HasCf);
        }
    }

    private (int Count, string? Header, string? LoadedFrom, bool HasCf) LoadCookiesCore()
    {
        foreach (var path in CandidateCookiePaths)
        {
            if (!File.Exists(path))
                continue;
            try
            {
                var json = File.ReadAllText(path);
                var data = JsonSerializer.Deserialize(json, ModDbCookieFileJsonContext.Default.ModDbCookieFile);
                var cookies = data?.Cookies;
                if (cookies is null || cookies.Count == 0)
                    continue;
                var pairs = new List<string>();
                var hasCf = false;
                foreach (var c in cookies)
                {
                    if (string.IsNullOrWhiteSpace(c.Name) || c.Value is null)
                        continue;
                    pairs.Add($"{c.Name}={c.Value}");
                    if (c.Name is "cf_clearance" or "__cf_bm")
                        hasCf = true;
                }
                if (pairs.Count == 0)
                    continue;
                return (pairs.Count, string.Join("; ", pairs), path, hasCf);
            }
            catch (Exception e)
            {
                logger.Debug(e, "Failed to read ModDB cookies from {Path}", path);
            }
        }
        return (0, null, null, false);
    }

    public string ModDb403Message(string? url = null)
    {
        var baseMsg = string.IsNullOrWhiteSpace(url)
            ? "ModDB request blocked (HTTP 403 / Cloudflare challenge)."
            : $"ModDB request blocked (HTTP 403 / Cloudflare challenge) for: {url}";
        return $"{baseMsg} {GetScHint}";
    }

    public string? FindFirefox(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var p = Environment.ExpandEnvironmentVariables(explicitPath);
            p = p.StartsWith("~", StringComparison.Ordinal)
                ? Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), p[1..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                : p;
            if (File.Exists(p)) return Path.GetFullPath(p);
            if (Directory.Exists(p))
            {
                var cand = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                    ? Path.Join(p, "Contents", "MacOS", "firefox")
                    : Path.Join(p, "firefox");
                if (File.Exists(cand)) return Path.GetFullPath(cand);
                cand = Path.Join(p, "firefox.exe");
                if (File.Exists(cand)) return Path.GetFullPath(cand);
            }
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            foreach (var env in new[] { "ProgramFiles", "ProgramFiles(x86)", "LocalAppData" })
            {
                var baseDir = Environment.GetEnvironmentVariable(env);
                if (string.IsNullOrWhiteSpace(baseDir)) continue;
                var cand = Path.Join(baseDir, "Mozilla Firefox", "firefox.exe");
                if (File.Exists(cand)) return cand;
            }
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            var cand = "/Applications/Firefox.app/Contents/MacOS/firefox";
            if (File.Exists(cand)) return cand;
        }
        else
        {
            foreach (var name in new[] { "firefox", "firefox-esr" })
            {
                var w = Which(name);
                if (w is not null) return w;
            }
            // Common local install locations
            foreach (var cand in new[] { Path.Join(Environment.CurrentDirectory, "firefox", "firefox"), Path.Join(AppContext.BaseDirectory, "firefox", "firefox") })
                if (File.Exists(cand) && IsExecutable(cand)) return Path.GetFullPath(cand);
        }
        return null;
    }

    private static bool IsExecutable(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return true;
        try
        {
            return File.GetUnixFileMode(path).HasFlag(UnixFileMode.UserExecute)
                || File.GetUnixFileMode(path).HasFlag(UnixFileMode.GroupExecute)
                || File.GetUnixFileMode(path).HasFlag(UnixFileMode.OtherExecute);
        }
        catch { return false; }
    }

    private static string? Which(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path)) return null;
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var cand = Path.Join(dir, name);
            if (File.Exists(cand)) return cand;
        }
        return null;
    }

    private string FirefoxProfilePath
    {
        get
        {
            var p = Path.Join(AppDataDir, "firefox-profile-moddb");
            Directory.CreateDirectory(p);
            return p;
        }
    }

    public int CaptureWithFirefox(string firefoxPath, string url = "https://www.moddb.com/")
    {
        var profile = FirefoxProfilePath;
        var userJs = Path.Join(profile, "user.js");
        if (!File.Exists(userJs))
        {
            File.WriteAllText(userJs,
                """
                user_pref("browser.shell.checkDefaultBrowser", false);
                user_pref("browser.startup.homepage_override.mstone", "ignore");
                user_pref("datareporting.policy.dataSubmissionEnabled", false);
                user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
                """);
        }

        var psi = new ProcessStartInfo
        {
            FileName = firefoxPath,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-profile");
        psi.ArgumentList.Add(profile);
        psi.ArgumentList.Add("-no-remote");
        psi.ArgumentList.Add("-new-instance");
        psi.ArgumentList.Add(url);

        logger.Information("Launching Firefox: {Firefox} -profile {Profile} {Url}", firefoxPath, profile, url);
        Console.WriteLine("[+] Complete any Cloudflare/ModDB challenge in the browser, then CLOSE Firefox.");
        Console.WriteLine($"[+] Cookies will be saved to: {CookiesPath}");
        try
        {
            using var proc = Process.Start(psi);
            proc?.WaitForExit();
        }
        catch (Exception e)
        {
            throw new InvalidOperationException($"Failed to launch Firefox at '{firefoxPath}': {e.Message}", e);
        }

        var cookies = ReadFirefoxCookies(profile);
        if (cookies.Count == 0)
        {
            Console.Error.WriteLine("[-] No ModDB cookies found in the Firefox profile.");
            Console.Error.WriteLine("    Make sure you visited moddb.com and completed any challenge before closing Firefox.");
            return 0;
        }

        Directory.CreateDirectory(AppDataDir);
        var data = new ModDbCookieFile { Cookies = cookies, Source = "firefox", Profile = profile };
        var json = JsonSerializer.Serialize(data, ModDbCookieFileJsonContext.Default.ModDbCookieFile);
        File.WriteAllText(CookiesPath, json, new UTF8Encoding(false));
        TryRestrictPermissions(CookiesPath);

        lock (_lock) { _cachedAt = default; _cachedHeader = null; }

        var hasCf = cookies.Any(c => c.Name is "cf_clearance" or "__cf_bm");
        Console.WriteLine($"[+] Saved {cookies.Count} ModDB cookie(s) to {CookiesPath}");
        if (!hasCf)
            Console.WriteLine("[*] Note: cf_clearance cookie not detected; 403s may persist if Cloudflare protection is active.");
        return cookies.Count;
    }

    private static void TryRestrictPermissions(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch { }
    }

    private static List<ModDbCookieEntry> ReadFirefoxCookies(string profile)
    {
        var db = Path.Join(profile, "cookies.sqlite");
        if (!File.Exists(db))
            return [];

        var td = Directory.CreateTempSubdirectory("stalker-gamma-moddb-cookies-");
        try
        {
            var tmp = Path.Join(td.FullName, "cookies.sqlite");
            File.Copy(db, tmp, true);
            foreach (var suffix in new[] { "-wal", "-shm" })
            {
                var side = db + suffix;
                if (File.Exists(side))
                    File.Copy(side, tmp + suffix, true);
            }

            var cookies = new List<ModDbCookieEntry>();
            using var con = new SqliteConnection($"Data Source={tmp};Mode=ReadOnly;Pooling=False");
            con.Open();
            using var cmd = con.CreateCommand();
            cmd.CommandText = "SELECT host, name, value, path FROM moz_cookies WHERE host LIKE '%moddb.com%'";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                cookies.Add(new ModDbCookieEntry(
                    reader.IsDBNull(0) ? null : reader.GetString(0),
                    reader.IsDBNull(1) ? null : reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.IsDBNull(3) ? "/" : reader.GetString(3)
                ));
            }
            return cookies;
        }
        finally
        {
            try { td.Delete(true); } catch { }
        }
    }
}
