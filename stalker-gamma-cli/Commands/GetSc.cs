using ConsoleAppFramework;
using Serilog;
using Stalker.Gamma.Services;

namespace stalker_gamma_cli.Commands;

[RegisterCommands("get-sc")]
public class GetSc(ILogger logger, IModDbSessionService modDbSessionService)
{
    /// <summary>
    /// Capture ModDB session cookies using Firefox (helps bypass Cloudflare 403/download issues). Also reads existing gamma-launcher cookies automatically.
    /// </summary>
    /// <param name="firefox">Path to Firefox binary or directory containing it (default: auto-detect)</param>
    /// <param name="url">URL to open (default: https://www.moddb.com/)</param>
    /// <param name="showPath">Print the cookies file path and exit</param>
    /// <param name="status">Show detected cookie files/status and exit</param>
    public int Run(
        string? firefox = null,
        string url = "https://www.moddb.com/",
        bool showPath = false,
        bool status = false
    )
    {
        if (showPath)
        {
            Console.WriteLine(modDbSessionService.CookiesPath);
            return 0;
        }

        if (status)
        {
            Console.WriteLine("ModDB cookie candidates (first valid file is used):");
            foreach (var p in modDbSessionService.CandidateCookiePaths)
                Console.WriteLine($"  {(File.Exists(p) ? "[ok]" : "[--]")} {p}");
            var loaded = modDbSessionService.LoadCookies();
            if (loaded.Count > 0)
                Console.WriteLine($"Loaded {loaded.Count} cookie(s) from {loaded.LoadedFrom}" + (loaded.HasCfClearance ? " (cf_clearance present)" : " (cf_clearance not detected)"));
            else
                Console.WriteLine("No ModDB cookies loaded.");
            return 0;
        }

        var ff = modDbSessionService.FindFirefox(firefox);
        if (ff is null)
        {
            Console.Error.WriteLine("[-] Firefox not found.");
            Console.Error.WriteLine("    Provide --firefox /path/to/firefox (or a directory containing it), install Firefox, or place it at ./firefox/firefox.");
            return 1;
        }

        try
        {
            var n = modDbSessionService.CaptureWithFirefox(ff, url);
            if (n <= 0)
            {
                Console.Error.WriteLine("[-] No cookies captured. ModDB downloads may still fail with 403.");
                return 1;
            }
            Console.WriteLine("[+] Done. Retry your ModDB download command (e.g. anomaly install, full-install).");
            return 0;
        }
        catch (Exception e)
        {
            logger.Error(e, "get-sc failed: {Message}", e.Message);
            Console.Error.WriteLine($"[-] {e.Message}");
            return 1;
        }
    }
}
