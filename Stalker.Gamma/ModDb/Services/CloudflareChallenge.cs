namespace Stalker.Gamma.ModDb.Services;

public static class CloudflareChallenge
{
    public static string ThrowIfChallenged(string html, string url) =>
        html.Contains("Just a moment...")
            ? throw new CloudflareChallengeException(
                $"""
                Cloudflare challenge detected when retrieving: {url}
                Run `stalker-gamma get-sc` to capture ModDB session cookies with a real browser (Firefox), or use a VPN/--stalker-gamma-server-url. Existing gamma-launcher cookies at ~/.config/gamma-launcher/moddb_cookies.json are also read automatically.
                """
            )
            : html;
}

public class CloudflareChallengeException(string msg) : Exception(msg);
