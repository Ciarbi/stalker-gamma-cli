using LibCurlImpersonate;
using Stalker.Gamma.ModDb.Services;
using Stalker.Gamma.Proxies;
using Stalker.Gamma.Utilities;

namespace Stalker.Gamma.Services;

public class NetworkService(
    IHttpClientFactory hcf,
    StalkerGammaServerProxy stalkerGammaServerProxy,
    IModDbSessionService modDbSessionService,
    bool useCurl
)
{
    public async Task<Dictionary<string, string>> GetHeadersAsync(
        string url,
        CancellationToken cancellationToken = default
    ) =>
        useCurl
            ? await Task.Run(
                () =>
                    CurlHttp.GetHeaders(
                        url,
                        http3: true,
                        ct: cancellationToken,
                        cookieHeader: modDbSessionService.GetCookieHeader(url)
                    ),
                cancellationToken
            )
            : (await stalkerGammaServerProxy.GetHeadersAsync(url, cancellationToken)).ToDictionary(
                x => x.Key,
                x => x.Value.ToString()!
            );

    public async Task DownloadFileAsync(
        string url,
        string pathToDownloads,
        string fileName,
        Action<DownloadProgress>? onProgress = null,
        CancellationToken cancellationToken = default
    )
    {
        var destinationPath = Path.Join(pathToDownloads, fileName);
        if (useCurl && modDbSessionService.IsModDbUrl(url))
        {
            await Task.Run(
                () =>
                    CurlHttp.DownloadToFile(
                        url,
                        destinationPath,
                        onProgress: p =>
                        {
                            if (p is >= 0 and <= 1)
                                onProgress?.Invoke(new DownloadProgress((long)(p * 1_000_000), 1_000_000));
                        },
                        http3: true,
                        ct: cancellationToken,
                        cookieHeader: modDbSessionService.GetCookieHeader(url)
                    ),
                cancellationToken
            );
            var size = File.Exists(destinationPath) ? new FileInfo(destinationPath).Length : 0;
            onProgress?.Invoke(new DownloadProgress(size, size));
            return;
        }

        await DownloadFileFast.DownloadAsync(
            _dlAddonHc,
            url,
            destinationPath,
            onProgress,
            cancellationToken
        );
    }

    public async Task<string> GetStringAsync(
        string url,
        CancellationToken cancellationToken = default
    ) =>
        CloudflareChallenge.ThrowIfChallenged(
            useCurl
                ? await Task.Run(
                    () =>
                        CurlHttp.Fetch(
                            url,
                            http3: true,
                            ct: cancellationToken,
                            cookieHeader: modDbSessionService.GetCookieHeader(url)
                        ),
                    cancellationToken
                )
                : await stalkerGammaServerProxy.GetStringAsync(url, cancellationToken),
            url
        );

    /// <summary>
    /// Whether curl service found curl-impersonate-win.exe and can execute.
    /// </summary>
    public bool Ready => true;

    private readonly HttpClient _dlAddonHc = hcf.CreateClient("dlAddon");
}

public class ModDbBotDetectedException(string msg) : Exception(msg);
