using Stalker.Gamma.Models;
using Stalker.Gamma.Proxies;
using Stalker.Gamma.Services;

namespace Stalker.Gamma.Factories;

public class NetworkServiceFactory(
    IHttpClientFactory hcf,
    StalkerGammaServerProxy stalkerGammaServerProxy,
    StalkerGammaSettings settings,
    IModDbSessionService modDbSessionService
)
{
    public NetworkService Create() =>
        new(
            hcf,
            stalkerGammaServerProxy,
            modDbSessionService,
            useCurl: settings.StalkerGammaServerUrl is null
                || settings.StalkerGammaServerUrl.Length == 0
        );
}
