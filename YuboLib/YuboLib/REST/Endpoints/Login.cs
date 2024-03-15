using System.Collections.Generic;
using System.Threading.Tasks;
using YuboLib.Extras;
using YuboLib.REST;
using YuboLib;
using static YuboLib.Models.LoginModel;

namespace SnapchatLib.REST.Endpoints;

public interface ILoginEndpoint
{
    Task<LoginResponse> Login(string password);
}

internal class LoginEndpoint : EndpointAccessor, ILoginEndpoint
{
    internal static readonly EndpointInfo _LoginEndpoint = new()
    {
        Url = "/login",
        BaseEndpoint = RequestConfigurator.ApiBaseEndpoint,
    };

    public LoginEndpoint(YuboClient client, IYuboHttpClient httpClient, YuboLockedConfig config, IClientLogger logger, IUtilities utilities, IRequestConfigurator configurator) : base(client, httpClient, config, logger, utilities, configurator)
    {
    }

    public async Task<LoginResponse> Login(string password)
    {
        var parameters = new Dictionary<string, string>
        {
            {"username", Config.Username },
            {"type", "username" },
            {"password", password },
        };
        var response = await Send(_LoginEndpoint, parameters);
        return m_Utilities.JsonDeserializeObject<LoginResponse>(await response.Content.ReadAsStringAsync());
    }
}