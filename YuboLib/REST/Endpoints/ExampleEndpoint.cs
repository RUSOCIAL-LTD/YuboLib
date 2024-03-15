using System.Collections.Generic;
using System.Threading.Tasks;
using YuboLib.Extras;
using YuboLib.REST;
using YuboLib;

namespace SnapchatLib.REST.Endpoints;

public interface IExampleEndpoint
{
    Task<string> ExampleMethod(string exampleparam);
}

internal class ExampleEndpoint : EndpointAccessor, IExampleEndpoint
{
    internal static readonly EndpointInfo Example = new()
    {
        Url = "/Example",
        BaseEndpoint = RequestConfigurator.ApiBaseEndpoint,
    };

    public ExampleEndpoint(YuboClient client, IYuboHttpClient httpClient, YuboLockedConfig config, IClientLogger logger, IUtilities utilities, IRequestConfigurator configurator) : base(client, httpClient, config, logger, utilities, configurator)
    {
    }
    public async Task<string> ExampleMethod(string exampleparam)
    {
        var parameters = new Dictionary<string, string>
        {
            {"example_key", "example_value"},
        };
        var response = await Send(Example, parameters);
        return m_Utilities.JsonDeserializeObject<string>(await response.Content.ReadAsStringAsync());
    }
}