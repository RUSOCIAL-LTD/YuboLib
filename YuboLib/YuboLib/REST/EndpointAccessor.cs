using SnapchatLib;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using YuboLib.Extras;

namespace YuboLib.REST;

internal abstract class EndpointAccessor
{
    protected IYuboHttpClient HttpClient { get; }
    protected YuboLockedConfig Config { get; }
    protected YuboClient YuboClient { get; }
    protected IClientLogger m_Logger;
    protected IUtilities m_Utilities;

    private readonly IRequestConfigurator m_Configurator;

    protected EndpointAccessor() { }

    protected EndpointAccessor(YuboClient client, IYuboHttpClient httpClient, YuboLockedConfig config, IClientLogger logger, IUtilities utilities, IRequestConfigurator requestConfigurator)
    {
        HttpClient = httpClient;
        Config = config;
        YuboClient = client;
        m_Logger = logger;
        m_Utilities = utilities;
        m_Configurator = requestConfigurator;
    }

    protected virtual async Task<HttpResponseMessage> Send(EndpointInfo endpointInfo, Dictionary<string, string> parameters, bool isMulti = false)
    {
        parameters ??= new Dictionary<string, string>();

        var request = await m_Configurator.Configure(endpointInfo, parameters, HttpMethod.Post, YuboClient, HttpClient, isMulti);
        return await HttpClient.Send(endpointInfo.Url, request);
    }

    protected virtual async Task<HttpResponseMessage> Send(EndpointInfo endpointInfo, HttpContent streamContent, bool isMulti = false)
    {
        var request = m_Configurator.Configure(endpointInfo, streamContent, HttpMethod.Post, YuboClient, HttpClient, isMulti);
        return await HttpClient.Send(endpointInfo.Url, request);
    }

    protected virtual async Task<HttpResponseMessage> SendPut(EndpointInfo endpointInfo, Stream stream)
    {
        using var fileStreamContent = new StreamContent(stream);

        var request = m_Configurator.Configure(endpointInfo, fileStreamContent, HttpMethod.Put, YuboClient, HttpClient);

        m_Logger.Debug($"Calling SendPut to {endpointInfo.Url}. Request Version: {request.Version}. Request Url: {request.RequestUri}");
        return await HttpClient.SendPut(endpointInfo.Url, request, !Config.BandwithSaver);
    }
}