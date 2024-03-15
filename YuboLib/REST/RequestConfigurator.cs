using SnapchatLib;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using YuboLib.Exceptions;
using YuboLib.Extras;

namespace YuboLib.REST;

internal struct RequestConfiguration
{
    public string Endpoint;
    public HttpMethod HttpMethod;
    public bool IsMulti;
}

internal struct EndpointInfo
{
    public string BaseEndpoint;
    public string Url;
    public string SignUrlOverride = null;

    public EndpointInfo()
    {
        BaseEndpoint = RequestConfigurator.ApiBaseEndpoint;
        Url = "";
    }
}

internal interface IRequestConfigurator
{
    HttpRequestMessage Configure(EndpointInfo endpointInfo, HttpContent content, HttpMethod httpMethod, YuboClient client, IYuboHttpClient httpClient, bool isMulti = false);
    Task<HttpRequestMessage> Configure(EndpointInfo endpointInfo, Dictionary<string, string> parameters, HttpMethod httpMethod, YuboClient client, IYuboHttpClient httpClient, bool isMulti = false);
}

internal class RequestConfigurator : IRequestConfigurator
{
    internal static string ApiBaseEndpoint => "https://mobile.yellw.co";
    internal static string AcceptEncodingHeaderName => "Accept-Encoding";
    internal static string AcceptHeaderName => "Accept";
    internal static string AcceptLanguageHeaderName => "Accept-Language";
    internal static string AcceptLocaleHeaderName => "Accept-Locale";
    internal static string AcceptLanguageValue => "en";
    internal static string AcceptLocaleValue => "en_US";
    internal static string ApplicationJsonValue => "application/json";


    private readonly IUtilities m_Utilities;
    private readonly IClientLogger m_Logger;

    public RequestConfigurator(IClientLogger logger, IUtilities utilities)
    {
        m_Logger = logger;
        m_Utilities = utilities;
    }

    public HttpRequestMessage Configure(EndpointInfo endpointInfo, HttpContent content, HttpMethod httpMethod, YuboClient client, IYuboHttpClient httpClient, bool isMulti = false)
    {
        var config = CreateConfig(endpointInfo, httpMethod, client, isMulti);
        return GenerateRequest(httpClient, config, endpointInfo, content);
    }

    public async Task<HttpRequestMessage> Configure(EndpointInfo endpointInfo, Dictionary<string, string> parameters, HttpMethod httpMethod, YuboClient client, IYuboHttpClient httpClient, bool isMulti = false)
    {
        var config = CreateConfig(endpointInfo, httpMethod, client, isMulti);
        return await GenerateRequest(httpClient, config, endpointInfo, parameters, isMulti);
    }

    private RequestConfiguration CreateConfig(EndpointInfo endpointInfo, HttpMethod httpMethod, YuboClient client, bool isMulti = false)
    {
        var config = new RequestConfiguration
        {
            Endpoint = endpointInfo.Url,
            HttpMethod = httpMethod,
            IsMulti = isMulti,
        };

        return config;
    }

    private HttpRequestMessage CreateRequest(IYuboHttpClient client, RequestConfiguration configuration, EndpointInfo endpointInfo)
    {
        var baseEndpoint = endpointInfo.BaseEndpoint;
        var url = baseEndpoint + configuration.Endpoint;
        var request = new HttpRequestMessage(configuration.HttpMethod, url);
        request.Version = configuration.HttpMethod == HttpMethod.Put ? HttpVersion.Version11 : HttpVersion.Version20;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
        return request;
    }

    private HttpRequestMessage GenerateRequest(IYuboHttpClient client, RequestConfiguration configuration, EndpointInfo endpointInfo, HttpContent content)
    {
        var request = CreateRequest(client, configuration, endpointInfo);

        request.Content = content;
        return request;
    }

    private async Task<HttpRequestMessage> GenerateRequest(IYuboHttpClient client, RequestConfiguration configuration, EndpointInfo endpointInfo, Dictionary<string, string> parameters, bool ismulti)
    {
        var request = CreateRequest(client, configuration, endpointInfo);
        var signResult = m_Utilities.JsonDeserializeObject<SignJson>(await client.Sign.SignRequest());;

        m_Logger.Debug("Trying to add sign headers to request");
        request.Headers.UserAgent.Clear();
        if (signResult == null)
            throw new SignerException("Could not deserialize SignRequest response");


        request.Headers.TryAddWithoutValidation("x-brand-encoded", signResult.headers.XBrandEncoded);
        request.Headers.TryAddWithoutValidation("x-device-model-encoded", signResult.headers.XDeviceModelEncoded);
        request.Headers.TryAddWithoutValidation("x-carrier-encoded", signResult.headers.XCarrierEncoded);
        request.Headers.TryAddWithoutValidation("x-android-version", signResult.headers.XAndroidVersion);
        request.Headers.TryAddWithoutValidation("x-os", signResult.headers.XOS);
        request.Headers.TryAddWithoutValidation("x-is-rooted", signResult.headers.XIsRooted);
        request.Headers.TryAddWithoutValidation("x-is-emulator", signResult.headers.XIsEmulator);
        request.Headers.TryAddWithoutValidation("accept-language", signResult.headers.AcceptLanguage);
        request.Headers.TryAddWithoutValidation("user-agent", signResult.headers.UserAgent);
        request.Headers.TryAddWithoutValidation("x-errors", signResult.headers.XErrors);
        request.Headers.TryAddWithoutValidation("x-yellow-token", signResult.headers.XYellowToken);
        parameters.Add("nonce", signResult.request_body.nonce);
        parameters.Add("signature", signResult.request_body.signature);
        if (ismulti)
        {
            var content = new MultipartFormDataContent();
            foreach (var parameter in parameters)
            {
                Console.WriteLine(parameter.Key);
                content.Add(new StringContent(parameter.Value), parameter.Key);
            }
            request.Content = content;
        }
        else
        {
            request.Content = new StringContent(m_Utilities.JsonSerializeObject(parameters), Encoding.UTF8, "application/json");
        }
        
        return request;
    }
}