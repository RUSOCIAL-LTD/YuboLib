using SnapchatLib;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using YuboLib.Exceptions;
using YuboLib.Extras;

namespace YuboLib.REST.Endpoints;
internal interface ISignEndpoint
{
    Task<string> SignRequest();
}

internal class SignEndpoint : EndpointAccessor, ISignEndpoint
{
    internal const string DefaultSignUrl = "https://sign.rusocial.io/yubo/sign";

    public SignEndpoint(YuboClient client, IYuboHttpClient httpClient, YuboLockedConfig config, IClientLogger logger, IUtilities utilities, IRequestConfigurator configurator) : base(client, httpClient, config, logger, utilities, configurator)
    {
    }

    internal static HttpResponseMessage response { get; set; }
    private void RaiseForInvalidValues()
    {
        if (string.IsNullOrEmpty(Config.ApiKey))
            new Exception("ApiKey is required");

        if (string.IsNullOrEmpty(Config.Username))
            new Exception("Username is required");

        if (string.IsNullOrEmpty(Config.android_id) || string.IsNullOrEmpty(Config.ro_build_id) || string.IsNullOrEmpty(Config.ro_build_version_release) || string.IsNullOrEmpty(Config.ro_product_brand) || string.IsNullOrEmpty(Config.ro_product_model))
            throw new Exception("Phone Stuff is required");

        if (string.IsNullOrWhiteSpace(Config.android_id))
        {
            throw new AndroidIDNotSet();
        }
    }
    public async Task<string> SignRequest()
    {
        RaiseForInvalidValues();

        var request = new HttpRequestMessage(HttpMethod.Post, DefaultSignUrl);
        request.Version = HttpVersion.Version20;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
        request.Headers.TryAddWithoutValidation("x-license", Config.ApiKey);
        request.Headers.TryAddWithoutValidation("User-Agent", "Yubo/Public");
        var sign_json = new SerializeSign {
            device = new Device
            {
                android_id = Config.android_id,
                ro_build_id = Config.ro_build_id,
                ro_build_version_release = Config.ro_build_version_release,
                ro_product_brand = Config.ro_product_brand,
                ro_product_model = Config.ro_product_model,
            },
            yubo_request_info = new YuboRequestInfo
            {
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                username = Config.Username
            },
            yubo_version = Config.yubo_version
        };
        request.Content = new StringContent(m_Utilities.JsonSerializeObject(sign_json), Encoding.UTF8, "application/json");

        if (Config.ProxySigner)
        {
            response = await HttpClient.Send(DefaultSignUrl, request, true);
        }
        else
        {
            response = await HttpClient.Send(DefaultSignUrl, request, false);
        }

        var responseData = await response.Content.ReadAsStringAsync();

        if (response.StatusCode != HttpStatusCode.OK)
            throw new SignerException(responseData);

        if (responseData != null)
            return responseData;

        throw new SignerException(responseData);
    }
}