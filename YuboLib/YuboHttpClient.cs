using SnapchatLib.REST.Endpoints;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using YuboLib;
using YuboLib.Exceptions;
using YuboLib.Extras;
using YuboLib.REST;
using YuboLib.REST.Endpoints;

namespace YuboLib.Exceptions
{
    public class BadProxyException : Exception
    {
        public BadProxyException() : base("Bad Proxy")
        {
        }
    }

    public class ProxyTimeoutException : Exception
    {
        public ProxyTimeoutException() : base("The proxy seems to have timeout")
        {
        }
    }

    public class ProxyAuthRequiredException : Exception
    {
        public ProxyAuthRequiredException() : base("The configured proxy requires authentication")
        {
        }
    }

    public class EmailDomainBannedException : Exception
    {
        public EmailDomainBannedException() : base("Email Domain Banned")
        {
        }
    }

    public class InvalidPasswordException : Exception
    {
        public InvalidPasswordException() : base("Password Invalid")
        {
        }
    }

    public class RateLimitedException : Exception
    {
        public RateLimitedException() : base("Rate Limited. You are firing too many requests")
        {
        }
    }

    public class FailedHttpRequestException : Exception
    {
        public FailedHttpRequestException(HttpStatusCode statusCode, string info) : base($"Unhandled status code for HttpStatusCode: {statusCode}\n{info}")
        {
        }
    }
}

namespace SnapchatLib
{

    internal interface IYuboHttpClient
    {
        IExampleEndpoint Examples { get; }
        ISignEndpoint Sign { get; }
        ILoginEndpoint Login { get; }
        Task<HttpResponseMessage> Send(string url, HttpRequestMessage request, bool useProxyClient = true);
        Task<HttpResponseMessage> SendPut(string url, HttpRequestMessage request, bool useProxyClient = false);
        HttpClient webClient { get; set; }
        HttpClient m_UnproxiedHttpClient { get; }
        Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool useProxiedClient);
    }

    internal class YuboHttpClient : IYuboHttpClient
    {
        private readonly YuboClient YuboClient;
        private readonly YuboLockedConfig YuboConfig;

        public virtual HttpClient webClient { get; set; }
        public virtual HttpClient m_UnproxiedHttpClient { get; set; }

        private bool configuredClients;

        internal readonly IClientLogger m_Logger;
        public ISignEndpoint Sign { get; }
        public IExampleEndpoint Examples { get; }
        public ILoginEndpoint Login { get; }


        internal YuboHttpClient(YuboClient Client, IClientLogger logger, IUtilities utilities, IRequestConfigurator configurator)
        {
            YuboClient = Client;
            YuboConfig = Client.YuboConfig;
            m_Logger = logger;

            Examples = new ExampleEndpoint(Client, this, YuboConfig, logger, utilities, configurator);
            Sign = new SignEndpoint(Client, this, YuboConfig, logger, utilities, configurator);
            Login = new LoginEndpoint(Client, this, YuboConfig, logger, utilities, configurator);
            SetupClients();
        }

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool useProxiedClient)
        {
            EnsureClientConfigured();

            var client = useProxiedClient ? webClient : m_UnproxiedHttpClient;
            return await client.SendAsync(request);
        }

        public async Task<HttpResponseMessage> SendPut(string url, HttpRequestMessage request, bool useProxyClient = true)
        {
            EnsureClientConfigured();

            var client = useProxyClient ? webClient : m_UnproxiedHttpClient;

            m_Logger.Debug(client == webClient ? "SendPut: using Proxied client" : "SendPut: using unproxied client");
            var response = await client.SendAsync(request);
            await RaiseForResponse(url, response);
            return response;
        }

        public async Task<HttpResponseMessage> Send(string url, HttpRequestMessage request, bool useProxyClient = true)
        {
            EnsureClientConfigured();

            var client = useProxyClient ? webClient : m_UnproxiedHttpClient;
            m_Logger.Debug(client == webClient ? "Using Proxied client" : "Using unproxied client");
            var response = await client.SendAsync(request);
            await RaiseForResponse(url, response);
            return response;
        }

        // TODO: Seems unused
        public static string Base64Encode(string plainText)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
        }

        private HttpClient CreateHttpClient(bool useProxy)
        {
            var httpHandler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            };

            var client = new HttpClient(httpHandler);
            client.DefaultRequestVersion = HttpVersion.Version20;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact;
            client.Timeout = TimeSpan.FromSeconds(YuboConfig.Timeout);

            if (YuboConfig.Proxy == null || !useProxy) return client;

            // Setup proxy stuff
            httpHandler.Proxy = YuboConfig.Proxy;
            httpHandler.UseProxy = true;

            return client;
        }

        private void EnsureClientConfigured()
        {
            if (configuredClients)
            {
                return;
            }

            if (webClient == null || m_UnproxiedHttpClient == null)
            {
                return;
            }

            configuredClients = true;
        }

        private void SetupClients()
        {
            if (webClient != null && m_UnproxiedHttpClient != null)
                return;

            webClient = CreateHttpClient(true);
            m_UnproxiedHttpClient = CreateHttpClient(false);
        }

        private async Task RaiseForResponse(string endpoint, HttpResponseMessage response)
        {
            m_Logger.Debug($"Endpoint: {endpoint}");
            m_Logger.Debug($"Status Code: {response.StatusCode}");

            if (response.IsSuccessStatusCode) return;

            if (endpoint == "/login" && response.StatusCode == HttpStatusCode.Forbidden) return;

            // Custom messages for bad status codes
            switch (response.StatusCode)
            {
                case HttpStatusCode.GatewayTimeout:
                    throw new ProxyTimeoutException();
                case HttpStatusCode.InternalServerError:
                    throw new Exception(await response.Content.ReadAsStringAsync() + "[LOG] ->" + endpoint);
                case HttpStatusCode.ProxyAuthenticationRequired:
                    throw new ProxyAuthRequiredException();
                case HttpStatusCode.ServiceUnavailable:
                    throw new Exception("Snapchat seems to be down response -> ServiceUnavailable" + "[LOG] ->" + endpoint);
                case HttpStatusCode.HttpVersionNotSupported:
                    throw new Exception("HttpVersionNotSupported" + "[LOG] ->" + endpoint);
                case HttpStatusCode.TooManyRequests:
                    throw new RateLimitedException();
                default:
                    throw new FailedHttpRequestException(response.StatusCode, await response.Content.ReadAsStringAsync());
            }
        }
    }
}