
using System.Text.Json.Serialization;

public class Headers
{
    [JsonPropertyName("x-brand-encoded")]
    public string XBrandEncoded { get; set; }

    [JsonPropertyName("x-device-model-encoded")]
    public string XDeviceModelEncoded { get; set; }

    [JsonPropertyName("x-carrier-encoded")]
    public string XCarrierEncoded { get; set; }

    [JsonPropertyName("x-android-version")]
    public string XAndroidVersion { get; set; }

    [JsonPropertyName("x-os")]
    public string XOS { get; set; }

    [JsonPropertyName("x-is-rooted")]
    public string XIsRooted { get; set; }

    [JsonPropertyName("x-is-emulator")]
    public string XIsEmulator { get; set; }

    [JsonPropertyName("accept-language")]
    public string AcceptLanguage { get; set; }

    [JsonPropertyName("user-agent")]
    public string UserAgent { get; set; }

    [JsonPropertyName("x-errors")]
    public string XErrors { get; set; }

    [JsonPropertyName("x-yellow-token")]
    public string XYellowToken { get; set; }
}

public class RequestBody
{
    public string nonce { get; set; }
    public string signature { get; set; }
}

public class SignJson
{
    public Headers headers { get; set; }
    public RequestBody request_body { get; set; }
}

public class Device
{
    public string ro_product_brand { get; set; }
    public string ro_product_model { get; set; }
    public string ro_build_version_release { get; set; }
    public string ro_build_id { get; set; }
    public string android_id { get; set; }
}

public class Request
{
    public long timestamp { get; set; }
    public string username { get; set; }
}

public class SerializeSign
{
    public Request request { get; set; }
    public Device device { get; set; }
}

