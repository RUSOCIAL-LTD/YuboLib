using System;
using System.Net;
using YuboLib.Extras;
using static YuboLib.Extras.Utilities;

namespace YuboLib;
public class YuboConfig
{
    private string _ApiKey;
    public WebProxy Proxy { get; set; }
    public static bool IsBase64String(string base64)
    {
        Span<byte> buffer = new Span<byte>(new byte[base64.Length]);
        return Convert.TryFromBase64String(base64, buffer, out int bytesParsed);
    }
    public string ApiKey
    {
        get => _ApiKey;
        set
        {
            _ApiKey = value;
            if (string.IsNullOrEmpty(_ApiKey)) throw new ArgumentNullException("ApiKey Cannot be empty");
        }
    }

    public bool Debug { get; set; } = false;
    public bool ProxySigner { get; set; } = false;
    public bool BandwithSaver { get; set; } = true;
    public int Timeout { get; set; }
    public string android_id { get; set; } = AndroidIDGenerator.GenerateAndroidID();
    public string Username { get; set; }
    public string ro_product_brand { get; set; }
    public string ro_product_model { get; set; }
    public string ro_build_version_release { get; set; }
    public string ro_build_id { get; set; }

    internal readonly IUtilities Utilities;
    internal YuboConfig(IUtilities utilities)
    {
        Utilities = utilities;
    }

    public YuboConfig()
    {
        Utilities = new Utilities();
    }
}

public class YuboLockedConfig
{
    public YuboLockedConfig(YuboConfig config)
    {
        android_id = config.android_id;
        Username = config.Username;
        ApiKey = config.ApiKey;
        Proxy = config.Proxy;
        Debug = config.Debug;
        BandwithSaver = config.BandwithSaver;
        Timeout = config.Timeout;
        ProxySigner = config.ProxySigner;
        ro_build_id = config.ro_build_id;
        ro_product_brand = config.ro_product_brand;
        ro_product_model = config.ro_product_model;
        ro_build_version_release = config.ro_build_version_release;
    }
    public WebProxy Proxy { get; set; }
    public string ApiKey { get; set; }
    public string Username { get; set; }
    public string android_id { get; set; }
    public bool Debug { get; set; }
    public bool BandwithSaver { get; set; }
    public bool ProxySigner { get; set; }
    public int Timeout { get; set; }
    public string ro_product_brand { get; set; }
    public string ro_product_model { get; set; }
    public string ro_build_version_release { get; set; }
    public string ro_build_id { get; set; }
}