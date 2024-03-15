using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using YuboLib.Exceptions;

namespace YuboLib.Extras;

internal interface IUtilities
{
    long LongRandom(long min, long max, Random rand);
    ulong NextULong(ulong min, ulong max);
    string RandomString(int length);
    T JsonDeserializeObject<T>(string data);
    string JsonSerializeObject(object obj);
    string NewGuid();
    Guid ParseGuid(string uuid);
    long UtcTimestamp();
    int GetAge(DateTime dateOfBirth);
    long GetInstallTimeStamp();
}

internal class Utilities : IUtilities
{
    private readonly Random m_Random = new();

    public class AndroidIDGenerator
    {
        public static string GenerateAndroidID()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[8];
                rng.GetBytes(bytes);

                ulong value = BitConverter.ToUInt64(bytes, 0);
                return value.ToString("x16");
            }
        }
    }

    public long LongRandom(long min, long max, Random rand)
    {
        byte[] buf = new byte[8];
        rand.NextBytes(buf);
        long longRand = BitConverter.ToInt64(buf, 0);
        return (Math.Abs(longRand % (max - min)) + min);
    }

    public ulong NextULong(ulong min, ulong max)
    {
        // Get a random 64 bit number.

        var buf = new byte[sizeof(ulong)];
        m_Random.NextBytes(buf);
        ulong n = BitConverter.ToUInt64(buf, 0);

        // Scale to between 0 inclusive and 1 exclusive; i.e. [0,1).

        double normalised = n / (ulong.MaxValue + 1.0);

        // Determine result by scaling range and adding minimum.

        double range = (double)max - min;

        return (ulong)(normalised * range) + min;
    }

    public int GetAge(DateTime dateOfBirth)
    {
        var today = DateTime.Today;

        var a = (today.Year * 100 + today.Month) * 100 + today.Day;
        var b = (dateOfBirth.Year * 100 + dateOfBirth.Month) * 100 + dateOfBirth.Day;

        return (a - b) / 10000;
    }
    public string RandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[m_Random.Next(s.Length)]).ToArray());
    }
    public T JsonDeserializeObject<T>(string data)
    {

        var result = JsonSerializer.Deserialize<T>(data, new JsonSerializerOptions
        {
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        if (result == null) throw new DeserializationException(nameof(T));
        return result;
    }

    public string JsonSerializeObject(object obj)
    {
        try
        {
            return JsonSerializer.Serialize(obj);
        }
        catch (Exception e)
        {
            throw new SerializationException("Failed to serialize object", e);
        }
    }

    public string NewGuid()
    {
        return Guid.NewGuid().ToString();
    }

    public Guid ParseGuid(string uuid)
    {
        return Guid.Parse(uuid);
    }
    public long GetInstallTimeStamp()
    {
        long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long oneHourAgoTimestamp = currentTimestamp - (60 * 60 * 1000);
        return new Random().NextInt64(1684970549000, oneHourAgoTimestamp);
    }
    public long UtcTimestamp()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    
}