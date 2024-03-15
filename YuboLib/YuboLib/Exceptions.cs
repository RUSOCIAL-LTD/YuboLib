using System;

namespace YuboLib.Exceptions;
public class AndroidIDNotSet: Exception
{
    public AndroidIDNotSet() : base("Android ID needed")
    {
    }
}

public abstract class ContactDerpyException : Exception
{
    protected ContactDerpyException(string error, Exception exception = null) : base($"${error}. Contact DerpyCat to report a bug.{exception?.Message}", exception)
    {
    }
}

public class SignerException : ContactDerpyException
{
    public SignerException(string error): base(error)
    {
    }
}

public class AuthTokenNotSetException : Exception
{
    public AuthTokenNotSetException(): base("AuthToken is not defined. Use SnapchatLib.Login first")
    {
    }
}

public class FailedToInitClient : Exception
{
    public FailedToInitClient() : base("Init Client Failed Retry")
    {
    }
}

public class DeserializationException : ContactDerpyException
{
    public DeserializationException(string typeName) : base($"Unable to deserialize data into type \"{typeName}\"")
    {
    }
}

public class SerializationException : ContactDerpyException
{
    public SerializationException(string typeName, Exception innerException) : base($"Unable to deserialize data into type \"{typeName}\"", innerException)
    {
    }
}

public class FailedToPredictGenderException : ContactDerpyException
{
    public FailedToPredictGenderException() : base($"Failed to predict gender")
    {
    }
}

public class EmptyIEnumerableException : ContactDerpyException
{
    public EmptyIEnumerableException() : base($"The code was expecting elements in side a collection but it was empty")
    {
    }
}

public class DeadProxyException : Exception
{
    public DeadProxyException() : base("Dead Proxy")
    {
    }
}
