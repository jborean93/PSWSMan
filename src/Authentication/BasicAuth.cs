using System;
using System.Text;

namespace PSWSMan.Authentication;

public sealed class BasicCredential : WSManCredential
{
    private readonly byte[] _authValue;

    public BasicCredential(string? username, string? password)
    {
        _authValue = Encoding.UTF8.GetBytes($"{username}:{password}");
    }

    protected internal override AuthenticationContext CreateAuthContext()
        => new BasicAuthContext(_authValue);
}

public sealed class BasicAuthContext : AuthenticationContext
{
    private readonly byte[] _authToken;

    public override bool Complete => false;

    public override string HttpAuthLabel => "Basic";

    internal BasicAuthContext(byte[] authToken)
    {
        _authToken = authToken;
    }

    protected internal override byte[]? Step(Span<byte> inToken, NegotiateOptions options, ChannelBindings? bindings)
        => _authToken;
}
