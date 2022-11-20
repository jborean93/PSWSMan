using System;
using System.Net.Http;
using System.Text;

namespace PSWSMan;

internal class BasicAuthProvider : HttpAuthProvider
{
    private readonly string _authValue;

    public override bool Complete => false;

    public override bool AlwaysAddHeaders => true;

    /// <summary>Basic authentication provider.</summary>
    /// <param name="username">The username to authenticate as.</param>
    /// <param name="password">The password to authenticate with.</param>
    public BasicAuthProvider(string? username, string? password)
    {
        _authValue = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        request.Headers.Add("Authorization", _authValue);
        return false;
    }
}
