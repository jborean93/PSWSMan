using System;
using System.Net.Http;
using System.Text;

namespace PSWSMan;

internal class BasicAuthProvider : AuthenticationProvider
{
    private readonly string _authValue;
    private bool _complete;

    public override bool Complete => _complete;

    public BasicAuthProvider(string? username, string? password)
        : this("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))) { }

    public BasicAuthProvider(string authValue)
    {
        _authValue = authValue;
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            throw new Exception("Auth provider is already completed");
        }

        request.Headers.Add("Authorization", _authValue);
        _complete = true;
        return true;
    }
}
