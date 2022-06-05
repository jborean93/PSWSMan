using System;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;

namespace PSWSMan;

internal class BasicAuthProvider : AuthenticationProvider
{
    private readonly string _authValue;
    private bool _complete;

    public override bool Complete => _complete;

    public BasicAuthProvider(string? username, string? password)
    {
        _authValue = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
    }

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        if (Complete)
        {
            return false;
        }

        request.Headers.Add("Authorization", _authValue);
        _complete = true;
        return true;
    }
}
