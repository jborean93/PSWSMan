using System;
using System.Text.Json;
using System.Threading;

namespace PSWSMan.Authentication.Tests;

/// <summary>
/// The Kerberos realm build.ps1 provides for the run through an Obol KDC, see Invoke-WithTestKdc in
/// tools/common.ps1. The providers find the KDC through the krb5.conf KRB5_CONFIG points to, or the realm's registry
/// key on Windows, and a GSSAPI acceptor takes the service keys from the keytab KRB5_KTNAME points to.
/// </summary>
/// <param name="Realm">The realm name.</param>
/// <param name="Username">The user that authenticates to the service, as user@REALM.</param>
/// <param name="Password">The password of <paramref name="Username"/>.</param>
/// <param name="Service">The service of the acceptor's SPN.</param>
/// <param name="Hostname">The host of the acceptor's SPN.</param>
/// <param name="AcceptorUsername">
/// The account the SPN is an alias of, as account@REALM. SSPI does not read KRB5_KTNAME, the acceptor on Windows logs
/// on with it instead.
/// </param>
/// <param name="AcceptorPassword">The password of <paramref name="AcceptorUsername"/>.</param>
internal sealed record KerberosRealm(string Realm, string Username, string Password, string Service, string Hostname,
    string AcceptorUsername, string AcceptorPassword)
{
    /// <summary>The environment variable build.ps1 sets to the JSON form of this record.</summary>
    public const string EnvironmentVariable = "PSWSMAN_TEST_KERBEROS";

    private static readonly JsonSerializerOptions s_jsonOptions = new() { PropertyNameCaseInsensitive = true };

    private static readonly Lazy<KerberosRealm?> s_current = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The configured realm, or null when the run has none.</summary>
    public static KerberosRealm? Current => s_current.Value;

    /// <summary>The user part of <see cref="Username"/>.</summary>
    public string User => Username[..Username.IndexOf('@')];

    /// <summary>Returns the configured realm or skips the current test when the run has none.</summary>
    public static KerberosRealm Require()
    {
        KerberosRealm? realm = Current;
        if (realm is null)
        {
            Skip.Test($"No Kerberos realm is available, set {EnvironmentVariable} or run build.ps1 -Task Test");
        }

        return realm!;
    }

    private static KerberosRealm? Load()
    {
        string? json = Environment.GetEnvironmentVariable(EnvironmentVariable);
        return string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<KerberosRealm>(json, s_jsonOptions);
    }
}
