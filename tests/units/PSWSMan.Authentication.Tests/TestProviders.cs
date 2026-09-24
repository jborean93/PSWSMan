using PSWSMan.Authentication.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace PSWSMan.Authentication.Tests;

/// <summary>A loaded native security library the tests build credentials from.</summary>
internal sealed class AuthProvider
{
    private readonly Func<string?, string?, NegotiateMethod, NegotiateOptions, WSManCredential> _factory;

    public string Name { get; }

    private AuthProvider(string name,
        Func<string?, string?, NegotiateMethod, NegotiateOptions, WSManCredential> factory)
    {
        Name = name;
        _factory = factory;
    }

    public static AuthProvider FromGssapi(string name, GssapiProvider provider)
        => new(name, (user, pass, method, options) => new GssapiCredential(provider, user, pass, method, options));

    public static AuthProvider FromSspi(string name, SspiProvider provider)
        => new(name, (user, pass, method, options) => new SspiCredential(provider, user, pass, method, options));

    public WSManCredential CreateCredential(string? username, string? password, NegotiateMethod method,
        NegotiateOptions? options = null)
        => _factory(username, password, method, options ?? new NegotiateOptions());

    public override string ToString() => Name;
}

/// <summary>
/// The security libraries available on this host, loaded the same way the module does on import but without
/// System.Management.Automation involved. A provider that cannot be loaded is reported as unavailable so the tests
/// depending on it skip rather than fail.
/// </summary>
internal static class TestProviders
{
    /// <summary>The system GSSAPI library, MIT krb5 or Heimdal on Linux and GSS.framework on macOS.</summary>
    public const string Gssapi = "Gssapi";

    /// <summary>The Windows SSPI in Secur32.dll.</summary>
    public const string Sspi = "Sspi";

    /// <summary>The Devolutions sspi-rs library bundled with the module.</summary>
    public const string Devolutions = "Devolutions";

    private static readonly Dictionary<string, Lazy<AuthProvider?>> s_providers = new()
    {
        [Gssapi] = new(LoadGssapi, LazyThreadSafetyMode.ExecutionAndPublication),
        [Sspi] = new(LoadSspi, LazyThreadSafetyMode.ExecutionAndPublication),
        [Devolutions] = new(LoadDevolutions, LazyThreadSafetyMode.ExecutionAndPublication),
    };

    /// <summary>Gets the provider or skips the current test when it is not available on this host.</summary>
    public static AuthProvider Require(string name)
    {
        AuthProvider? provider = s_providers[name].Value;
        if (provider is null)
        {
            Skip.Test($"The {name} provider is not available on this host");
        }

        return provider!;
    }

    private static AuthProvider? LoadGssapi()
    {
        return ProviderLibs.TryGetSystemGssapi(out GssapiProvider? provider, out _)
            ? AuthProvider.FromGssapi(Gssapi, provider)
            : null;
    }

    private static AuthProvider? LoadSspi()
    {
        SspiProvider? provider = ProviderLibs.GetSystemSspi();
        return provider is null ? null : AuthProvider.FromSspi(Sspi, provider);
    }

    private static AuthProvider? LoadDevolutions()
    {
        // The package's runtimes folder is copied next to the test assembly by the project reference, which is a
        // different layout from the built module so the path is resolved here rather than by ProviderLibs.
        string path = Path.Combine(
            AppContext.BaseDirectory,
            "runtimes",
            $"{ProviderLibs.OsName}-{RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}",
            "native",
            $"{ProviderLibs.LibPrefix}DevolutionsSspi.{ProviderLibs.LibExt}");

        return NativeLibrary.TryLoad(path, out IntPtr lib)
            ? AuthProvider.FromSspi(Devolutions, new SspiProvider(lib))
            : null;
    }
}
