using PSWSMan.Authentication.Native;
using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace PSWSMan.Commands;

public sealed record PSWSManAuthSettings(
    AuthenticationProvider DefaultAuthProvider,
    string GssapiLib);

[Cmdlet(
    VerbsCommon.Get, "PSWSManAuth"
)]
[OutputType(typeof(PSWSManAuthSettings))]
public sealed class GetPSWSManAuth : PSCmdlet
{
    protected override void EndProcessing()
    {
        ModuleSettings moduleSettings = ModuleSettings.GetFromTLS();
        WriteObject(new PSWSManAuthSettings(moduleSettings.DefaultAuthProvider, moduleSettings.GssapiLib));
    }
}

[Cmdlet(
    VerbsCommon.Set, "PSWSManAuth",
    SupportsShouldProcess = true
)]
public sealed class SetPSWSManAuth : PSCmdlet
{
    [Parameter()]
    public AuthenticationProvider? AuthProvider { get; set; }

    [Parameter()]
    [ArgumentCompletions(ModuleSettings.DefaultGssapiLib)]
    public string? GssapiLib { get; set; }

    protected override void EndProcessing()
    {
        ModuleSettings settings = ModuleSettings.GetFromTLS();

        if (AuthProvider == AuthenticationProvider.Default)
        {
            WriteError(new ErrorRecord(
                new ArgumentException($"AuthProvider cannot be set to {AuthProvider}, must be System or Devolutions"),
                "SetAuthProviderDefault",
                ErrorCategory.InvalidArgument,
                AuthProvider));
            return;
        }

        // The sentinel is matched case insensitively so 'default' is stored
        // as the canonical 'Default' the session code compares against.
        string? newGssapiLib = null;
        if (!string.IsNullOrWhiteSpace(GssapiLib))
        {
            newGssapiLib = string.Equals(GssapiLib, ModuleSettings.DefaultGssapiLib, StringComparison.OrdinalIgnoreCase)
                ? ModuleSettings.DefaultGssapiLib
                : GssapiLib;
        }

        // Every requested value is checked before anything is changed so a
        // failure leaves the settings as they were. The libraries are cached
        // by ProviderLibs so a successful check is not repeated at connection
        // time.
        bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        if (newGssapiLib is not null)
        {
            if (isWindows)
            {
                // Windows always authenticates through SSPI so a GSSAPI
                // library would never be used, reject it rather than store a
                // setting that silently does nothing.
                WriteError(new ErrorRecord(
                    new PlatformNotSupportedException("GssapiLib cannot be set on Windows, SSPI is always used"),
                    "GssapiLibNotSupported",
                    ErrorCategory.InvalidArgument,
                    newGssapiLib));
                return;
            }

            if (!TryValidateGssapiLib(newGssapiLib))
            {
                return;
            }
        }

        if (AuthProvider == AuthenticationProvider.Devolutions &&
            !ProviderLibs.TryGetDevolutionsSspi(out _, out Exception? devolutionsError))
        {
            WriteError(new ErrorRecord(
                devolutionsError,
                "AuthProviderNotAvailable",
                ErrorCategory.ObjectNotFound,
                AuthProvider));
            return;
        }

        if (AuthProvider == AuthenticationProvider.System && !isWindows)
        {
            // The System provider on non-Windows is whatever GSSAPI library
            // will be in effect once this call completes.
            string effectiveLib = newGssapiLib ?? settings.GssapiLib;
            if (!TryValidateGssapiLib(effectiveLib))
            {
                return;
            }
        }

        if (AuthProvider.HasValue && settings.DefaultAuthProvider != AuthProvider)
        {
            if (ShouldProcess("Default PSWSMan Auth Provider", $"Set {AuthProvider}"))
            {
                settings.DefaultAuthProvider = AuthProvider.Value;
            }
        }

        if (newGssapiLib is not null && settings.GssapiLib != newGssapiLib)
        {
            if (ShouldProcess("GSSAPI Library", $"Set {newGssapiLib}"))
            {
                settings.GssapiLib = newGssapiLib;
            }
        }
    }

    /// <summary>Checks the GSSAPI library a setting refers to can be loaded, writing an error when it cannot.</summary>
    private bool TryValidateGssapiLib(string gssapiLib)
    {
        bool loaded;
        Exception? error;
        if (gssapiLib == ModuleSettings.DefaultGssapiLib)
        {
            loaded = ProviderLibs.TryGetSystemGssapi(out _, out error);
        }
        else
        {
            loaded = ProviderLibs.TryGetGssapi(gssapiLib, out _, out error);
        }

        if (loaded)
        {
            return true;
        }

        // The error already names the library and the loader's reason and
        // keeps the loader exception as its inner exception.
        WriteError(new ErrorRecord(
            error,
            "GssapiLibNotAvailable",
            ErrorCategory.ObjectNotFound,
            gssapiLib));
        return false;
    }
}
