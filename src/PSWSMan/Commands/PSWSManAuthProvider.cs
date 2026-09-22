using System;
using System.Management.Automation;

namespace PSWSMan.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "PSWSManAuthProvider"
)]
[OutputType(typeof(AuthenticationProvider))]
public sealed class GetPSWSManAuthProvider : PSCmdlet
{
    protected override void EndProcessing()
    {
        WriteObject(GlobalState.DefaultProvider);
    }
}

[Cmdlet(
    VerbsCommon.Set, "PSWSManAuthProvider",
    SupportsShouldProcess = true
)]
public sealed class SetPSWSManAuthProvider : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    public AuthenticationProvider AuthProvider { get; set; } = AuthenticationProvider.Default;

    protected override void EndProcessing()
    {
        if (AuthProvider == AuthenticationProvider.Default)
        {
            ErrorRecord err = new(
                new ArgumentException($"AuthProvider cannot be set to {AuthProvider}, must be System or Devolutions"),
                "SetAuthProviderDefault",
                ErrorCategory.InvalidArgument,
                AuthProvider);
            WriteError(err);
            return;
        }

        if (GlobalState.DefaultProvider != AuthProvider)
        {
            if (ShouldProcess("Default PSWSMan Auth Provider", $"Set {AuthProvider}"))
            {
                GlobalState.DefaultProvider = AuthProvider;
            }
        }
    }
}
