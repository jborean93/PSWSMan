#if NET8_0_OR_GREATER
using RemoteForge;
#endif
using System;
using System.Management.Automation;

namespace PSWSMan.Module.Commands;

[Cmdlet(
    VerbsLifecycle.Register, "WinRSForge"
)]
public sealed class RegisterWinRSForge : PSCmdlet
{
    [Parameter()]
    public SwitchParameter Force { get; set; }

    protected override void EndProcessing()
    {
#if NET8_0_OR_GREATER
        RemoteForgeRegistration.Register(
            WinRSForge.ForgeName,
            (i) => new RemoteForgeConnectionInfo(WinRSForge.Create(i)),
            description: WinRSForge.ForgeDescription);
#else
        ErrorRecord err = new(
            new Exception("Forge registration only works on PowerShell 7.4 or newer"),
            "ForgeRegistrationFailure",
            ErrorCategory.NotSpecified,
            null);
        ThrowTerminatingError(err);
#endif
    }
}
