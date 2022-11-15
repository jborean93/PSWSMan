using HarmonyLib;
using System.Management.Automation;

internal static class PSWSManStatus
{
    public const string HarmonyId = "PSWSMan";

    public static bool Enabled { get; set; } = false;
    public static Harmony HarmonyLib { get; } = new(HarmonyId);
}

[Cmdlet(
    VerbsLifecycle.Enable, "PSWSMan"
)]
public sealed class EnablePSWSMan : PSCmdlet
{
    [Parameter()]
    public SwitchParameter Force { get; set; }

    protected override void EndProcessing()
    {
        const string confirmMessage = "If you continue, hooks will be injected into the PowerShell to force it to use PSWSMan as the WSMan client transport. This operation is global to the process and is not reversible.";

        if (!PSWSManStatus.Enabled)
        {
            if (Force || ShouldContinue(confirmMessage, "Confirm"))
            {
                PSWSManStatus.HarmonyLib.PatchAll();
                PSWSManStatus.Enabled = true;
            }
        }
    }
}
