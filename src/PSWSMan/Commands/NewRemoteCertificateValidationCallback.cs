using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommon.New, "RemoteCertificateValidationCallback"
)]
[OutputType(typeof(RemoteCertificateValidationCallback))]
public sealed class NewRemoteCertificateValidationCallback : PSCmdlet
{
    [Parameter(
        Position = 1,
        Mandatory = true
    )]
    public ScriptBlock ScriptBlock { get; set; } = null!;

    protected override void EndProcessing()
    {
        // Internal S.M.A API: ScriptBlockToPowerShellConverter.GetUsingValuesAsDictionary and Cmdlet.Context are
        // internal and only reachable through the assembly wide IgnoresAccessChecksTo. They capture the $using:
        // values the same way Start-ThreadJob and ForEach-Object -Parallel do, which no public API offers. It is a
        // known risk, a PowerShell release that changes them breaks this cmdlet until PSWSMan is updated.
        Dictionary<string, object> usingVars = ScriptBlockToPowerShellConverter.GetUsingValuesAsDictionary(
            ScriptBlock, true, this.Context, null);

        ScriptBlockCertificateValidation sbkDelegate = new(Host, ScriptBlock, usingVars);
        WriteObject((RemoteCertificateValidationCallback)sbkDelegate.Validate);
    }
}

public sealed class ScriptBlockCertificateValidation
{
    public PSHost? Host { get; }
    public ScriptBlock ScriptBlock { get; }
    public Dictionary<string, object> UsingVars { get; }

    public ScriptBlockCertificateValidation(PSHost? host, ScriptBlock scriptBlock,
        Dictionary<string, object> usingVars)
    {
        Host = host;
        ScriptBlock = scriptBlock;
        UsingVars = usingVars;
    }

    public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        using Runspace rs = RunspaceFactory.CreateRunspace(Host);
        rs.Open();
        using PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;

        object?[] sbkArgs = [sender, certificate, chain, sslPolicyErrors];
        ps.AddScript(@"
            $methArgs = $args[2]
            & $args[0].Invoke($args[1]) @methArgs
        ", true)
            .AddArgument((object)ScriptBlockHelper.StripScriptBlockAffinity)
            .AddArgument(ScriptBlock)
            .AddArgument(sbkArgs);
        ps.AddParameter("--%", UsingVars);

        Collection<PSObject> res = ps.Invoke();
        if (res.Count > 0)
        {
            if (res[res.Count - 1].BaseObject is bool castedRes)
            {
                return castedRes;
            }
        }

        return false;
    }
}
