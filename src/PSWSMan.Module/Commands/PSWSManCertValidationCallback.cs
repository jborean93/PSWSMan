using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Net.Security;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace PSWSMan.Module.Commands;

[Cmdlet(
    VerbsCommon.New, "PSWSManCertValidationCallback"
)]
[OutputType(typeof(RemoteCertificateValidationCallback))]
public sealed class NewPSWSmanCertValidationCallback : PSCmdlet
{
    [Parameter(
        Position = 1,
        Mandatory = true
    )]
    public ScriptBlock ScriptBlock { get; set; } = ScriptBlock.EmptyScriptBlock;

    protected override void EndProcessing()
    {
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

        ps.AddScript(ScriptBlock.ToString())
            .AddArgument(sender)
            .AddArgument(certificate)
            .AddArgument(chain)
            .AddArgument(sslPolicyErrors);
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
