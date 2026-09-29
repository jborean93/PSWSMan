using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
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

    private Hashtable? _usingVars = null;

    protected override void BeginProcessing()
    {
        try
        {
            _usingVars = UsingVariableParser.GetUsingParameters(SessionState, ScriptBlock.Ast);
        }
        catch (ArgumentException e)
        {
            ThrowTerminatingError(new ErrorRecord(
                e,
                "UsingVariableIsUndefined",
                ErrorCategory.InvalidArgument,
                ScriptBlock));
        }
    }

    protected override void EndProcessing()
    {
        Debug.Assert(_usingVars != null);
        ScriptBlockCertificateValidation sbkDelegate = new(Host, ScriptBlock, _usingVars);
        WriteObject((RemoteCertificateValidationCallback)sbkDelegate.Validate);
    }
}

public sealed class ScriptBlockCertificateValidation
{
    public PSHost? Host { get; }
    public ScriptBlock ScriptBlock { get; }
    public Hashtable UsingVars { get; }

    public ScriptBlockCertificateValidation(PSHost? host, ScriptBlock scriptBlock,
        Hashtable usingVars)
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
