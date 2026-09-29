using System.Management.Automation;
using System.Management.Automation.Language;

namespace PSWSMan;

internal static class ScriptBlockHelper
{
    // Internal S.M.A API: the ScriptBlock(IParameterMetadataProvider, bool) constructor is internal and only
    // reachable through the assembly wide IgnoresAccessChecksTo. A function definition has no public way to get an
    // unbound scriptblock. It is a known risk, a PowerShell release that changes it breaks the certificate validation
    // callback for a scriptblock made from a function until PSWSMan is updated.
    public static ScriptBlock StripScriptBlockAffinity(ScriptBlock scriptBlock) => scriptBlock.Ast switch
    {
        ScriptBlockAst sba => sba.GetScriptBlock(),
        FunctionDefinitionAst fda => new ScriptBlock(fda, fda.IsFilter),
        _ => throw new RuntimeException($"Unexpected Ast type from ScriptBlock {scriptBlock.Ast.GetType().Name}.")
    };
}
