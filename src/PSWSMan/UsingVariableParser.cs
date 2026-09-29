using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Text;

namespace PSWSMan;

internal static class UsingVariableParser
{
    private sealed class UndefinedValue
    {
        public static readonly UndefinedValue Value = new();

        private UndefinedValue()
        { }
    }

    /// <summary>
    /// Gets the values of every $using: expression in the Ast from the session state. The resulting Hashtable is
    /// keyed the way PowerShell expects for the --% using parameter of a script invocation.
    /// </summary>
    /// <param name="sessionState">The session state of the caller to retrieve the values from.</param>
    /// <param name="ast">The Ast to extract the $using: expressions from.</param>
    /// <returns>The using values keyed for the --% parameter.</returns>
    /// <exception cref="ArgumentException">One or more using variables have not been set, all are listed.</exception>
    public static Hashtable GetUsingParameters(SessionState sessionState, Ast ast)
    {
        Hashtable found = new();
        HashSet<string> undefinedKeys = [];
        List<string> undefined = [];

        foreach (Ast usingStatement in ast.FindAll(a => a is UsingExpressionAst, true))
        {
            UsingExpressionAst usingAst = (UsingExpressionAst)usingStatement;
            VariableExpressionAst backingVariableAst = UsingExpressionAst.ExtractUsingVariable(usingAst);
            string varPath = backingVariableAst.VariablePath.UserPath;

            // PowerShell lowercases the key of a plain $using:var so it matches regardless of case. An index or
            // member expression is left as is as a string index could be case sensitive.
            string varText = usingAst.ToString();
            if (usingAst.SubExpression is VariableExpressionAst)
            {
                varText = varText.ToLowerInvariant();
            }
            string key = Convert.ToBase64String(Encoding.Unicode.GetBytes(varText));

            if (found.ContainsKey(key) || undefinedKeys.Contains(key))
            {
                continue;
            }

            // GetValue returns the default for a variable set to $null so a plain variable is looked up with Get.
            // A drive qualified path like env:VAR is not a variable and is only reachable through GetValue.
            object? value = UndefinedValue.Value;
            if (backingVariableAst.VariablePath.IsVariable)
            {
                PSVariable? variable = sessionState.PSVariable.Get(varPath);
                if (variable is not null)
                {
                    value = variable.Value;
                }
            }
            else
            {
                value = sessionState.PSVariable.GetValue(varPath, UndefinedValue.Value);
            }

            if (value is UndefinedValue)
            {
                undefinedKeys.Add(key);
                undefined.Add(usingAst.ToString());
                continue;
            }

            found.Add(key, ExtractUsingExpressionValue(value, usingAst.SubExpression));
        }

        if (undefined.Count > 0)
        {
            string varList = string.Join(", ", undefined.Select(v => $"'{v}'"));
            throw new ArgumentException(
                $"The value of the using variable(s) {varList} cannot be retrieved because they have not been set in the local session.");
        }

        return found;
    }

    private static object? ExtractUsingExpressionValue(object? value, ExpressionAst ast)
    {
        if (ast is not MemberExpressionAst && ast is not IndexExpressionAst)
        {
            return value;
        }

        // Rebuilds the member and index expressions on top of the variable value as a constant, from the innermost
        // variable outwards, and runs that to get the final value.
        VariableExpressionAst usingVariable = (VariableExpressionAst)ast.Find(a => a is VariableExpressionAst, false);
        ExpressionAst lookupAst = new ConstantExpressionAst(ast.Extent, value);
        ExpressionAst currentAst = usingVariable;
        while (true)
        {
            if (currentAst.Parent is IndexExpressionAst indexAst)
            {
                lookupAst = new IndexExpressionAst(
                    indexAst.Extent,
                    lookupAst,
                    (ExpressionAst)indexAst.Index.Copy(),
                    indexAst.NullConditional);
                currentAst = indexAst;
            }
            else if (currentAst.Parent is MemberExpressionAst memberAst)
            {
                lookupAst = new MemberExpressionAst(
                    memberAst.Extent,
                    lookupAst,
                    (ExpressionAst)memberAst.Member.Copy(),
                    memberAst.Static,
                    memberAst.NullConditional);
                currentAst = memberAst;
            }
            else
            {
                break;
            }
        }

        // Wrapping it in an array, like the unary comma, stops the pipeline from enumerating a collection value.
        lookupAst = new ArrayLiteralAst(ast.Extent, [lookupAst]);
        ScriptBlock extractionScriptBlock = new ScriptBlockAst(
            ast.Extent,
            null,
            new StatementBlockAst(
                ast.Extent,
                [
                    new PipelineAst(
                        ast.Extent,
                        [new CommandExpressionAst(ast.Extent, lookupAst, null)])
                ],
                null),
            false).GetScriptBlock();

        return extractionScriptBlock.Invoke()[0];
    }
}
