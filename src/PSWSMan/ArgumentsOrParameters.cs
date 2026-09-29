using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;

namespace PSWSMan;

/// <summary>The -ArgumentList of Invoke-WinRMCommand, either positional arguments or named parameters.</summary>
/// <remarks>
/// A dictionary is bound to the remote script by parameter name like splatting a hashtable, anything else is passed
/// positionally like splatting an array.
/// </remarks>
public sealed class ArgumentsOrParameters
{
    private ArgumentsOrParameters(IReadOnlyList<object?> arguments,
        IReadOnlyList<KeyValuePair<string, object?>> parameters)
    {
        Arguments = arguments;
        Parameters = parameters;
    }

    /// <summary>The positional arguments.</summary>
    public IReadOnlyList<object?> Arguments { get; }

    /// <summary>The named parameters in the order the dictionary gave them.</summary>
    public IReadOnlyList<KeyValuePair<string, object?>> Parameters { get; }

    /// <summary>Creates positional arguments.</summary>
    public static ArgumentsOrParameters FromArguments(IEnumerable arguments)
    {
        List<object?> values = new();
        foreach (object? value in arguments)
        {
            values.Add(value);
        }
        return new(values, []);
    }

    /// <summary>Creates named parameters from the keys and values of a dictionary.</summary>
    public static ArgumentsOrParameters FromParameters(IDictionary parameters)
    {
        List<KeyValuePair<string, object?>> values = new();
        foreach (DictionaryEntry entry in parameters)
        {
            values.Add(new(LanguagePrimitives.ConvertTo<string>(entry.Key), entry.Value));
        }
        return new([], values);
    }
}

/// <summary>Converts an -ArgumentList value to <see cref="ArgumentsOrParameters"/>.</summary>
public sealed class ArgumentsOrParametersTransformAttribute : ArgumentTransformationAttribute
{
    public override object? Transform(EngineIntrinsics engineIntrinsics, object? inputData)
    {
        if (inputData is PSObject psObj)
        {
            inputData = psObj.BaseObject;
        }

        return inputData switch
        {
            null => null,
            ArgumentsOrParameters value => value,
            IDictionary parameters => ArgumentsOrParameters.FromParameters(parameters),
            IList arguments => ArgumentsOrParameters.FromArguments(arguments),
            _ => ArgumentsOrParameters.FromArguments(new[] { inputData }),
        };
    }
}
