using System;
using System.Globalization;
using System.Management.Automation;
using System.Text;

namespace PSWSMan;

internal sealed class EncodingTransformAttribute : ArgumentTransformationAttribute
{
    internal static readonly string[] KnownEncodings = [
        "UTF8",
        "UTF8Bom",
        "UTF8NoBom",
        "ASCII",
        "ANSI",
        "OEM",
        "ConsoleInput",
        "ConsoleOutput",
    ];

    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
    {
        if (inputData is PSObject psObj)
        {
            inputData = psObj.BaseObject;
        }

        try
        {
            return inputData switch
            {
                Encoding e => e,
                int i => Encoding.GetEncoding(i),
                string s when int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int i) =>
                    Encoding.GetEncoding(i),
                string s => GetEncodingFromString(s),
                _ => throw new ArgumentTransformationMetadataException(
                    $"Could not convert input '{inputData}' to a valid Encoding object."),
            };
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException)
        {
            throw new ArgumentTransformationMetadataException(e.Message, e);
        }
    }

    private static Encoding GetEncodingFromString(string encoding) => encoding.ToUpperInvariant() switch
    {
        "ASCII" => new ASCIIEncoding(),
        "ANSI" => Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage),
        "CONSOLEINPUT" => Console.InputEncoding,
        "CONSOLEOUTPUT" => Console.OutputEncoding,
        "OEM" => Console.OutputEncoding,
        "UTF8" => new UTF8Encoding(),
        "UTF8BOM" => new UTF8Encoding(true),
        "UTF8NOBOM" => new UTF8Encoding(),
        _ => Encoding.GetEncoding(encoding),
    };
}

internal sealed class EncodingCompletionsAttribute : ArgumentCompletionsAttribute
{
    public EncodingCompletionsAttribute() : base(EncodingTransformAttribute.KnownEncodings)
    { }
}
