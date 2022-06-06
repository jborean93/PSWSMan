using System.Management.Automation;
using System.Text;

namespace PSWSMan;

public class EncodingTransformer : ArgumentTransformationAttribute
{
    public override object Transform(EngineIntrinsics engineIntrinsics, object? inputData)
    {
        if (inputData is Encoding inputEncoding)
        {
            return inputEncoding;
        }
        else if (inputData is int inputInt)
        {
            return Encoding.GetEncoding(inputInt);
        }

        string inputStr = inputData?.ToString() ?? "";

        return inputStr.ToLowerInvariant() switch
        {
            "ascii" => Encoding.ASCII,
            "utf8" => new UTF8Encoding(false),
            "utf8nobom" => new UTF8Encoding(false),
            "utf8bom" => new UTF8Encoding(true),
            "unicode" => Encoding.Unicode,
            _ => Encoding.GetEncoding(inputStr),
        };
    }
}
