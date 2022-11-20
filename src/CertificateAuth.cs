using System.Net.Http;

namespace PSWSMan;

internal class CertificateAuthProvider : HttpAuthProvider
{
    public override bool Complete => false;

    public override bool AlwaysAddHeaders => true;

    public override bool AddAuthenticationHeaders(HttpRequestMessage request, HttpResponseMessage? response)
    {
        // dotnet sees this value as invalid based on the HTTP spec. Use without validation to ensure it is added.
        request.Headers.TryAddWithoutValidation("Authorization",
            "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual");
        return false;
    }
}
