using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text;

namespace PSWSMan.Authentication.Native;

internal class GSSAPIException : AuthenticationException
{
    public uint MajorStatus { get; } = uint.MaxValue;

    public uint MinorStatus { get; } = uint.MaxValue;

    public GSSAPIException() { }

    public GSSAPIException(string message) : base(message) { }

    public GSSAPIException(string message, Exception innerException) :
        base(message, innerException)
    { }

    internal GSSAPIException(GssapiProvider provider, uint majorStatus, uint minorStatus, string method)
        : base(GetExceptionMessage(provider, majorStatus, minorStatus, method))
    {
        MajorStatus = majorStatus;
        MinorStatus = minorStatus;
    }

    private static string GetExceptionMessage(GssapiProvider provider, uint majorStatus, uint minorStatus,
        string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "GSSAPI Call" : method;
        string majString = DisplayStatus(provider, majorStatus, GssapiStatusType.GSS_C_GSS_CODE);
        string minString = DisplayStatus(provider, minorStatus, GssapiStatusType.GSS_C_MECH_CODE);

        return String.Format("{0} failed (Major Status {1} - {2}) (Minor Status {3} - {4})",
            method, majorStatus, majString, minorStatus, minString);
    }

    /// <summary>Gets every message the library has for a status code, joined into one string.</summary>
    /// <remarks>
    /// <c>gss_display_status</c> returns one message per call and uses <c>message_context</c> to continue where it
    /// left off, the loop ends once it comes back as zero. Failures cannot throw here as that would recurse.
    /// </remarks>
    private static unsafe string DisplayStatus(GssapiProvider provider, uint statusValue, GssapiStatusType statusType)
    {
        List<string> lines = new();
        uint messageContext = 0;
        do
        {
            Helpers.gss_buffer_desc statusString = default;
            try
            {
                uint majorStatus = provider.DisplayStatus(statusValue, statusType, default, &messageContext,
                    &statusString);
                if (majorStatus != 0)
                {
                    break;
                }

                string line = Encoding.UTF8.GetString((byte*)statusString.value, (int)statusString.length);
                if (!String.IsNullOrEmpty(line))
                {
                    lines.Add(line);
                }
            }
            finally
            {
                provider.ReleaseBuffer(&statusString);
            }
        }
        while (messageContext != 0);

        return String.Join(". ", lines);
    }
}
