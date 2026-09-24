using System;
using System.ComponentModel;
using System.Security.Authentication;

namespace PSWSMan.Authentication.Native;

internal class SspiException : AuthenticationException
{
    public int ErrorCode { get; } = -1;

    public SspiException() { }

    public SspiException(string message) : base(message) { }

    public SspiException(string message, Exception innerException) :
        base(message, innerException)
    { }

    public SspiException(int errorCode, string method)
        : base(GetExceptionMessage(errorCode, method))
    {
        ErrorCode = errorCode;
    }

    private static string GetExceptionMessage(int errorCode, string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "SSPI Call" : method;
        string errMsg = new Win32Exception(errorCode).Message;

        return String.Format("{0} failed ({1}, Win32ErrorCode {2} - 0x{2:X8})", method, errMsg, errorCode);
    }
}
