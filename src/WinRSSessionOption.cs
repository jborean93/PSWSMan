using System.Net.Security;

namespace PSWSMan;

public class WinRSSessionOption
{
    public string? Culture { get; set; }

    public string? UICulutre { get; set; }

    public int OpenTimeout { get; set; }

    public int IdleTimeout { get; set; }

    public int OperationTimeout { get; set; }

    public bool NoEncryption { get; set; }

    public bool SkipCertificateCheck { get; set; }

    public bool RequestDelegate { get; set; }

    public string? SPNService { get; set; }

    public string? SPNHostname { get; set; }

    public SslClientAuthenticationOptions? SslOptions { get; set; }
}
