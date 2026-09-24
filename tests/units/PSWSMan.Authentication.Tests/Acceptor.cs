using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace PSWSMan.Authentication.Tests;

/// <summary>The result of an acceptor step.</summary>
/// <param name="Token">The token to feed back to the client, null when the acceptor has nothing to send.</param>
/// <param name="Complete">Whether the acceptor considers the context established.</param>
internal sealed record AcceptorStepResult(byte[]? Token, bool Complete);

/// <summary>The result of the acceptor wrapping data for WinRM.</summary>
internal sealed record AcceptorWinRMWrapResult(byte[] Header, byte[] Data, int PaddingLength);

/// <summary>The password credentials a CredSSP acceptor received from the client.</summary>
internal sealed record AcceptorDelegatedCredentials(string Domain, string Username, string Password);

/// <summary>What the acceptor reports about its context.</summary>
internal sealed record AcceptorContextInfo(bool Complete, string? NegotiatedProtocol, int ContextAttr,
    string? ClientPrincipal, string? TlsProtocol, string? TlsCipher,
    AcceptorDelegatedCredentials? DelegatedCredentials);

/// <summary>An NTLM user the acceptor will accept.</summary>
internal sealed record AcceptorUser(string Domain, string Username, string Password);

/// <summary>Raised when the acceptor reports a failure for an operation.</summary>
internal sealed class AcceptorException(string type, string message) : Exception($"{type}: {message}")
{
    /// <summary>The Python exception type name, e.g. BadBindingsError.</summary>
    public string Type { get; } = type;
}

/// <summary>
/// A pyspnego acceptor running in a child Python process, driven over stdin/stdout with one JSON object per line. See
/// acceptor.py for the protocol.
/// </summary>
internal sealed class Acceptor : IDisposable
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly Process _process;
    private readonly StreamWriter _stdin;
    private readonly StreamReader _stdout;
    private readonly StringBuilder _stderr = new();
    private readonly string? _userFile;
    private bool _disposed;

    private Acceptor(Process process, string? userFile)
    {
        _process = process;
        _stdin = process.StandardInput;
        _stdout = process.StandardOutput;
        _userFile = userFile;

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (_stderr)
                {
                    _stderr.AppendLine(e.Data);
                }
            }
        };
        process.BeginErrorReadLine();
    }

    /// <summary>Starts the acceptor process, skipping the current test when Python with pyspnego is unavailable.</summary>
    /// <param name="users">The NTLM users to accept, written to the NTLM_USER_FILE the pure Python acceptor reads.</param>
    public static Acceptor Start(params AcceptorUser[] users)
    {
        string python = PythonHost.Require();

        string? userFile = null;
        if (users.Length > 0)
        {
            userFile = Path.Combine(Path.GetTempPath(), $"pswsman-ntlm-{Guid.NewGuid():N}.txt");
            StringBuilder content = new();
            foreach (AcceptorUser user in users)
            {
                content.Append(user.Domain).Append(':').Append(user.Username).Append(':').Append(user.Password)
                    .Append('\n');
            }
            File.WriteAllText(userFile, content.ToString());
        }

        ProcessStartInfo psi = new(python)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "acceptor.py"));
        psi.Environment["PYTHONIOENCODING"] = "utf-8";
        psi.Environment["PYTHONUNBUFFERED"] = "1";
        if (userFile is not null)
        {
            psi.Environment["NTLM_USER_FILE"] = userFile;
        }

        Process process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start acceptor");
        return new Acceptor(process, userFile);
    }

    /// <summary>Creates the acceptor context.</summary>
    /// <param name="protocol">The pyspnego protocol, ntlm, kerberos, negotiate or credssp.</param>
    /// <param name="options">pyspnego NegotiateOptions names controlling the implementation used.</param>
    /// <param name="hostname">The acceptor host name used to build its SPN.</param>
    /// <param name="service">The acceptor service used to build its SPN.</param>
    /// <param name="channelBindings">The application data of the channel bindings the acceptor expects.</param>
    /// <param name="tls">CredSSP only, pins the acceptor's TLS version and cipher family, see acceptor.py.</param>
    public void Create(string protocol, string[]? options = null, string hostname = "unspecified",
        string service = "host", byte[]? channelBindings = null, string? tls = null)
    {
        Send(new
        {
            op = "create",
            protocol,
            options,
            hostname,
            service,
            channel_bindings = channelBindings,
            tls,
        });
    }

    public AcceptorStepResult Step(byte[]? token)
    {
        JsonElement response = Send(new { op = "step", token });
        return new AcceptorStepResult(Bytes(response, "token"), response.GetProperty("complete").GetBoolean());
    }

    public byte[] Wrap(byte[] data)
        => Bytes(Send(new { op = "wrap", data }), "data")!;

    public byte[] Unwrap(byte[] data)
        => Bytes(Send(new { op = "unwrap", data }), "data")!;

    public AcceptorWinRMWrapResult WrapWinRM(byte[] data)
    {
        JsonElement response = Send(new { op = "wrap_winrm", data });
        return new AcceptorWinRMWrapResult(
            Bytes(response, "header")!,
            Bytes(response, "data")!,
            response.GetProperty("padding_length").GetInt32());
    }

    public byte[] UnwrapWinRM(byte[] header, byte[] data)
        => Bytes(Send(new { op = "unwrap_winrm", header, data }), "data")!;

    public AcceptorContextInfo Query()
    {
        JsonElement response = Send(new { op = "query" });

        AcceptorDelegatedCredentials? delegated = null;
        if (response.TryGetProperty("delegated_credentials", out JsonElement creds))
        {
            delegated = new AcceptorDelegatedCredentials(
                creds.GetProperty("domain").GetString() ?? "",
                creds.GetProperty("username").GetString() ?? "",
                creds.GetProperty("password").GetString() ?? "");
        }

        return new AcceptorContextInfo(
            response.GetProperty("complete").GetBoolean(),
            response.GetProperty("negotiated_protocol").GetString(),
            response.GetProperty("context_attr").GetInt32(),
            response.GetProperty("client_principal").GetString(),
            response.TryGetProperty("tls_protocol", out JsonElement tlsProtocol) ? tlsProtocol.GetString() : null,
            response.TryGetProperty("tls_cipher", out JsonElement tlsCipher) ? tlsCipher.GetString() : null,
            delegated);
    }

    private JsonElement Send(object request)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _stdin.Write(JsonSerializer.Serialize(request, s_jsonOptions));
        _stdin.Write('\n');
        _stdin.Flush();

        string? line = _stdout.ReadLine();
        if (line is null)
        {
            _process.WaitForExit(5000);
            throw new InvalidOperationException(
                $"Acceptor exited with {(_process.HasExited ? _process.ExitCode : "no exit code")} while waiting for a response.\n{Stderr}");
        }

        JsonElement response = JsonDocument.Parse(line).RootElement;
        if (!response.GetProperty("ok").GetBoolean())
        {
            throw new AcceptorException(
                response.GetProperty("type").GetString() ?? "Exception",
                response.GetProperty("error").GetString() ?? "");
        }

        return response;
    }

    private static byte[]? Bytes(JsonElement element, string property)
    {
        JsonElement value = element.GetProperty(property);
        return value.ValueKind == JsonValueKind.Null ? null : value.GetBytesFromBase64();
    }

    private string Stderr
    {
        get
        {
            lock (_stderr)
            {
                return _stderr.ToString();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        try
        {
            _stdin.Write("{\"op\":\"exit\"}\n");
            _stdin.Flush();
            _stdin.Close();
            if (!_process.WaitForExit(5000))
            {
                _process.Kill();
            }
        }
        catch (IOException)
        {
            // The process already went away.
        }
        finally
        {
            _process.Dispose();
            if (_userFile is not null)
            {
                File.Delete(_userFile);
            }
        }
    }
}

/// <summary>Locates the Python interpreter that has pyspnego installed.</summary>
internal static class PythonHost
{
    /// <summary>
    /// The environment variable the build script sets to the interpreter of the virtual environment it provisions.
    /// Without it the interpreters on PATH are probed.
    /// </summary>
    public const string EnvironmentVariable = "PSWSMAN_TEST_PYTHON";

    private static readonly Lazy<string?> s_python = new(Locate, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The interpreter path, or null when none with pyspnego was found.</summary>
    public static string? Path => s_python.Value;

    /// <summary>Returns the interpreter path or skips the current test when there is none.</summary>
    public static string Require()
    {
        string? python = Path;
        if (python is null)
        {
            Skip.Test($"Python with pyspnego is not available, set {EnvironmentVariable} or run build.ps1 -Task Test");
        }

        return python!;
    }

    private static string? Locate()
    {
        List<string> candidates = [];
        string? configured = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            candidates.Add(configured);
        }
        candidates.Add("python3");
        candidates.Add("python");

        foreach (string candidate in candidates)
        {
            if (HasSpnego(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static bool HasSpnego(string python)
    {
        try
        {
            ProcessStartInfo psi = new(python)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("import spnego");

            using Process? process = Process.Start(psi);
            if (process is null)
            {
                return false;
            }

            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or IOException)
        {
            return false;
        }
    }
}
