using PSWSMan.Connection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Text;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommunications.Send, "WinRSFile",
    DefaultParameterSetName = "ComputerName",
    SupportsShouldProcess = true
)]
public sealed class SendWinRSFile : WinRSFileCmdletBase
{
    private const string ErrorId = "WinRSSendFileFailed";

    [Parameter(
        Mandatory = true,
        Position = 1,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [ValidateNotNullOrEmpty]
    [Alias("PSPath", "LiteralPath", "FullName")]
    public string[] Path { get; set; } = [];

    [Parameter(
        Mandatory = true,
        Position = 2,
        ValueFromPipelineByPropertyName = true
    )]
    [ValidateNotNullOrEmpty]
    public string Destination { get; set; } = "";

    protected override void ProcessRecord()
    {
        foreach (string path in Path)
        {
            Guard(() => SendFile(path));
        }
    }

    private void SendFile(string path)
    {
        string localPath;
        FileStream source;
        string commandLine;
        try
        {
            localPath = GetFileSystemPath(path);
            if (Directory.Exists(localPath))
            {
                throw new ArgumentException($"The path '{localPath}' is a directory, only files can be copied.");
            }
            if (!ShouldProcess(localPath, $"Copy to '{Destination}' on '{ConnectionTarget}'"))
            {
                return;
            }

            commandLine = WinRSPowerShell.GetCommandLine("SendWinRSFile.ps1", Destination,
                System.IO.Path.GetFileName(localPath), Compression.ToString());
            source = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException
            or NotSupportedException or RuntimeException)
        {
            WriteFileError(e, ErrorId, path);
            return;
        }

        TransferResult result;
        string remotePath = "";
        TransferProgress progress = new(this, $"Copying '{localPath}' to '{Destination}' on '{ConnectionTarget}'");
        using (source)
        {
            long length = source.Length;
            IEnumerable<byte[]> chunks = ReportProgress(
                WinRSFileTransfer.ReadFramedChunks(source, length, WinRSCommand.InputChunkSize), length, progress);
            if (Compression == CompressionMethod.Deflate)
            {
                chunks = WinRSFileTransfer.Deflate(chunks, WinRSCommand.InputChunkSize);
            }
            result = RunTransfer(commandLine, $"remote PowerShell to write '{Destination}'", chunks, stdout =>
            {
                using StreamReader reader = new(stdout, Encoding.UTF8);
                remotePath = reader.ReadToEnd();
            });
        }
        progress.Complete();

        if (result.InputError is not null)
        {
            WriteFileError(result.InputError, ErrorId, localPath);
        }
        else if (result.GetRemoteError() is Exception remoteError)
        {
            WriteFileError(remoteError, ErrorId, localPath);
        }
        else
        {
            WriteVerbose($"Copied '{localPath}' to '{remotePath}' on '{ConnectionTarget}'.");
        }
    }

    private static IEnumerable<byte[]> ReportProgress(IEnumerable<byte[]> chunks, long length,
        TransferProgress progress)
    {
        long sent = -WinRSFileTransfer.HeaderLength;
        foreach (byte[] chunk in chunks)
        {
            yield return chunk;
            sent += chunk.Length;
            progress.Update(sent, length);
        }
    }
}
