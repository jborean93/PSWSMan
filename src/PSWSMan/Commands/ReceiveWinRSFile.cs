using System;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using PSWSMan.Connection;

namespace PSWSMan.Commands;

[Cmdlet(
    VerbsCommunications.Receive, "WinRSFile",
    DefaultParameterSetName = "ComputerName",
    SupportsShouldProcess = true
)]
public sealed class ReceiveWinRSFile : WinRSFileCmdletBase
{
    private const string ErrorId = "WinRSReceiveFileFailed";

    [Parameter(
        Mandatory = true,
        Position = 1,
        ValueFromPipeline = true
    )]
    [ValidateNotNullOrEmpty]
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
            Guard(() => ReceiveFile(path));
        }
    }

    private void ReceiveFile(string remotePath)
    {
        string localPath;
        string tempPath;
        FileStream temp;
        string commandLine;
        try
        {
            localPath = GetFileSystemPath(Destination);
            if (Directory.Exists(localPath))
            {
                string name = remotePath.TrimEnd('\\', '/').Split('\\', '/')[^1];
                if (name.Length == 0 || name.EndsWith(':'))
                {
                    throw new ArgumentException($"The remote path '{remotePath}' does not have a file name.");
                }
                localPath = System.IO.Path.Combine(localPath, name);
            }
            if (!ShouldProcess($"'{remotePath}' on '{ConnectionTarget}'", $"Copy to '{localPath}'"))
            {
                return;
            }

            commandLine = WinRSPowerShell.GetCommandLine("ReceiveWinRSFile.ps1", remotePath,
                Compression.ToString());
            string directory = System.IO.Path.GetDirectoryName(localPath) ?? "";
            tempPath = System.IO.Path.Combine(directory,
                $".{System.IO.Path.GetFileName(localPath)}.{Guid.NewGuid():N}.tmp");
            temp = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException
            or NotSupportedException or RuntimeException)
        {
            WriteFileError(e, ErrorId, remotePath);
            return;
        }

        try
        {
            using WinRSFileTransferReader reader = new(temp);
            TransferProgress progress = new(this,
                $"Copying '{remotePath}' on '{ConnectionTarget}' to '{localPath}'");
            Exception? localError = null;
            string description = $"remote PowerShell to read '{remotePath}'";
            TransferResult result = RunTransfer(commandLine, description, null, stdout =>
            {
                using Stream content = Compression == CompressionMethod.Deflate
                    ? new DeflateStream(stdout, CompressionMode.Decompress)
                    : stdout;
                byte[] buffer = new byte[81920];
                try
                {
                    int read;
                    while ((read = content.Read(buffer)) > 0)
                    {
                        reader.Write(buffer.AsSpan(0, read));
                        progress.Update(reader.BytesWritten, reader.Length);
                    }
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    // A write to the local file failing or the compressed data being corrupt, the rest of the
                    // output is discarded and a remote error takes precedence as it is likely the cause.
                    localError = e;
                }
            });
            progress.Complete();

            Exception? error = result.GetRemoteError() ?? localError;
            if (error is null)
            {
                try
                {
                    reader.Complete();
                    temp.Dispose();
                    File.Move(tempPath, localPath, overwrite: true);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    error = e;
                }
            }

            if (error is null)
            {
                WriteVerbose($"Copied '{remotePath}' on '{ConnectionTarget}' to '{localPath}'.");
            }
            else
            {
                WriteFileError(error, ErrorId, remotePath);
            }
        }
        finally
        {
            temp.Dispose();
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }
}
