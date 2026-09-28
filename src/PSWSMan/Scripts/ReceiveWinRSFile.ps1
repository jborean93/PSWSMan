param([string]$Path, [string]$Compression)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$fs = $null
try {
    if ([IO.Directory]::Exists($Path)) {
        throw "The path '$Path' is a directory, only files can be copied."
    }

    $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $remaining = $fs.Length
    $stdout = [Console]::OpenStandardOutput()
    if ($Compression -eq 'Deflate') {
        # Deflate writes in small blocks, each pipe write can become its own small WinRS response.
        $stdout = [IO.BufferedStream]::new($stdout, 65536)
        $stdout = [IO.Compression.DeflateStream]::new($stdout, [IO.Compression.CompressionLevel]::Optimal)
    }
    $stdout.Write([BitConverter]::GetBytes([long]$remaining), 0, 8)

    $sha = [Security.Cryptography.SHA256CryptoServiceProvider]::new()
    $buffer = [byte[]]::new(65536)
    while ($remaining -gt 0) {
        $read = $fs.Read($buffer, 0, [Math]::Min($buffer.Length, $remaining))
        if ($read -eq 0) { throw "The file '$Path' was truncated while it was being read." }
        [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
        $stdout.Write($buffer, 0, $read)
        $remaining -= $read
    }
    [void]$sha.TransformFinalBlock($buffer, 0, 0)
    $stdout.Write($sha.Hash, 0, $sha.Hash.Length)
    $stdout.Dispose()
}
catch {
    [Console]::Error.WriteLine($_.Exception.GetBaseException().Message)
    $host.SetShouldExit(1)
}
finally {
    if ($fs) { $fs.Dispose() }
}
