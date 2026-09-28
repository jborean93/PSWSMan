param([string]$Path, [string]$Name, [string]$Compression)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$fs = $null
$tempPath = $null
try {
    $Path = [IO.Path]::GetFullPath($Path)
    if ([IO.Directory]::Exists($Path)) {
        $Path = [IO.Path]::Combine($Path, $Name)
    }
    $dir = [IO.Path]::GetDirectoryName($Path)
    if (-not [IO.Path]::GetFileName($Path) -or -not [IO.Directory]::Exists($dir)) {
        throw "Could not find the directory of '$Path'."
    }

    $tempPath = [IO.Path]::Combine($dir, ".$([IO.Path]::GetFileName($Path)).$([Guid]::NewGuid().ToString('N')).tmp")
    $fs = [IO.FileStream]::new($tempPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $in = [Console]::OpenStandardInput()
    if ($Compression -eq 'Deflate') {
        $in = [IO.Compression.DeflateStream]::new($in, [IO.Compression.CompressionMode]::Decompress)
    }
    $buffer = [byte[]]::new(65536)

    function Read-Exact([int]$Count) {
        $offset = 0
        while ($offset -lt $Count) {
            $read = $in.Read($buffer, $offset, $Count - $offset)
            if ($read -eq 0) { throw 'The input ended before the whole file was received.' }
            $offset += $read
        }
    }

    Read-Exact 8
    $remaining = [BitConverter]::ToInt64($buffer, 0)
    $sha = [Security.Cryptography.SHA256CryptoServiceProvider]::new()
    while ($remaining -gt 0) {
        $read = $in.Read($buffer, 0, [Math]::Min($buffer.Length, $remaining))
        if ($read -eq 0) { throw 'The input ended before the whole file was received.' }
        [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
        $fs.Write($buffer, 0, $read)
        $remaining -= $read
    }
    [void]$sha.TransformFinalBlock($buffer, 0, 0)
    Read-Exact 32
    $expected = [BitConverter]::ToString($buffer, 0, 32)
    $actual = [BitConverter]::ToString($sha.Hash)
    if ($expected -ne $actual) {
        throw "The SHA256 hash of the received content $($actual.Replace('-', '')) does not match the sender's hash $($expected.Replace('-', ''))."
    }

    $fs.Dispose()
    $fs = $null
    if ([IO.File]::Exists($Path)) {
        [IO.File]::Replace($tempPath, $Path, [NullString]::Value)
    }
    else {
        [IO.File]::Move($tempPath, $Path)
    }
    $tempPath = $null

    [Console]::Out.Write($Path)
}
catch {
    [Console]::Error.WriteLine($_.Exception.GetBaseException().Message)
    $host.SetShouldExit(1)
}
finally {
    if ($fs) { $fs.Dispose() }
    if ($tempPath -and [IO.File]::Exists($tempPath)) { [IO.File]::Delete($tempPath) }
}
