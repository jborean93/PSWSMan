#!/usr/bin/env pwsh
#Requires -Version 7.2

using namespace System.IO
using namespace System.Text

<#
.SYNOPSIS
Regenerates the markdown help from the built module.

.DESCRIPTION
Imports the module from output/ and runs platyPS to update the cmdlet pages
and module page under docs/en-US so new parameters, aliases and the syntax
blocks match the built cmdlets. Run build.ps1 first, it builds the module and
downloads the pinned platyPS into output/Modules.

platyPS writes CRLF line endings. On non-Windows hosts git normalises them to
LF on commit but the working tree then differs from the index, so the pages
are rewritten with LF here to keep the tree clean.

.PARAMETER DocsPath
The directory holding the markdown help, defaults to docs/en-US.

.EXAMPLE
./tools/UpdateDocs.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $DocsPath
)

$ErrorActionPreference = 'Stop'

$projectRoot = [Path]::GetFullPath([Path]::Combine($PSScriptRoot, '..'))
$moduleName = (Get-Item ([Path]::Combine($projectRoot, 'module', '*.psd1'))).BaseName
$modulePath = [Path]::Combine($projectRoot, 'output', $moduleName)
$platyPSPath = [Path]::Combine($projectRoot, 'output', 'Modules', 'platyPS')
if (-not $DocsPath) {
    $DocsPath = [Path]::Combine($projectRoot, 'docs', 'en-US')
}

foreach ($required in $modulePath, $platyPSPath) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Cannot find '$required', run build.ps1 -Task Build first"
    }
}

Import-Module -Name $modulePath
Import-Module -Name $platyPSPath

Update-MarkdownHelpModule -Path $DocsPath -AlphabeticParamsOrder -RefreshModulePage -UpdateInputOutput | Out-Null

if (-not $IsWindows) {
    $utf8NoBom = [UTF8Encoding]::new($false)
    foreach ($file in Get-ChildItem -LiteralPath $DocsPath -Filter *.md -File) {
        $content = [File]::ReadAllText($file.FullName)
        $normalized = $content.Replace("`r`n", "`n")
        if ($normalized -ne $content) {
            [File]::WriteAllText($file.FullName, $normalized, $utf8NoBom)
        }
    }
}
