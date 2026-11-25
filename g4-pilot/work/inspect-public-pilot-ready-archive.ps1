param(
    [Parameter(Mandatory=$true)][string]$ZipPath,
    [Parameter(Mandatory=$true)][string]$ExpectedZipSha256,
    [Parameter(Mandatory=$true)][string]$ControlDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedReadySha256
)
# Read-only inspection. Never extracts files or executes archive content.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-Local([string]$Value,[bool]$Directory) {
    if (-not [IO.Path]::IsPathRooted($Value) -or $Value.StartsWith('\\') -or $Value.StartsWith('//')) { throw 'PILOT_READY_LOCAL_ABSOLUTE_PATH_REQUIRED' }
    $resolved = [IO.Path]::GetFullPath($Value)
    $item = Get-Item -LiteralPath $resolved -Force
    if (($item -is [IO.DirectoryInfo]) -ne $Directory) { throw 'PILOT_READY_RESOURCE_TYPE' }
    $current = $item
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'PILOT_READY_REPARSE_POINT' }
        if ($current -is [IO.DirectoryInfo]) { $current = $current.Parent } else { $current = $current.Directory }
    }
    return $resolved
}
function Digest([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
}
if ($ExpectedZipSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedReadySha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'PILOT_READY_EXTERNAL_HASH_REQUIRED' }
$archivePath = Assert-Local $ZipPath $false
$controlPath = Assert-Local $ControlDirectory $true
if ((Get-Item -LiteralPath $archivePath).Length -gt 1048576) { throw 'PILOT_READY_ARCHIVE_TOO_LARGE' }
$archiveBytes = [IO.File]::ReadAllBytes($archivePath)
if ((Digest $archiveBytes) -cne $ExpectedZipSha256) { throw 'PILOT_READY_ARCHIVE_HASH' }
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.MemoryStream]::new($archiveBytes,$false)
$zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$false)
$entries = [Collections.Generic.List[object]]::new()
$allowed = @('READY.json','pilot-plan.json','native-plan.json')
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
try {
    if ($zip.Entries.Count -ne 3) { throw 'PILOT_READY_ENTRY_COUNT' }
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName
        if ($allowed -cnotcontains $name -or -not $seen.Add($name)) { throw 'PILOT_READY_ENTRY_NAME' }
        if ($entry.Length -lt 1 -or $entry.Length -gt 262144) { throw 'PILOT_READY_ENTRY_SIZE' }
        $inputStream = $entry.Open()
        $decoded = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(32768)
            while (($count = $inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
                if ($decoded.Length + $count -gt 262144) { throw 'PILOT_READY_DECOMPRESSED_BOUND' }
                $decoded.Write($buffer,0,$count)
            }
            $data = $decoded.ToArray()
        } finally { $inputStream.Dispose(); $decoded.Dispose() }
        if ($data.Length -ne $entry.Length) { throw 'PILOT_READY_ENTRY_LENGTH' }
        $entryHash = Digest $data
        $localFile = Assert-Local ([IO.Path]::Combine($controlPath,$name)) $false
        if ((Get-Item -LiteralPath $localFile).Length -ne $data.Length -or (Digest ([IO.File]::ReadAllBytes($localFile))) -cne $entryHash) { throw 'PILOT_READY_LOCAL_ENTRY_MISMATCH' }
        if ($name -ceq 'READY.json' -and $entryHash -cne $ExpectedReadySha256) { throw 'PILOT_READY_LOG_HASH_MISMATCH' }
        $entries.Add([ordered]@{path=$name;bytes=$data.Length;sha256=$entryHash})
    }
} finally { $zip.Dispose(); $stream.Dispose() }
if ((Digest ([IO.File]::ReadAllBytes($archivePath))) -cne $ExpectedZipSha256) { throw 'PILOT_READY_ARCHIVE_CHANGED' }
foreach ($entry in $entries) {
    $localFile = Assert-Local ([IO.Path]::Combine($controlPath,$entry.path)) $false
    if ((Digest ([IO.File]::ReadAllBytes($localFile))) -cne $entry.sha256) { throw 'PILOT_READY_CONTROL_CHANGED' }
}
[ordered]@{
    schemaVersion='g4.public-availability-ready-import.v1'
    archiveSha256=$ExpectedZipSha256
    archiveBytes=$archiveBytes.Length
    entries=@($entries | Sort-Object { $_.path })
    inspectorSha256=(Digest ([IO.File]::ReadAllBytes($PSCommandPath)))
    readOnly=$true
} | ConvertTo-Json -Depth 5
