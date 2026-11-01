$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
$inspector=Join-Path $PSScriptRoot '../inspect-public-pilot-ready-archive.ps1'
$testRoot=Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../work/data'))) ('public-pilot-ready-tests-'+[Guid]::NewGuid().ToString('N'))
$control=Join-Path $testRoot 'control'
New-Item -ItemType Directory -Path $control -Force | Out-Null
function Hash([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Zip([string]$Name,[string[]]$Names,[bool]$Oversize=$false){
 $target=Join-Path $testRoot $Name
 $file=[IO.File]::Open($target,[IO.FileMode]::CreateNew)
 $archive=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$false)
 try {foreach($name in $Names){$entry=$archive.CreateEntry($name);$s=$entry.Open();try{
  $data=if($Oversize){[byte[]]::new(262145)}else{[Text.Encoding]::UTF8.GetBytes('{"fixture":true}')}
  $s.Write($data,0,$data.Length)
 }finally{$s.Dispose()}}}finally{$archive.Dispose();$file.Dispose()}
 return $target
}
$names=@('READY.json','pilot-plan.json','native-plan.json')
foreach($name in $names){[IO.File]::WriteAllText((Join-Path $control $name),'{"fixture":true}',[Text.UTF8Encoding]::new($false))}
$good=Zip 'good.zip' $names
$goodHash=Hash $good
$readyHash=Hash (Join-Path $control 'READY.json')
$receipt=(& $inspector -ZipPath $good -ExpectedZipSha256 $goodHash -ControlDirectory $control -ExpectedReadySha256 $readyHash) | ConvertFrom-Json
if($receipt.entries.Count -ne 3 -or -not $receipt.readOnly -or $receipt.archiveSha256 -ne $goodHash){throw 'INSPECTOR_VALID_CASE_FAILED'}
$cases=@(
 @{name='zip-digest';zip=$good;hash=('0'*64);ready=$readyHash;expected='ARCHIVE_HASH'},
 @{name='external-ready-digest';zip=$good;hash=$goodHash;ready=('0'*64);expected='LOG_HASH_MISMATCH'},
 @{name='unexpected-entry';zip=(Zip 'extra.zip' ($names+@('unknown.json')));ready=$readyHash;expected='ENTRY_COUNT'},
 @{name='duplicate-entry';zip=(Zip 'duplicate.zip' @('READY.json','READY.json','native-plan.json'));ready=$readyHash;expected='ENTRY_NAME'},
 @{name='traversal-entry';zip=(Zip 'traversal.zip' @('../READY.json','pilot-plan.json','native-plan.json'));ready=$readyHash;expected='ENTRY_NAME'},
 @{name='oversize-entry';zip=(Zip 'oversize.zip' $names $true);ready=$readyHash;expected='ENTRY_SIZE'}
)
$results=@([ordered]@{case='valid-three-entry-archive';passed=$true})
foreach($case in $cases){
 $expectedHash=if($case.ContainsKey('hash')){$case.hash}else{Hash $case.zip}
 $rejected=$false
 try {& $inspector -ZipPath $case.zip -ExpectedZipSha256 $expectedHash -ControlDirectory $control -ExpectedReadySha256 $case.ready | Out-Null}
 catch {if($_.Exception.Message -notmatch $case.expected){throw};$rejected=$true}
 if(-not $rejected){throw ('INSPECTOR_UNEXPECTED_ACCEPTANCE_'+$case.name)}
 $results += [ordered]@{case=$case.name;passed=$true}
}
$other=Join-Path $testRoot 'different-controls';New-Item -ItemType Directory -Path $other | Out-Null
foreach($name in $names){[IO.File]::WriteAllText((Join-Path $other $name),'{"different":true}',[Text.UTF8Encoding]::new($false))}
$rejected=$false
try {& $inspector -ZipPath $good -ExpectedZipSha256 $goodHash -ControlDirectory $other -ExpectedReadySha256 $readyHash | Out-Null}
catch {if($_.Exception.Message -notmatch 'LOCAL_ENTRY_MISMATCH'){throw};$rejected=$true}
if(-not $rejected){throw 'INSPECTOR_CONTROL_SUBSTITUTION_ACCEPTED'}
$results += [ordered]@{case='local-control-substitution';passed=$true}
if((Hash $good) -ne $goodHash -or (Hash (Join-Path $control 'READY.json')) -ne $readyHash){throw 'INSPECTOR_MUTATED_INPUT'}
[ordered]@{status='FIXTURE_TESTS_PASSED';tests=$results.Count;pass=$results.Count;fail=0;cases=$results;fixtureRoot=$testRoot;nativeAvailabilityAccepted=$false;inspectorSha256=(Hash $inspector)} | ConvertTo-Json -Depth 6
