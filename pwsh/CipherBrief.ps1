[CmdletBinding()]
param(
    [ValidateSet('crowdstrike','nessus','blumira','auto')][string]$Source = 'auto',
    [Parameter(Mandatory=$true)][string]$Input,
    [string]$OutDir = 'brief_out',
    [switch]$Offline
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
. "$root/Lib/Parsers.ps1"
. "$root/Lib/Enrich.ps1"
. "$root/Lib/Report.ps1"
if(!(Test-Path -LiteralPath $Input)){ throw "Input not found: $Input" }
$file=Get-Item -LiteralPath $Input
if($file.Extension.ToLower() -ne '.csv'){ throw 'Input must be a CSV file.' }
if($Source -eq 'auto'){
    $n=$file.Name.ToLower()
    if($n -match 'crowd|falcon|spotlight'){$Source='crowdstrike'} elseif($n -match 'nessus'){$Source='nessus'} elseif($n -match 'blumira'){$Source='blumira'} else {throw 'Could not detect source. Use -Source crowdstrike, nessus, or blumira.'}
}
$findings=switch($Source){'crowdstrike'{Parse-CrowdStrike $Input};'nessus'{Parse-Nessus $Input};'blumira'{Parse-Blumira $Input}}
$findings=Add-Enrichment -Findings $findings -Offline:$Offline
$summary=New-ExecutiveSummary -Findings $findings -Source $Source -InputName $file.Name
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$pdf=Join-Path $OutDir "cipherbrief_${Source}_$($file.BaseName).pdf"
Export-ExecutivePdf -Summary $summary -Path $pdf
Write-Host "Generated PDF: $pdf"
Write-Host "Findings: $($summary.total); NOW: $($summary.now_count); WAIT: $($summary.wait_count)"
