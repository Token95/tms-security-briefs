Set-StrictMode -Version Latest

$script:SourceLabels = @{
    crowdstrike = 'CrowdStrike EDR Vulnerabilities'
    nessus      = 'Nessus Network Vulnerability Scan'
    blumira     = 'Blumira Weekly Report of Events'
}

function Get-Score {
    param([object]$Finding)
    $value = 0.0
    if ([double]::TryParse([string]$Finding.cvss, [ref]$value)) { return $value }
    return 0.0
}

function Get-Lane {
    param([object]$Finding)

    $status = ([string]$Finding.status).Trim().ToLowerInvariant()
    if ($status -in @('resolved','closed','false positive','no action needed','risk accepted')) { return 'wait' }

    $severity = ([string]$Finding.severity).ToUpperInvariant()
    $score = Get-Score $Finding
    $text = (@($Finding.title,$Finding.description,$Finding.product,$Finding.host,$Finding.asset,$Finding.fix) -join ' ').ToLowerInvariant()
    $host = (@($Finding.host,$Finding.asset) -join ' ').ToLowerInvariant()

    if ($Finding.in_kev -or $severity -eq 'CRITICAL') { return 'now' }
    if ($severity -eq 'HIGH' -and ($score -eq 0 -or $score -ge 7)) { return 'now' }

    $urgent = @('rce','remote code','code execution','zerologon','log4shell','log4j','eternalblue','proxylogon','ransomware','mfa fatigue','impossible travel','password spray','domain controller','netlogon','privilege escalation','authentication bypass','vpn','rdp','exchange','brute force')
    foreach ($keyword in $urgent) { if ($text.Contains($keyword)) { return 'now' } }

    foreach ($hint in @('dc','domain','vpn','exchange','adfs','firewall','fw-','id-')) {
        if ($host.Contains($hint) -and $severity -in @('HIGH','CRITICAL','MEDIUM')) { return 'now' }
    }
    return 'wait'
}

function Get-VerifiedFix {
    param([object]$Finding)

    if ($Finding.in_kev -and $Finding.kev -and $Finding.kev.required_action) {
        $due = if ($Finding.kev.due_date) { " Federal due date $($Finding.kev.due_date)." } else { '' }
        return "CISA KEV required action: $($Finding.kev.required_action)$due"
    }
    if ($Finding.fix -and ([string]$Finding.fix).Trim().ToLowerInvariant() -notin @('n/a','none','unknown')) { return [string]$Finding.fix }
    if ($Finding.cves -and @($Finding.cves).Count -gt 0) { return "Patch or upgrade the affected product for $($Finding.cves[0]), then verify with a re-scan." }
    return 'Investigate with the asset owner, apply the vendor fix or configuration change, and verify closure.'
}

function Get-Schedule {
    param([object]$Finding)
    $today = Get-Date
    $severity = ([string]$Finding.severity).ToUpperInvariant()
    if ($Finding.in_kev -or $severity -eq 'CRITICAL') { return @{ priority='P1'; priority_label='P1 Immediate'; sla='7 days'; due=$today.AddDays(7).ToString('yyyy-MM-dd'); work='Investigate and contain first. Patch before the due date.' } }
    if ($Finding.lane -eq 'now' -or $severity -eq 'HIGH') { return @{ priority='P2'; priority_label='P2 This sprint'; sla='14 days'; due=$today.AddDays(14).ToString('yyyy-MM-dd'); work='Assign an owner and complete the fix in the next change window.' } }
    if ($severity -eq 'MEDIUM') { return @{ priority='P3'; priority_label='P3 Planned'; sla='30 days'; due=$today.AddDays(30).ToString('yyyy-MM-dd'); work='Schedule with the asset owner and verify on the next scan.' } }
    return @{ priority='P4'; priority_label='P4 Backlog'; sla='90 days'; due=$today.AddDays(90).ToString('yyyy-MM-dd'); work='Track in the quarterly hygiene window.' }
}

function New-ExecutiveSummary {
    param([object[]]$Findings,[string]$Source,[string]$InputName)

    foreach ($finding in $Findings) {
        $finding.lane = Get-Lane $finding
        $finding.verified_fix = Get-VerifiedFix $finding
        $finding.schedule = Get-Schedule $finding
        $finding.priority = $finding.schedule.priority
        $finding.due = $finding.schedule.due
    }

    $severity = [ordered]@{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; UNKNOWN=0 }
    foreach ($finding in $Findings) {
        $key = ([string]$finding.severity).ToUpperInvariant()
        if ($severity.Contains($key)) { $severity[$key]++ } else { $severity.UNKNOWN++ }
    }

    $ranked = @($Findings | Sort-Object @{Expression={if ($_.lane -eq 'now') { 0 } else { 1 }}}, @{Expression={if ($_.in_kev) { 0 } else { 1 }}}, @{Expression={Get-Score $_};Descending=$true})
    $hosts = @($Findings | ForEach-Object { if ($_.host) { $_.host } elseif ($_.asset) { $_.asset } else { 'Unknown' } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ name=$_.Name; count=$_.Count } })
    $cves = @($Findings | ForEach-Object { $_.cves } | Where-Object { $_ } | Sort-Object -Unique)

    return [ordered]@{
        generated=(Get-Date -Format 'yyyy-MM-dd HH:mm'); source=$Source; source_label=$script:SourceLabels[$Source]; input_name=$InputName
        total=$Findings.Count; now_count=@($ranked | Where-Object lane -eq 'now').Count; wait_count=@($ranked | Where-Object lane -eq 'wait').Count
        severity=$severity; unique_cves=$cves; unique_hosts=@($hosts | Where-Object name -ne 'Unknown').Count
        host_counts=$hosts; kev_count=@($Findings | Where-Object in_kev).Count; findings=$ranked
    }
}

function ConvertTo-PdfText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $Text = $Text -replace '\\', '\\'
    $Text = $Text -replace '\(', '\('
    $Text = $Text -replace '\)', '\)'
    return ($Text -replace '[^\x20-\x7E]', ' ')
}

function Export-ExecutivePdf {
    param([System.Collections.IDictionary]$Summary,[string]$Path)

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(
        'TIMES MICROWAVE SYSTEMS',
        'Cybersecurity Executive Brief',
        'Prepared by Devon Brown',
        'Title: Network Security Engineer',
        '',
        "Source: $($Summary.source_label)",
        "Input: $($Summary.input_name)",
        "Generated: $($Summary.generated)",
        "Findings: $($Summary.total)   NOW: $($Summary.now_count)   WAIT: $($Summary.wait_count)",
        "KEV: $($Summary.kev_count)",
        ''
    )) { $lines.Add($line) }

    foreach ($finding in @($Summary.findings)) {
        $lines.Add("[$($finding.severity)] $($finding.title)")
        $lines.Add("Host: $($finding.host)")
        $lines.Add("Lane: $($finding.lane)   Priority: $($finding.priority)   Due: $($finding.due)")
        $lines.Add("Fix: $($finding.verified_fix)")
        $lines.Add('')
    }

    $pageLines = 44
    $pages = @()
    for ($index=0; $index -lt $lines.Count; $index += $pageLines) {
        $end = [Math]::Min($index + $pageLines - 1, $lines.Count - 1)
        $pages += ,(@($lines[$index..$end]))
    }
    if ($pages.Count -eq 0) { $pages = @(,@('No findings.')) }

    $objects = [System.Collections.Generic.List[string]]::new()
    $objects.Add('<< /Type /Catalog /Pages 2 0 R >>')
    $pageObjectIds = @()
    $contentObjectIds = @()
    $nextId = 4
    foreach ($page in $pages) {
        $pageObjectIds += $nextId
        $contentObjectIds += ($nextId + 1)
        $nextId += 2
    }
    $kids = ($pageObjectIds | ForEach-Object { "$_ 0 R" }) -join ' '
    $objects.Add("<< /Type /Pages /Kids [$kids] /Count $($pages.Count) >>")
    $objects.Add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')

    for ($p=0; $p -lt $pages.Count; $p++) {
        $stream = "BT`n/F1 10 Tf`n50 750 Td`n"
        foreach ($line in $pages[$p]) { $stream += "($(ConvertTo-PdfText $line)) Tj`n0 -16 Td`n" }
        $stream += 'ET'
        $length = [Text.Encoding]::ASCII.GetByteCount($stream)
        $objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents $($contentObjectIds[$p]) 0 R >>")
        $objects.Add("<< /Length $length >>`nstream`n$stream`nendstream")
    }

    $pdf = "%PDF-1.4`n"
    $offsets = [System.Collections.Generic.List[int]]::new(); $offsets.Add(0)
    for ($i=0; $i -lt $objects.Count; $i++) {
        $offsets.Add([Text.Encoding]::ASCII.GetByteCount($pdf))
        $pdf += "$($i + 1) 0 obj`n$($objects[$i])`nendobj`n"
    }
    $xref = [Text.Encoding]::ASCII.GetByteCount($pdf)
    $pdf += "xref`n0 $($objects.Count + 1)`n0000000000 65535 f `n"
    for ($i=1; $i -lt $offsets.Count; $i++) { $pdf += "$($offsets[$i].ToString('0000000000')) 00000 n `n" }
    $pdf += "trailer`n<< /Size $($objects.Count + 1) /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n"

    [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes($pdf))
    $signature = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path), 0, 5)
    if ($signature -ne '%PDF-') { throw "PDF validation failed: $Path" }
}
