Set-StrictMode -Version Latest

$script:SourceLabels = @{
    'crowdstrike' = 'Crowdstrike EDR Vulnerabilities'
    'nessus' = 'Nessus Network Vulnerability Scan'
    'blumira' = 'Blumira Weekly Report of Events'
}

function Get-SeverityRank {
    param([string]$Severity)

    $map = @{
        'CRITICAL' = 0
        'HIGH' = 1
        'MEDIUM' = 2
        'LOW' = 3
        'INFO' = 4
    }
    return [int]($map[$Severity] ?? 5)
}

function Get-Score {
    param([psobject]$Finding)

    try { return [double]$Finding.cvss } catch { return 0.0 }
}

function Get-Lane {
    param([psobject]$Finding)

    $status = ([string]$Finding.status).ToLowerInvariant()
    if ($status -in @('resolved','closed','false positive','no action needed','risk accepted')) {
        return 'wait'
    }

    $sev = ([string]$Finding.severity).ToUpperInvariant()
    $score = Get-Score -Finding $Finding
    $blob = @(
        $Finding.title,
        $Finding.description,
        $Finding.product,
        $Finding.host,
        $Finding.asset,
        $Finding.fix
    ) -join ' '
    $blob = $blob.ToLowerInvariant()
    $host = ([string]($Finding.host + $Finding.asset)).ToLowerInvariant()

    if ($Finding.in_kev) { return 'now' }
    if ($sev -eq 'CRITICAL') { return 'now' }
    if ($sev -eq 'HIGH' -and ($score -eq 0 -or $score -ge 7.0)) { return 'now' }

    $keywords = @(
        'rce','remote code','code execution','zerologon','log4shell','log4j','eternalblue',
        'proxylogon','ransomware','mfa fatigue','impossible travel','password spray',
        'domain controller','netlogon','privilege','elevation of privilege','authentication bypass',
        'vpn','rdp','exchange','brute force'
    )
    foreach ($key in $keywords) {
        if ($blob.Contains($key)) { return 'now' }
    }

    $hostHints = @('dc','domain','vpn','exchange','adfs','firewall','fw-','id-')
    foreach ($hint in $hostHints) {
        if ($host.Contains($hint) -and $sev -in @('HIGH','CRITICAL','MEDIUM')) { return 'now' }
    }

    return 'wait'
}

function Get-VerifiedFix {
    param([psobject]$Finding)

    if ($Finding.in_kev -and $Finding.kev) {
        $action = [string]$Finding.kev.required_action
        if ($action) {
            $due = [string]$Finding.kev.due_date
            $suffix = if ($due) { " Federal due date $due." } else { '' }
            return "CISA KEV required action: $action$suffix"
        }
    }

    $srcFix = ([string]$Finding.fix).Trim()
    if ($srcFix -and $srcFix.ToLower() -notin @('n/a','none','unknown')) {
        return $srcFix
    }

    if ($Finding.nvd -and $Finding.nvd.fix_links) {
        return "Apply the vendor patch in the NVD advisory: " + (($Finding.nvd.fix_links | Select-Object -First 2) -join '; ')
    }

    $title = ([string]$Finding.title).ToLowerInvariant()
    $source = [string]$Finding.source
    if ($source -eq 'blumira') {
        return "Run the Blumira finding workflow to the end: confirm whether the activity is expected, contain the account or host if it is not, then set the resolution type (Valid / False positive / No action needed / Risk accepted)."
    }

    if ($title.Contains('ssl') -or $title.Contains('tls') -or $title.Contains('poodle') -or $title.Contains('beast')) {
        return 'Disable SSLv3 and TLS 1.0/1.1. Require TLS 1.2+ with AEAD ciphers. Recheck after the change window.'
    }
    if ($title.Contains('smb') -or $title.Contains('445')) {
        return 'Install the current Microsoft SMB/Netlogon updates, require SMB signing, and restrict TCP 445 to trusted subnets.'
    }
    if ($Finding.cves.Count -gt 0) {
        $cve = $Finding.cves[0]
        return "Patch or upgrade the affected product for $cve. If a patch is not available, isolate the host, apply the vendor workaround, and schedule a verified re-scan."
    }
    return 'Investigate with the asset owner. Apply the vendor fix or configuration change, then re-scan or re-check logs to verify the finding is closed.'
}

function Get-Schedule {
    param([psobject]$Finding)

    $today = Get-Date
    $status = ([string]$Finding.status).ToLowerInvariant()
    $sev = ([string]$Finding.severity).ToUpperInvariant()
    $lane = $Finding.lane
    $source = [string]$Finding.source
    $blob = @($Finding.title, $Finding.description, $Finding.product) -join ' '
    $blob = $blob.ToLowerInvariant()

    if ($status -in @('resolved','closed','false positive','no action needed','risk accepted')) {
        $due = $today.AddDays(7)
        return @{
            priority = 'P4'
            priority_label = 'P4 Verify only'
            sla = '7 days'
            due = $due.ToString('yyyy-MM-dd')
            work = 'Confirm the closure in the source tool. No new change required unless it reopens.'
        }
    }

    if ($Finding.in_kev -or $sev -eq 'CRITICAL' -or ($source -eq 'blumira' -and ($blob.Contains('mfa fatigue') -or $blob.Contains('impossible travel') -or $blob.Contains('ransomware')))) {
        $due = if ($source -eq 'blumira') { $today.AddDays(2) } else { $today.AddDays(7) }
        $sla = if ($source -eq 'blumira') { '48 hours' } else { '7 days' }
        return @{
            priority = 'P1'
            priority_label = 'P1 Immediate'
            sla = $sla
            due = $due.ToString('yyyy-MM-dd')
            work = 'Investigate and contain first. Patch or revoke access before the due date.'
        }
    }

    if ($lane -eq 'now' -or $sev -eq 'HIGH') {
        $due = $today.AddDays(14)
        return @{
            priority = 'P2'
            priority_label = 'P2 This sprint'
            sla = '14 days'
            due = $due.ToString('yyyy-MM-dd')
            work = 'Owner assigned this week. Complete the fix in the next change window.'
        }
    }

    if ($sev -eq 'MEDIUM') {
        $due = $today.AddDays(30)
        return @{
            priority = 'P3'
            priority_label = 'P3 Planned'
            sla = '30 days'
            due = $due.ToString('yyyy-MM-dd')
            work = 'Schedule with the asset owner. Do not block production work.'
        }
    }

    $due = $today.AddDays(90)
    return @{
        priority = 'P4'
        priority_label = 'P4 Backlog'
        sla = '90 days'
        due = $due.ToString('yyyy-MM-dd')
        work = 'Track in the quarterly hygiene window and verify on the next scan.'
    }
}

function New-ExecutiveSummary {
    param(
        [psobject[]]$Findings,
        [string]$Source,
        [string]$InputName
    )

    foreach ($f in $Findings) {
        $f.lane = Get-Lane -Finding $f
        $f.verified_fix = Get-VerifiedFix -Finding $f
        $sched = Get-Schedule -Finding $f
        $f.schedule = $sched
        $f.priority = $sched.priority
        $f.due = $sched.due
    }

    $sev = [ordered]@{
        'CRITICAL' = 0
        'HIGH' = 0
        'MEDIUM' = 0
        'LOW' = 0
        'INFO' = 0
        'UNKNOWN' = 0
    }

    foreach ($f in $Findings) {
        $key = [string]$f.severity.ToUpperInvariant()
        if ($sev.Contains($key)) {
            $sev[$key] = [int]($sev[$key] + 1)
        }
        else {
            $sev['UNKNOWN'] = [int]($sev['UNKNOWN'] + 1)
        }
    }

    $hosts = @{}
    foreach ($f in $Findings) {
        $h = [string]($f.host + $f.asset)
        if (-not $h) { $h = 'Unknown' }
        $hosts[$h] = [int]($hosts[$h] + 1)
    }

    $cves = @()
    foreach ($f in $Findings) {
        foreach ($cve in @($f.cves)) {
            $cves += $cve
        }
    }
    $uniqueCves = @($cves | Sort-Object -Unique)

    $ranked = $Findings | Sort-Object `
        @{Expression = { if ($_.lane -eq 'now') { 0 } else { 1 } }}, `
        @{Expression = { if ($_.in_kev) { 0 } else { 1 } }}, `
        @{Expression = { Get-Score -Finding $_ }; Descending = $true }

    $nowFindings = @($ranked | Where-Object { $_.lane -eq 'now' })
    $waitFindings = @($ranked | Where-Object { $_.lane -ne 'now' })
    $kevCount = @($Findings | Where-Object { $_.in_kev }).Count

    $workPlan = @()
    foreach ($f in $ranked) {
        $workPlan += [pscustomobject]@{
            title = $f.title
            severity = $f.severity
            action = $f.verified_fix
            cves = @($f.cves)
            kev = $f.in_kev
            host = $f.host
            lane = $f.lane
            priority = $f.priority
            priority_label = $f.schedule.priority_label
            sla = $f.schedule.sla
            due = $f.schedule.due
            work = $f.schedule.work
        }
    }

    return [ordered]@{
        generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        source = $Source
        source_label = $script:SourceLabels[$Source]
        input_name = $InputName
        total = $Findings.Count
        now_count = $nowFindings.Count
        wait_count = $waitFindings.Count
        severity = $sev
        unique_cves = $uniqueCves
        unique_hosts = @($hosts.Keys | Where-Object { $_ -and $_ -ne 'Unknown' }).Count
        host_counts = @($hosts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)
        kev_count = $kevCount
        top_now = $nowFindings
        top_wait = $waitFindings
        work_plan = $workPlan
        findings = $Findings
    }
}

function Get-DefaultReportHeader {
    param(
        [string]$Title = 'Cybersecurity Executive Brief'
    )

    $name = 'Token95'
    $role = 'Security Analyst'
    $logoPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets/tms_header.svg'

    $headerLines = @(
        'TIMES MICROWAVE SYSTEMS',
        'Cybersecurity Executive Brief',
        "Prepared by $name | $role",
        '---'
    )

    if (Test-Path $logoPath) {
        $headerLines = @(
            "Logo: $logoPath",
            'TIMES MICROWAVE SYSTEMS',
            $Title,
            "Prepared by $name | $role"
        )
    }

    return $headerLines
}

function Export-ExecutiveJson {
    param(
        [hashtable]$Summary,
        [string]$Path
    )

    $payload = [ordered]@{}
    foreach ($k in $Summary.Keys) {
        if ($k -ne 'findings') {
            $payload[$k] = $Summary[$k]
        }
    }

    $slim = @()
    foreach ($f in $Summary.findings) {
        $slim += [ordered]@{
            source = $f.source
            title = $f.title
            severity = $f.severity
            cvss = $f.cvss
            cves = @($f.cves)
            host = $f.host
            product = $f.product
            description = if ($f.description) { $f.description.Substring(0, [Math]::Min(500, $f.description.Length)) } else { '' }
            fix = $f.fix
            lane = $f.lane
            priority = $f.priority
            due = $f.due
            verified_fix = $f.verified_fix
            in_kev = $f.in_kev
            kev = $f.kev
        }
    }

    $payload['findings'] = $slim
    $payload | ConvertTo-Json -Depth 30 | Set-Content -Path $Path -Encoding utf8
}

function Export-ExecutiveCsv {
    param(
        [psobject[]]$Findings,
        [string]$Path
    )

    $rows = @()
    foreach ($f in $Findings) {
        $fixText = [string]($f.fix)
        $descText = [string]($f.description)
        $verifiedText = [string]($f.verified_fix)

        $rows += [pscustomobject]@{
            source = $f.source
            title = $f.title
            severity = $f.severity
            cvss = if ($null -ne $f.cvss) { $f.cvss } else { '' }
            cves = (($f.cves | ForEach-Object { [string]$_ }) -join ';')
            host = if ($f.host) { $f.host } else { $f.asset }
            product = $f.product
            lane = if ($f.lane -eq 'now') { 'NOW' } else { 'WAIT' }
            priority = $f.priority
            due = $f.due
            sla = $f.schedule.sla
            in_kev = if ($f.in_kev) { 'YES' } else { '' }
            verified_fix = ($verifiedText -replace "`r"," " -replace "`n"," ").Substring(0, [Math]::Min(400, ($verifiedText -replace "`r"," " -replace "`n"," ").Length))
            fix = ($fixText -replace "`r"," " -replace "`n"," ").Substring(0, [Math]::Min(400, ($fixText -replace "`r"," " -replace "`n"," ").Length))
            description = ($descText -replace "`r"," " -replace "`n"," ").Substring(0, [Math]::Min(400, ($descText -replace "`r"," " -replace "`n"," ").Length))
        }
    }

    $rows | Export-Csv -Path $Path -NoTypeInformation
}

function Export-ExecutivePdf {
    param(
        [hashtable]$Summary,
        [string]$Path
    )

    $headerLines = Get-DefaultReportHeader -Title 'Cybersecurity Executive Brief'
    $lines = @()
    foreach ($line in $headerLines) { $lines += $line }
    $lines += ''
    $lines += "Source: $($Summary.source_label)"
    $lines += "Generated: $($Summary.generated)"
    $lines += "Rows: $($Summary.total)"
    $lines += "Now: $($Summary.now_count)"
    $lines += "Wait: $($Summary.wait_count)"
    $lines += "KEV: $($Summary.kev_count)"
    $lines += ''
    foreach ($f in $Summary.findings) {
        $lines += "- $($f.title) [$($f.severity)] Host=$($f.host)"
    }

    $textPath = $Path -replace '\.pdf$', '.txt'
    $lines | Set-Content -Path $textPath -Encoding utf8
    Write-Host "PDF export requested; using text fallback because PowerShell has no native PDF engine. File written at $textPath"
}
