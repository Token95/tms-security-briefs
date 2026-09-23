Set-StrictMode -Version Latest
$script:SourceLabels=@{crowdstrike='Crowdstrike EDR Vulnerabilities';nessus='Nessus Network Vulnerability Scan';blumira='Blumira Weekly Report of Events'}
function New-ExecutiveSummary {param([object[]]$Findings,[string]$Source,[string]$InputName)
 foreach($f in $Findings){$s=([string]$f.severity).ToUpper();$f.lane=if($s -in @('CRITICAL','HIGH')){'now'}else{'wait'};$f.verified_fix=if($f.fix){$f.fix}elseif($f.cves){"Patch or upgrade the affected product for $($f.cves[0]) and verify with a re-scan."}else{'Investigate with the asset owner, apply the vendor fix, and verify closure.'};$f.priority=if($f.lane -eq 'now'){'P1'}else{'P3'}}
 $sev=[ordered]@{CRITICAL=0;HIGH=0;MEDIUM=0;LOW=0;INFO=0;UNKNOWN=0};foreach($f in $Findings){$k=([string]$f.severity).ToUpper();if($sev.Contains($k)){$sev[$k]++}else{$sev.UNKNOWN++}}
 return [ordered]@{generated=(Get-Date -Format 'yyyy-MM-dd HH:mm');source=$Source;source_label=$script:SourceLabels[$Source];input_name=$InputName;total=$Findings.Count;now_count=@($Findings|? lane -eq now).Count;wait_count=@($Findings|? lane -eq wait).Count;severity=$sev;kev_count=0;findings=$Findings}
}
function Convert-PdfText([string]$s){return (($s -replace '\\','\\' -replace '\(','\(' -replace '\)','\)') -replace '[^\x20-\x7E]',' ')}
function Export-ExecutivePdf {param([hashtable]$Summary,[string]$Path)
 $lines=@('TIMES MICROWAVE SYSTEMS','Cybersecurity Executive Brief','Prepared by Devon Brown','Title: Network Security Engineer','',"Source: $($Summary.source_label)","Input: $($Summary.input_name)","Generated: $($Summary.generated)","Findings: $($Summary.total)   NOW: $($Summary.now_count)   WAIT: $($Summary.wait_count)",'')
 foreach($f in $Summary.findings){$lines += "[$($f.severity)] $($f.title) | Host: $($f.host) | Lane: $($f.lane)";$lines += "Fix: $($f.verified_fix)";$lines += ''}
 $stream="BT`n/F1 11 Tf`n50 750 Td`n";foreach($line in $lines){$stream+="($(Convert-PdfText $line)) Tj`n0 -16 Td`n"};$stream+='ET'
 $objects=@("<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>","<< /Length $([Text.Encoding]::ASCII.GetByteCount($stream)) >>`nstream`n$stream`nendstream")
 $pdf='%PDF-1.4`n';$offsets=@(0);for($i=0;$i -lt $objects.Count;$i++){$offsets+=[Text.Encoding]::ASCII.GetByteCount($pdf);$pdf+=("{0} 0 obj`n{1}`nendobj`n" -f ($i+1),$objects[$i])};$xref=[Text.Encoding]::ASCII.GetByteCount($pdf);$pdf+="xref`n0 $($objects.Count+1)`n0000000000 65535 f `n";for($i=1;$i -lt $offsets.Count;$i++){$pdf+="$($offsets[$i].ToString('0000000000')) 00000 n `n"};$pdf+="trailer`n<< /Size $($objects.Count+1) /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n";[IO.File]::WriteAllBytes($Path,[Text.Encoding]::ASCII.GetBytes($pdf))
}
