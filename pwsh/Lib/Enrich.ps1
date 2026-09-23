Set-StrictMode -Version Latest
function Add-Enrichment {param([object[]]$Findings,[switch]$Offline)
 foreach($f in $Findings){$score=0.0;[double]::TryParse([string]$f.cvss,[ref]$score)|Out-Null;$sev=([string]$f.severity).ToUpper();if(!$sev){$sev=if($score -ge 9){'CRITICAL'}elseif($score -ge 7){'HIGH'}elseif($score -ge 4){'MEDIUM'}elseif($score -gt 0){'LOW'}else{'UNKNOWN'}};$f.severity=$sev;$f.in_kev=$false;$f.nvd=$null;$f.kev=$null};return $Findings}
