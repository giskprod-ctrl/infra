param(
    [Parameter(Mandatory=$true)]
    [string]$SamplePath,
    [int]$TimeoutSeconds = 120,
    [switch]$CollectMemory
)

$ErrorActionPreference = 'Stop'
$resultsDir = 'C:\results'
$logFile = Join-Path $resultsDir 'autorun.log'
$summaryFile = Join-Path $resultsDir 'autorun-summary.json'
$procmonLog = Join-Path $resultsDir 'procmon.pml'
$procmonCsv = Join-Path $resultsDir 'procmon.csv'
$sysmonExport = Join-Path $resultsDir 'sysmon.evtx'
$memoryDump = Join-Path $resultsDir 'memory.dmp'

$procmonCandidates = @(
    $env:PROCmonPath,
    'C:\Program Files\Sysinternals\Procmon.exe',
    'C:\Tools\Sysinternals\Procmon.exe',
    'C:\Program Files (x86)\SysinternalsSuite\Procmon.exe'
) | Where-Object { $_ -and (Test-Path $_) }
$procDumpCandidates = @(
    $env:ProcDumpPath,
    'C:\Program Files\Sysinternals\procdump.exe',
    'C:\Tools\Sysinternals\procdump.exe',
    'C:\Program Files (x86)\SysinternalsSuite\procdump.exe'
) | Where-Object { $_ -and (Test-Path $_) }

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    $entry = "[$timestamp] $Message"
    Write-Host $entry
    Add-Content -Path $logFile -Value $entry
}

if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
}

Write-Log "Autorun invoked for $SamplePath with timeout $TimeoutSeconds seconds. CollectMemory=$CollectMemory"

if (-not (Test-Path $SamplePath)) {
    Write-Log "Sample not found: $SamplePath"
    throw "SamplePath not found"
}

$procmonProc = $null
if ($procmonCandidates.Count -gt 0) {
    $procmonExe = $procmonCandidates[0]
    Write-Log "Starting Procmon from $procmonExe"
    Start-Process -FilePath $procmonExe -ArgumentList "/AcceptEula","/Quiet","/BackingFile","$procmonLog" -PassThru | Out-Null
} else {
    Write-Log "Procmon not found; skipping"
}

# Ensure Sysmon logs flushed if service is installed
try {
    if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
        Write-Log "Sysmon detected; exporting events"
        wevtutil epl Microsoft-Windows-Sysmon/Operational $sysmonExport /ow:true
    }
} catch {
    Write-Log "Failed to export Sysmon events: $_"
}

$workingDir = Split-Path -Path $SamplePath -Parent
if (-not $workingDir) { $workingDir = 'C:\' }

$stdoutFile = Join-Path $resultsDir 'stdout.log'
$stderrFile = Join-Path $resultsDir 'stderr.log'
if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force }
if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force }
$startArgs = @{
    FilePath = $SamplePath
    WorkingDirectory = $workingDir
    PassThru = $true
    WindowStyle = 'Hidden'
    RedirectStandardOutput = $stdoutFile
    RedirectStandardError = $stderrFile
}
try {
    $process = Start-Process @startArgs
    Write-Log "Sample started with PID $($process.Id)"
} catch {
    Write-Log "Failed to start sample: $_"
    throw
}

$dumpDelay = [Math]::Min([Math]::Max([int]($TimeoutSeconds * 0.1), 2), 30)
if ($CollectMemory -or $env:AUTORUN_FORCE_DUMP -eq '1') {
    Start-Sleep -Seconds $dumpDelay
    if (-not $process.HasExited) {
        if ($procDumpCandidates.Count -gt 0) {
            $dumpExe = $procDumpCandidates[0]
            try {
                Write-Log "Running procdump for PID $($process.Id)"
                Start-Process -FilePath $dumpExe -ArgumentList '-ma', $process.Id, $memoryDump -Wait -NoNewWindow | Out-Null
            } catch {
                Write-Log "procdump failed: $_"
            }
        } else {
            Write-Log "ProcDump not found; skipping memory dump"
        }
    } else {
        Write-Log "Process exited before memory dump"
    }
}

$completed = $true
try {
    Wait-Process -Id $process.Id -Timeout $TimeoutSeconds -ErrorAction Stop
} catch {
    $completed = $false
    Write-Log "Timeout reached; terminating PID $($process.Id)"
    try { Stop-Process -Id $process.Id -Force } catch { Write-Log "Failed to kill process: $_" }
}

try { $process.WaitForExit() } catch { }

if (-not (Test-Path $stdoutFile)) { New-Item -ItemType File -Path $stdoutFile -Force | Out-Null }
if (-not (Test-Path $stderrFile)) { New-Item -ItemType File -Path $stderrFile -Force | Out-Null }

if ($procmonCandidates.Count -gt 0) {
    try {
        Write-Log "Stopping Procmon capture"
        Start-Process -FilePath $procmonCandidates[0] -ArgumentList '/Terminate' -Wait -NoNewWindow | Out-Null
        if (Test-Path $procmonLog) {
            Start-Process -FilePath $procmonCandidates[0] -ArgumentList '/OpenLog',"$procmonLog","/SaveAs",$procmonCsv,"/Quiet","/Minimized" -Wait -NoNewWindow | Out-Null
        }
    } catch {
        Write-Log "Failed to stop Procmon: $_"
    }
}

$exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
$summary = [ordered]@{
    sample = $SamplePath
    pid = $process.Id
    exitCode = $exitCode
    completed = $completed
    timeoutSeconds = $TimeoutSeconds
    collectMemory = [bool]($CollectMemory -or $env:AUTORUN_FORCE_DUMP -eq '1')
    stdoutLog = Split-Path -Leaf $stdoutFile
    stderrLog = Split-Path -Leaf $stderrFile
    procmonLog = Split-Path -Leaf $procmonLog
    procmonCsv = Split-Path -Leaf $procmonCsv
    memoryDump = if (Test-Path $memoryDump) { Split-Path -Leaf $memoryDump } else { $null }
    generatedAt = (Get-Date).ToString('o')
}

$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryFile -Encoding UTF8
Write-Log "Summary written to $summaryFile"

Write-Log "Shutting down in 10 seconds"
Start-Process -FilePath 'shutdown.exe' -ArgumentList '/s','/t','10' -WindowStyle Hidden
