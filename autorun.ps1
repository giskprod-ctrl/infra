param(
    [Parameter(Mandatory=$true)]
    [string]$SamplePath,
    [int]$TimeoutSeconds = 120,
    [switch]$CollectMemory,
    [switch]$IsDll,
    [string[]]$DllExports = @(),
    [string]$HeuristicScore
)

$ErrorActionPreference = 'Stop'

$resultsDir = 'C:\results'
$logFile = Join-Path $resultsDir 'autorun.log'
$summaryFile = Join-Path $resultsDir 'autorun-summary.json'
$procmonLog = Join-Path $resultsDir 'procmon.pml'
$procmonCsv = Join-Path $resultsDir 'procmon.csv'
$sysmonPre = Join-Path $resultsDir 'sysmon-pre.evtx'
$sysmonPost = Join-Path $resultsDir 'sysmon-post.evtx'
$memoryRoot = $resultsDir
$etwDir = Join-Path $resultsDir 'etw'
$stdoutDefault = Join-Path $resultsDir 'stdout.log'
$stderrDefault = Join-Path $resultsDir 'stderr.log'

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

$registryRoots = @(
    @{ Name = 'HKCU_Run'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
    @{ Name = 'HKCU_RunOnce'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Name = 'HKLM_Run'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Name = 'HKLM_RunOnce'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
)

if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
}
if (-not (Test-Path $etwDir)) {
    New-Item -ItemType Directory -Path $etwDir | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    $entry = "[$timestamp] $Message"
    Write-Host $entry
    Add-Content -Path $logFile -Value $entry
}

if (-not (Test-Path $SamplePath)) {
    Write-Log "Sample not found: $SamplePath"
    throw "SamplePath not found"
}

Write-Log "Autorun invoked for $SamplePath (IsDll=$($IsDll.IsPresent)) with timeout $TimeoutSeconds seconds. CollectMemory=$($CollectMemory.IsPresent)"

$heuristicScoreValue = $null
if ($HeuristicScore) {
    try {
        $heuristicScoreValue = [double]$HeuristicScore
    } catch {
        Write-Log "Failed to parse heuristic score '$HeuristicScore'"
    }
}

function Get-SystemSnapshot {
    param([string]$Phase)
    Write-Log "Capturing $Phase system snapshot"
    $snapshot = [ordered]@{
        phase = $Phase
        capturedAt = (Get-Date).ToString('o')
        processes = @()
        services = @()
        scheduledTasks = @()
        tcpConnections = @()
        registry = @()
    }
    try {
        $snapshot.processes = @(Get-Process | Select-Object Name,Id,Path,StartTime,SessionId)
    } catch {
        Write-Log "Process enumeration failed: $_"
    }
    try {
        $snapshot.services = @(Get-Service | Select-Object Name,Status,StartType)
    } catch {
        Write-Log "Service enumeration failed: $_"
    }
    try {
        $snapshot.scheduledTasks = @(Get-ScheduledTask | Select-Object TaskName,TaskPath,State)
    } catch {
        Write-Log "Scheduled task enumeration failed: $_"
    }
    try {
        $snapshot.tcpConnections = @(Get-NetTCPConnection -State Established,Listen -ErrorAction Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
    } catch {
        Write-Log "Network snapshot failed: $_"
    }
    $registryEntries = @()
    foreach ($entry in $registryRoots) {
        try {
            $values = Get-ItemProperty -Path $entry.Path -ErrorAction Stop
            foreach ($property in $values.PSObject.Properties) {
                if ($property.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $registryEntries += [pscustomobject]@{
                    Hive = $entry.Name
                    Name = $property.Name
                    Value = "$($property.Value)"
                }
            }
        } catch {
            Write-Log "Registry snapshot failed for $($entry.Path): $_"
        }
    }
    $snapshot.registry = $registryEntries
    return $snapshot
}

function Compare-SystemSnapshot {
    param($Pre,$Post)
    $diff = [ordered]@{
        processesStarted = @()
        processesStopped = @()
        servicesDelta = @()
        scheduledTasksNew = @()
        scheduledTasksRemoved = @()
        registryAdded = @()
        registryRemoved = @()
    }

    $preProcMap = @{}
    foreach ($item in $Pre.processes) {
        $key = "{0}|{1}|{2}" -f $item.Id,$item.Name,$item.Path
        $preProcMap[$key] = $item
    }
    $postProcMap = @{}
    foreach ($item in $Post.processes) {
        $key = "{0}|{1}|{2}" -f $item.Id,$item.Name,$item.Path
        $postProcMap[$key] = $item
    }
    $procCompare = Compare-Object -ReferenceObject $preProcMap.Keys -DifferenceObject $postProcMap.Keys -PassThru
    foreach ($entry in $procCompare) {
        if ($entry.SideIndicator -eq '=>') {
            $diff.processesStarted += $postProcMap[$entry]
        } elseif ($entry.SideIndicator -eq '<=') {
            $diff.processesStopped += $preProcMap[$entry]
        }
    }

    $preServices = @{}
    foreach ($svc in $Pre.services) { $preServices[$svc.Name] = $svc }
    $postServices = @{}
    foreach ($svc in $Post.services) { $postServices[$svc.Name] = $svc }
    foreach ($name in $postServices.Keys) {
        $svc = $postServices[$name]
        if ($preServices.ContainsKey($name)) {
            if ($preServices[$name].Status -ne $svc.Status) {
                $diff.servicesDelta += [pscustomobject]@{ Name = $name; From = $preServices[$name].Status; To = $svc.Status }
            }
        } else {
            $diff.servicesDelta += [pscustomobject]@{ Name = $name; From = 'NotPresent'; To = $svc.Status }
        }
    }
    foreach ($name in $preServices.Keys) {
        if (-not $postServices.ContainsKey($name)) {
            $diff.servicesDelta += [pscustomobject]@{ Name = $name; From = $preServices[$name].Status; To = 'Removed' }
        }
    }

    $preTasks = $Pre.scheduledTasks | ForEach-Object { "{0}|{1}" -f $_.TaskPath, $_.TaskName }
    $postTasks = $Post.scheduledTasks | ForEach-Object { "{0}|{1}" -f $_.TaskPath, $_.TaskName }
    $taskCompare = Compare-Object -ReferenceObject $preTasks -DifferenceObject $postTasks -PassThru
    foreach ($entry in $taskCompare) {
        $parts = $entry -split '\|',2
        if ($entry.SideIndicator -eq '=>') {
            $diff.scheduledTasksNew += [pscustomobject]@{ TaskPath = $parts[0]; TaskName = $parts[1] }
        } elseif ($entry.SideIndicator -eq '<=') {
            $diff.scheduledTasksRemoved += [pscustomobject]@{ TaskPath = $parts[0]; TaskName = $parts[1] }
        }
    }

    $preReg = $Pre.registry | ForEach-Object { "{0}|{1}|{2}" -f $_.Hive, $_.Name, $_.Value }
    $postReg = $Post.registry | ForEach-Object { "{0}|{1}|{2}" -f $_.Hive, $_.Name, $_.Value }
    $regCompare = Compare-Object -ReferenceObject $preReg -DifferenceObject $postReg -PassThru
    foreach ($entry in $regCompare) {
        $parts = $entry -split '\|',3
        $item = [pscustomobject]@{ Hive = $parts[0]; Name = $parts[1]; Value = $parts[2] }
        if ($entry.SideIndicator -eq '=>') {
            $diff.registryAdded += $item
        } elseif ($entry.SideIndicator -eq '<=') {
            $diff.registryRemoved += $item
        }
    }
    return $diff
}

function Start-EtwSessions {
    param([string]$Directory)
    $sessions = @(
        @{ Name = 'AutorunKernelProcess'; Provider = 'Microsoft-Windows-Kernel-Process'; File = 'kernel-process.etl' },
        @{ Name = 'AutorunKernelImage'; Provider = 'Microsoft-Windows-Kernel-Image'; File = 'kernel-image.etl' },
        @{ Name = 'AutorunKernelNetwork'; Provider = 'Microsoft-Windows-Kernel-Network'; File = 'kernel-network.etl' }
    )
    $started = @()
    foreach ($session in $sessions) {
        $output = Join-Path $Directory $session.File
        try {
            Write-Log "Starting ETW session $($session.Name)"
            & logman stop $session.Name -ets 2>$null | Out-Null
            & logman start $session.Name -p $session.Provider 0xffffffffffffffff 0 -bs 1024 -nb 16 256 -o $output -ets | Out-Null
            $started += [pscustomobject]@{ Name = $session.Name; Provider = $session.Provider; File = [IO.Path]::GetFileName($output) }
        } catch {
            Write-Log "Failed to start ETW session $($session.Name): $_"
        }
    }
    return $started
}

function Stop-EtwSessions {
    param([psobject[]]$Sessions)
    foreach ($session in $Sessions) {
        try {
            Write-Log "Stopping ETW session $($session.Name)"
            & logman stop $session.Name -ets | Out-Null
        } catch {
            Write-Log "Failed to stop ETW session $($session.Name): $_"
        }
    }
}

function Start-Procmon {
    param([string]$Executable,[string]$BackingFile)
    if (-not $Executable) { return $null }
    Write-Log "Starting Procmon from $Executable"
    Start-Process -FilePath $Executable -ArgumentList '/AcceptEula','/Quiet','/Minimized','/BackingFile',$BackingFile | Out-Null
    return $Executable
}

function Stop-Procmon {
    param([string]$Executable,[string]$BackingFile,[string]$CsvPath)
    if (-not $Executable) { return }
    try {
        Write-Log "Stopping Procmon capture"
        Start-Process -FilePath $Executable -ArgumentList '/Terminate' -Wait -NoNewWindow | Out-Null
        if (Test-Path $BackingFile) {
            Start-Process -FilePath $Executable -ArgumentList '/OpenLog',$BackingFile,'/SaveAs',$CsvPath,'/Quiet','/Minimized' -Wait -NoNewWindow | Out-Null
        }
    } catch {
        Write-Log "Failed to stop Procmon: $_"
    }
}
function Invoke-MemoryDump {
    param(
        [int]$Pid,
        [string]$Label,
        [string]$Suffix = 'dump'
    )
    $timestamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $dumpFile = Join-Path $memoryRoot ("memory-{0}-{1}-{2}.dmp" -f $Label,$Suffix,$timestamp)
    $artifact = $null
    if ($procDumpCandidates.Count -gt 0) {
        $dumpExe = $procDumpCandidates[0]
        try {
            Write-Log "Running ProcDump for PID $Pid -> $dumpFile"
            Start-Process -FilePath $dumpExe -ArgumentList '-ma', $Pid, $dumpFile -Wait -NoNewWindow | Out-Null
            if (Test-Path $dumpFile) {
                $artifact = [pscustomobject]@{ path = (Split-Path -Leaf $dumpFile); method = 'ProcDump'; pid = $Pid }
            }
        } catch {
            Write-Log "ProcDump failed for PID $Pid: $_"
        }
    }
    if (-not $artifact) {
        try {
            Write-Log "Falling back to comsvcs MiniDump for PID $Pid -> $dumpFile"
            Start-Process -FilePath 'rundll32.exe' -ArgumentList 'C:\Windows\System32\comsvcs.dll,MiniDump', $Pid, $dumpFile, 'full' -Wait -NoNewWindow | Out-Null
            if (Test-Path $dumpFile) {
                $artifact = [pscustomobject]@{ path = (Split-Path -Leaf $dumpFile); method = 'MiniDump'; pid = $Pid }
            }
        } catch {
            Write-Log "MiniDump fallback failed for PID $Pid: $_"
        }
    }
    if ($artifact) {
        $artifact | Add-Member -MemberType NoteProperty -Name capturedAt -Value (Get-Date).ToString('o')
    }
    return $artifact
}

function Capture-ModuleSnapshot {
    param([int]$Pid,[string]$Label)
    try {
        $process = Get-Process -Id $Pid -ErrorAction Stop
        $modules = @()
        foreach ($module in $process.Modules) {
            $modules += [pscustomobject]@{
                Name = $module.ModuleName
                FileName = $module.FileName
            }
        }
        $snapshot = [ordered]@{
            pid = $Pid
            label = $Label
            capturedAt = (Get-Date).ToString('o')
            modules = $modules
        }
        $path = Join-Path $resultsDir ("modules-{0}.json" -f $Label)
        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
        return $path
    } catch {
        Write-Log "Module snapshot failed for PID $Pid: $_"
        return $null
    }
}

function Capture-ChildProcesses {
    param([int]$ParentId,[string]$Label)
    $children = @()
    try {
        $items = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ParentId"
        foreach ($item in $items) {
            $children += [pscustomobject]@{
                label = $Label
                pid = $item.ProcessId
                name = $item.Name
                commandLine = $item.CommandLine
                creationTime = $item.CreationDate
            }
        }
    } catch {
        Write-Log "Failed to capture child processes for PID $ParentId: $_"
    }
    return $children
}

function Build-ExecutionPlan {
    param([string]$Sample,[bool]$DllMode,[string[]]$Exports)
    $plan = @()
    $workingDir = Split-Path -Path $Sample -Parent
    if (-not $workingDir) { $workingDir = 'C:\' }
    if ($DllMode) {
        $targets = if ($Exports.Count -gt 0) { $Exports } else { @('DllMain') }
        foreach ($export in $targets) {
            $label = ($export -replace '[^A-Za-z0-9_-]', '_')
            if (-not $label) { $label = 'export' }
            $plan += [pscustomobject]@{
                Label = $label
                Type = 'dllExport'
                Export = $export
                Command = 'rundll32.exe'
                Arguments = @("$Sample,$export")
                WorkingDirectory = $workingDir
            }
        }
    } else {
        $label = (Split-Path -Leaf $Sample) -replace '\.[^\.]+$', ''
        $label = ($label -replace '[^A-Za-z0-9_-]', '_')
        if (-not $label) { $label = 'exe' }
        $plan += [pscustomobject]@{
            Label = $label
            Type = 'exe'
            Export = $null
            Command = $Sample
            Arguments = @()
            WorkingDirectory = $workingDir
        }
    }
    return $plan
}

function Invoke-Execution {
    param(
        [pscustomobject]$Plan,
        [switch]$CollectMemory,
        [int]$TimeoutSeconds
    )
    $label = $Plan.Label
    $stdoutFile = Join-Path $resultsDir ("stdout-{0}.log" -f $label)
    $stderrFile = Join-Path $resultsDir ("stderr-{0}.log" -f $label)
    if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force }
    if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force }
    $args = $Plan.Arguments
    Write-Log "Launching $($Plan.Type) plan $label with command $($Plan.Command) $($args -join ' ')"
    $startTime = Get-Date
    $process = Start-Process -FilePath $Plan.Command -ArgumentList $args -WorkingDirectory $Plan.WorkingDirectory -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
    $moduleSnapshotPath = Capture-ModuleSnapshot -Pid $process.Id -Label $label
    $memoryArtifacts = @()
    $dumpDelay = [Math]::Min([Math]::Max([int]($TimeoutSeconds * 0.15), 3), 45)
    if ($CollectMemory) {
        Start-Sleep -Seconds $dumpDelay
        if (-not $process.HasExited) {
            $artifact = Invoke-MemoryDump -Pid $process.Id -Label $label -Suffix 'mid'
            if ($artifact) { $memoryArtifacts += $artifact }
        }
    }
    $completed = $true
    try {
        Wait-Process -Id $process.Id -Timeout $TimeoutSeconds -ErrorAction Stop
    } catch {
        $completed = $false
        Write-Log "Timeout reached for plan $label; terminating PID $($process.Id)"
        try { Stop-Process -Id $process.Id -Force } catch { Write-Log "Failed to terminate PID $($process.Id): $_" }
    }
    try { $process.WaitForExit() } catch { }
    if ($CollectMemory) {
        $artifact = Invoke-MemoryDump -Pid $process.Id -Label $label -Suffix 'final'
        if ($artifact) { $memoryArtifacts += $artifact }
    }
    $childProcesses = Capture-ChildProcesses -ParentId $process.Id -Label $label
    if ($CollectMemory -and $childProcesses.Count -gt 0) {
        foreach ($child in $childProcesses) {
            $childPid = [int]$child.pid
            $artifact = Invoke-MemoryDump -Pid $childPid -Label ("{0}-child{1}" -f $label,$childPid) -Suffix 'child'
            if ($artifact) { $memoryArtifacts += $artifact }
        }
    }
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    $exitCode = $null
    try { $exitCode = $process.ExitCode } catch { }
    $execution = [ordered]@{
        label = $label
        type = $Plan.Type
        export = $Plan.Export
        command = $Plan.Command
        arguments = $Plan.Arguments
        pid = $process.Id
        startedAt = $startTime.ToString('o')
        endedAt = $endTime.ToString('o')
        completed = $completed
        exitCode = $exitCode
        durationSeconds = [Math]::Round($duration, 2)
        stdoutLog = Split-Path -Leaf $stdoutFile
        stderrLog = Split-Path -Leaf $stderrFile
        memoryDumps = $memoryArtifacts
        moduleSnapshot = if ($moduleSnapshotPath) { Split-Path -Leaf $moduleSnapshotPath } else { $null }
        childProcesses = $childProcesses
    }
    return [pscustomobject]@{
        Execution = $execution
        MemoryDumps = $memoryArtifacts
        ModuleSnapshot = $moduleSnapshotPath
        ChildProcesses = $childProcesses
        StdoutPath = $stdoutFile
        StderrPath = $stderrFile
    }
}
$preSnapshot = Get-SystemSnapshot -Phase 'pre'
$preSnapshot | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $resultsDir 'baseline-pre.json') -Encoding UTF8

$procmonExe = if ($procmonCandidates.Count -gt 0) { $procmonCandidates[0] } else { $null }
$procmonHandle = Start-Procmon -Executable $procmonExe -BackingFile $procmonLog

try {
    if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
        Write-Log "Exporting pre-execution Sysmon events"
        wevtutil epl Microsoft-Windows-Sysmon/Operational $sysmonPre /ow:true
    }
} catch {
    Write-Log "Failed to export pre Sysmon events: $_"
}

$etwSessions = Start-EtwSessions -Directory $etwDir

$executionPlan = Build-ExecutionPlan -Sample $SamplePath -DllMode:$IsDll.IsPresent -Exports $DllExports
$executionResults = @()
$memoryDumpsAll = @()
$moduleSnapshots = @()
$processTree = @()
$executionIndex = 0

foreach ($plan in $executionPlan) {
    $result = Invoke-Execution -Plan $plan -CollectMemory:$CollectMemory.IsPresent -TimeoutSeconds $TimeoutSeconds
    $executionResults += $result.Execution
    $memoryDumpsAll += $result.MemoryDumps
    if ($result.ModuleSnapshot) {
        $moduleSnapshots += [pscustomobject]@{ label = $plan.Label; file = Split-Path -Leaf $result.ModuleSnapshot }
    }
    if ($result.ChildProcesses) {
        $processTree += $result.ChildProcesses
    }
    if ($executionIndex -eq 0) {
        Copy-Item -Path $result.StdoutPath -Destination $stdoutDefault -Force
        Copy-Item -Path $result.StderrPath -Destination $stderrDefault -Force
    }
    $executionIndex++
}

Stop-Procmon -Executable $procmonHandle -BackingFile $procmonLog -CsvPath $procmonCsv
Stop-EtwSessions -Sessions $etwSessions

try {
    if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
        Write-Log "Exporting post-execution Sysmon events"
        wevtutil epl Microsoft-Windows-Sysmon/Operational $sysmonPost /ow:true
    }
} catch {
    Write-Log "Failed to export post Sysmon events: $_"
}

$postSnapshot = Get-SystemSnapshot -Phase 'post'
$postSnapshot | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $resultsDir 'baseline-post.json') -Encoding UTF8
$baselineDiff = Compare-SystemSnapshot -Pre $preSnapshot -Post $postSnapshot
$baselineDiff | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $resultsDir 'baseline-diff.json') -Encoding UTF8

$telemetry = [ordered]@{
    procmon = @{
        log = Split-Path -Leaf $procmonLog
        csv = Split-Path -Leaf $procmonCsv
    }
    etw = $etwSessions
    sysmon = @{
        pre = Split-Path -Leaf $sysmonPre
        post = Split-Path -Leaf $sysmonPost
    }
}

$summary = [ordered]@{
    sample = $SamplePath
    kind = if ($IsDll) { 'dll' } else { 'exe' }
    heuristicScore = $heuristicScoreValue
    timeoutSeconds = $TimeoutSeconds
    collectMemory = [bool]$CollectMemory
    executions = $executionResults
    baseline = @{
        pre = $preSnapshot
        post = $postSnapshot
        diff = $baselineDiff
    }
    telemetry = $telemetry
    memoryDumps = $memoryDumpsAll
    moduleSnapshots = $moduleSnapshots
    processTree = $processTree
    dllExports = $DllExports
    verdict = if ($executionResults | Where-Object { -not $_.completed }) { 'incomplete' } else { 'completed' }
    summary = @{
        completedExecutions = ($executionResults | Where-Object { $_.completed }).Count
        totalExecutions = $executionResults.Count
    }
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryFile -Encoding UTF8
Write-Log "Summary written to $summaryFile"

Write-Log "Shutting down in 10 seconds"
Start-Process -FilePath 'shutdown.exe' -ArgumentList '/s','/t','10' -WindowStyle Hidden
