param(
  [int]$Port = 4200,
  [int]$StartTimeoutSec = 20,
  [int]$CheckIntervalSec = 1,
  [ValidateSet('inline','log')]
  [string]$Mode = 'inline',
  [string]$LogFile = ".\logs\dev-server.log",
  [int]$RestartAttempts = 3,
  [switch]$ReportOnly,
  [switch]$AutoDetectPort
)

# Option A (safe mode):
# - If something else is listening on $Port, report that it's listening and show the owning PID/process.
# - Do NOT kill or take the port from foreign processes.
# - Only start the dev server when the port is not listening. When we start the server, wait for it to bind
#   and then monitor; if the port stops listening we will restart the dev server (only when it's not listening).

function Get-PortOwner {
  param([int]$Port)
  # Try native cmdlet first (available on modern Windows)
  try {
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction Stop | Select-Object -First 1
    if ($conn) {
      return @{Pid = $conn.OwningProcess; 
      LocalAddress = $conn.LocalAddress; 
      State = $conn.State}
    }
  } catch {
    # ignore and fall back to netstat
  }

  # Fallback: parse netstat output
  try {
    $match = netstat -ano | Select-String -Pattern "\b:$Port\b" | Select-Object -First 1
    if ($match) {
      $parts = ($match.ToString() -split '\s+') | Where-Object { $_ -ne '' }
      $pid = $parts[-1]
      return @{Pid = [int]$pid; Raw = $match.ToString()}
    }
  } catch {
    # ignore
  }

  return $null
}

function Start-Angular {
  Write-Log "Starting dev server (npm run start) in a child PowerShell process..."

  # Ensure the log directory for the child log exists and compute absolute path
  try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  } catch {
    $scriptDir = Get-Location
  }
  $absLog = $LogFile
  if (-not (Split-Path -IsPathRooted $absLog)) {
    $absLog = Join-Path -Path $scriptDir -ChildPath $LogFile
  }
  $absLogDir = Split-Path -Path $absLog -Parent
  if ($absLogDir -and -not (Test-Path $absLogDir)) { New-Item -ItemType Directory -Path $absLogDir -Force | Out-Null }

  # Build a command that redirects stdout/stderr to the child log file
  $escapedLog = $absLog -replace "'","''"
  $command = "& { npm run start > '$escapedLog' 2>&1 }"

  # Start the child PowerShell process and return the process object
  try {
    $proc = Start-Process -FilePath powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',$command -WorkingDirectory $scriptDir -PassThru
    return $proc
  } catch {
    Write-WarnLog "Failed to spawn child PowerShell process: $($_.Exception.Message)"
    return $null
  }
}

# --- Logging helper functions (kept near the top with other functions) ---
function Write-Log {
  param([string]$Text)
  Write-Output $Text
  if ($Mode -eq 'log') {
    try {
      $parentDir = Split-Path -Path $ParentLogFile -Parent
      if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
      $time = (Get-Date).ToString('o')
      # Write the latest parent message to the helper log (overwrite) so it stays small.
      Set-Content -Path $ParentLogFile -Value "[$time] $Text" -Encoding UTF8 -Force
    } catch {
      # if that fails, fall back to console only
    }
  }
}

function Write-WarnLog {
  param([string]$Text)
  Write-Warning $Text
  if ($Mode -eq 'log') {
    try {
      $time = (Get-Date).ToString('o')
      $entry = "[$time] WARNING: $Text"
      Set-Content -Path $ParentLogFile -Value $entry -Force -Encoding UTF8
    } catch {
      # ignore
    }
  }
}

# Kill a process and all of its descendant processes (best-effort).
function Kill-ProcessTree {
  param([int]$Pid)
  try {
    $descendants = @()
    function Get-Descendants {
      param([int]$p)
      try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$p" -ErrorAction SilentlyContinue
        foreach ($c in $children) {
          if ($c -and $c.ProcessId) {
            $descendants += $c.ProcessId
            Get-Descendants -p $c.ProcessId
          }
        }
      } catch {
        # ignore errors enumerating children
      }
    }

    Get-Descendants -p $Pid

    # Stop descendants first (descending numeric order is a reasonable heuristic)
    foreach ($id in ($descendants | Sort-Object -Descending)) {
      try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch { }
    }

    # Finally, stop the root PID
    try { Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue } catch { }
  } catch {
    # Fallback: try a simple Stop-Process on the PID
    try { Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue } catch { }
  }
}

function Is-CI {
  # Detect common CI environment variables
  $ciVars = @('CI','GITHUB_ACTIONS','TF_BUILD','AZURE_PIPELINES','GITLAB_CI','TRAVIS','CIRCLECI','JENKINS_URL','TEAMCITY_VERSION')
  foreach ($v in $ciVars) {
    try {
      $val = (Get-Item -Path "Env:$v" -ErrorAction SilentlyContinue).Value
      if ($val) { return $true }
    } catch {
      # ignore
    }
  }
  return $false
}

function Get-PortFromEnvOrPkg {
  param([string]$RepoRoot)
  if (-not $RepoRoot) { $RepoRoot = (Get-Location).Path }
  # 1) environment variable
  if ($env:PORT) {
    $p = 0
    if ([int]::TryParse($env:PORT,[ref]$p)) { return $p }
  }

  # 2) package.json start script
  $pkgFile = Join-Path $RepoRoot 'package.json'
  if (Test-Path $pkgFile) {
    try {
      $pkg = Get-Content $pkgFile -Raw | ConvertFrom-Json
      $startScript = $pkg.scripts.start
      if ($startScript) {
        if ($startScript -match '--port(?:=|\s+)(\d{2,5})') { return [int]$matches[1] }
        if ($startScript -match 'PORT=(\d{2,5})') { return [int]$matches[1] }
      }
    } catch {
      # ignore parse errors
    }
  }
  return $null
}

function Get-PortFromAngularJson {
  param([string]$RepoRoot)
  if (-not $RepoRoot) { $RepoRoot = (Get-Location).Path }
  $angularFile = Join-Path $RepoRoot 'angular.json'
  if (-not (Test-Path $angularFile)) { return $null }
  try {
    $cfg = Get-Content $angularFile -Raw | ConvertFrom-Json
    $projName = $cfg.defaultProject
    if (-not $projName) {
      $props = $cfg.psobject.Properties | Where-Object { $_.Name -ne 'version' }
      if ($props) { $projName = $props[0].Name }
    }
    if ($projName -and $cfg.projects.$projName.architect) {
      $serve = $cfg.projects.$projName.architect.serve
      if ($serve -and $serve.options -and $serve.options.port) { return [int]$serve.options.port }
      if ($serve -and $serve.configurations) {
        foreach ($conf in $serve.configurations.PSObject.Properties) {
          $opts = $serve.configurations.$($conf.Name).options
          if ($opts -and $opts.port) { return [int]$opts.port }
        }
      }
    }
  } catch {
    # ignore
  }
  return $null
}

function Get-PortFromRunningProcess {
  # Look for running 'ng serve' or node processes with ng as command
  try {
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '\bng\b.*serve' -or $_.CommandLine -match 'node.*ng' }
    foreach ($p in $procs) {
      $cmd = $p.CommandLine
      if ($cmd -match '--port(?:=|\s+)(\d{2,5})') { return [int]$matches[1] }
      if ($cmd -match 'PORT=(\d{2,5})') { return [int]$matches[1] }
    }
  } catch {
    # ignore
  }
  return $null
}

function Get-AngularPort {
  param([string]$RepoRoot)
  if (-not $RepoRoot) {
    try { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path } catch { $RepoRoot = (Get-Location).Path }
  }

  $p = Get-PortFromEnvOrPkg -RepoRoot $RepoRoot
  if ($p) { return $p }
  $p = Get-PortFromAngularJson -RepoRoot $RepoRoot
  if ($p) { return $p }
  $p = Get-PortFromRunningProcess
  if ($p) { return $p }
  return 4200
}

# Logging helpers: write to console and, when running in log mode, write only to the helper logfile.
# We do NOT attempt to modify the child's log file to avoid file-lock errors; parent messages
# are preserved in `dev-server-helper.log` (overwritten with the latest status).
$ParentLogFile = [System.IO.Path]::Combine((Split-Path -Path $LogFile -Parent), 'dev-server-helper.log')
if ($Mode -eq 'log') {
  $parentDir = Split-Path -Path $ParentLogFile -Parent
  if ($parentDir -and -not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
  # Ensure the helper log file exists immediately (create with an initial timestamped entry).
  try {
    $time = (Get-Date).ToString('o')
    Set-Content -Path $ParentLogFile -Value "[$time] Helper log initialized." -Encoding UTF8 -Force
  } catch {
    # ignore file creation/write errors (permissions, etc.)
  }
}
# Auto-detect the Angular port in two cases:
# 1) When the caller explicitly passed -AutoDetectPort
# 2) When the caller did NOT explicitly pass -Port (i.e. they rely on defaults)
# This lets the script be dynamic by default while preserving an explicitly supplied -Port.
$shouldAutoDetect = $AutoDetectPort -or -not $PSBoundParameters.ContainsKey('Port')
if ($shouldAutoDetect) {
  try {
    $detected = Get-AngularPort
    if ($detected) {
      $old = $Port
      $Port = $detected
      if ($old -ne $Port) {
        Write-Log "Auto-detected Angular port: $Port (was $old)"
      } else {
        Write-Log "Auto-detected Angular port: $Port"
      }
    } else {
      Write-Log "Auto-detect did not find a port; using configured port $Port"
    }
  } catch {
    Write-WarnLog "Auto-detect failed: $($_.Exception.Message)"
  }
}
# If called as a single-report (postbuild), do a one-shot status check and exit immediately.
if ($ReportOnly) {
  try {
    $initial = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
  } catch {
    $initial = $null
  }

  if ($initial -and $initial.TcpTestSucceeded) {
    $owner = Get-PortOwner -Port $Port
    if ($owner -and $owner.Pid) {
      $ownerProc = Get-Process -Id $owner.Pid -ErrorAction SilentlyContinue
      $ownerName = if ($ownerProc) { $ownerProc.ProcessName } else { $owner.Raw }
      Write-Log "Port $Port is currently listening (PID $($owner.Pid); Process: $ownerName). No action taken."
    } else {
      Write-Log "Port $Port is currently listening. No action taken."
    }
  } else {
    Write-Log "Port $Port is not currently listening."
  }

  return
}

$global:childPid = $null
try {
  # Prevent accidental starts in CI environments
  if (-not $ReportOnly -and (Is-CI)) {
    Write-Log "CI environment detected; skipping start attempts. Use -ReportOnly to explicitly report status in CI." 
    return
  }

  # One-shot behavior: check port, start if needed, wait for bind, then exit.
  try {
    $initial = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
  } catch {
    $initial = $null
  }

  if ($initial -and $initial.TcpTestSucceeded) {
    # Port already listening: report and exit.
    $owner = Get-PortOwner -Port $Port
    if ($owner -and $owner.Pid) {
      $ownerProc = Get-Process -Id $owner.Pid -ErrorAction SilentlyContinue
      $ownerName = if ($ownerProc) { $ownerProc.ProcessName } else { $owner.Raw }
      Write-Log "Port $Port is currently listening (PID $($owner.Pid); Process: $ownerName). No action taken."
    } else {
      Write-Log "Port $Port is currently listening. No action taken."
    }

    return
  }

  # Port not listening -> try restarting up to 3 times
  $attemptNum = 0
  $startedAndListening = $false
  while ($attemptNum -lt $RestartAttempts) {
    $attemptNum++
  Write-Log "Attempt ${attemptNum} of ${RestartAttempts}: starting dev server..."
    $childProc = Start-Angular
    if (-not ($childProc -and $childProc.Id)) {
      Write-WarnLog "Attempt ${attemptNum}: failed to spawn child process."
      continue
    }
    $childPid = $childProc.Id
    $global:childPid = $childPid
    Write-Log "Attempt ${attemptNum}: Started child process PID ${childPid}"

    $listening = $false
    $attempts = [int]([math]::Ceiling($StartTimeoutSec / $CheckIntervalSec))
    for ($i = 0; $i -lt $attempts; $i++) {
      Start-Sleep -Seconds $CheckIntervalSec
      try {
        $res = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
        if ($res -and $res.TcpTestSucceeded) {
          $listening = $true
          break
        }
      } catch {
        # ignore and retry
      }
    }

    if ($listening) {
      Write-Log "Attempt ${attemptNum}: Dev server is listening on port $Port (child PID ${childPid})."
      $startedAndListening = $true
      break
    } else {
      Write-WarnLog "Attempt ${attemptNum}: Dev server did not start listening on port $Port within $StartTimeoutSec seconds. Stopping child and retrying..."
  try { Kill-ProcessTree $childPid } catch { }
      Start-Sleep -Seconds 1
      continue
    }
  }

  if ($startedAndListening) {
    return
  } else {
    Write-WarnLog "Failed to start dev server after $RestartAttempts attempts. See above logs for details."
    # Also write an explicit failure line to the helper log so postbuild consumers can detect failure
    Write-Log "ERROR: failed to start dev server on port $Port after $RestartAttempts attempts."
    exit 1
  }
} finally {
  # Script exiting - attempt to stop child we started to avoid leaving orphaned ng/Node processes.
  if ($global:childPid) {
    Write-Log "Script exiting - attempting to stop child process PID $global:childPid"
    try { Kill-ProcessTree $global:childPid } catch { }
  }
}
