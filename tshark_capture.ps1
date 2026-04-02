[CmdletBinding()]
param(
    [string]$TsharkPath = "C:\Program Files\Wireshark\tshark.exe",
    [string]$OutputDirectory,
    [string]$OutputPath,
    [int]$ProcessId,
    [ValidateSet("chrome", "edge", "firefox", "brave", "opera", "vivaldi", "arc", "yandex")]
    [string]$Browser,
    [switch]$ListBrowsers,
    [switch]$IncludeUndecidableEvents,
    [switch]$SkipElevation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:BrowserProcessMap = @{
    "chrome.exe" = "chrome"
    "msedge.exe" = "edge"
    "firefox.exe" = "firefox"
    "brave.exe" = "brave"
    "opera.exe" = "opera"
    "vivaldi.exe" = "vivaldi"
    "arc.exe" = "arc"
    "browser.exe" = "yandex"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-ScriptElevated {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    $shellPath = (Get-Command powershell.exe -ErrorAction Stop).Source
    $argumentList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath
    )

    foreach ($entry in ($BoundParameters.GetEnumerator() | Sort-Object Key)) {
        if ($entry.Key -eq "SkipElevation") {
            continue
        }

        $parameterName = "-{0}" -f $entry.Key
        $value = $entry.Value

        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) {
                $argumentList += $parameterName
            }
            continue
        }

        if ($null -eq $value) {
            continue
        }

        $argumentList += $parameterName
        $argumentList += [string]$value
    }

    try {
        Start-Process -FilePath $shellPath -Verb RunAs -ArgumentList $argumentList | Out-Null
    } catch {
        throw "Administrator privileges are required for ETW capture. Elevation was cancelled."
    }
}

function Get-TextFileContent {
    param(
        [string]$Path
    )

    if (-not $Path) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $content) {
        return $null
    }

    $trimmed = ([string]$content).Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    return $trimmed
}

function Stop-CaptureProcess {
    param(
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    if ($Process.HasExited) {
        return
    }

    try {
        if ($Process.CloseMainWindow()) {
            if ($Process.WaitForExit(10000)) {
                return
            }
        }
    } catch {
    }

    try {
        Stop-Process -Id $Process.Id -ErrorAction SilentlyContinue
    } catch {
    }

    if (-not $Process.WaitForExit(5000)) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(5000)
    }
}

function Test-IsChromiumBrowser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BrowserId
    )

    return $BrowserId -in @("chrome", "edge", "brave", "opera", "vivaldi", "arc", "yandex")
}

function Get-BrowserRole {
    param(
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return "unknown"
    }

    if ($CommandLine -match '--utility-sub-type=network\.mojom\.NetworkService') {
        return "network-service"
    }

    if ($CommandLine -match '--type=renderer\b') {
        return "renderer"
    }

    if ($CommandLine -match '--type=gpu-process\b') {
        return "gpu"
    }

    if ($CommandLine -match '--type=crashpad-handler\b') {
        return "crashpad"
    }

    if ($CommandLine -match '(?<!\S)-socketprocess\b') {
        return "socket"
    }

    if ($CommandLine -match '(?<!\S)-contentproc\b') {
        return "contentproc"
    }

    if ($CommandLine -match '(?<!\S)-gpu\b') {
        return "gpu"
    }

    if ($CommandLine -match '--utility-sub-type=([^\s"]+)') {
        return $matches[1]
    }

    if ($CommandLine -match '--type=([^\s"]+)') {
        return $matches[1]
    }

    return "browser"
}

function Get-RoleRank {
    param(
        [string]$Role
    )

    switch ($Role) {
        "network-service" { return 0 }
        "socket" { return 1 }
        "browser" { return 2 }
        "renderer" { return 3 }
        "contentproc" { return 3 }
        default { return 3 }
    }
}

function Shorten-Text {
    param(
        [string]$Text,
        [int]$MaxLength = 88
    )

    $value = [string]$Text
    if ([string]::IsNullOrWhiteSpace($value)) {
        return ""
    }

    if ($value.Length -le $MaxLength) {
        return $value
    }

    return $value.Substring(0, $MaxLength - 3) + "..."
}

function Get-CommandSummary {
    param(
        [string]$CommandLine,
        [string]$Role
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return "(no command line)"
    }

    if ($Role -eq "network-service") {
        return "network-service"
    }

    if ($Role -eq "socket") {
        return "socketprocess"
    }

    if ($Role -eq "contentproc") {
        return "contentproc"
    }

    if ($CommandLine -match '--profile-directory=([^\s"]+)') {
        return "profile={0}" -f $matches[1]
    }

    if ($CommandLine -match '--app-id=([^\s"]+)') {
        return "app-id={0}" -f $matches[1]
    }

    if ($CommandLine -match '--type=([^\s"]+)') {
        return "type={0}" -f $matches[1]
    }

    return "browser"
}

function Get-NetworkConnectionCountMap {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "UDP")]
        [string]$Protocol
    )

    $counts = @{}

    try {
        if ($Protocol -eq "TCP") {
            $items = Get-NetTCPConnection -ErrorAction Stop
        } else {
            $items = Get-NetUDPEndpoint -ErrorAction Stop
        }

        foreach ($group in ($items | Group-Object -Property OwningProcess)) {
            if ($group.Name -match '^\d+$') {
                $counts[[int]$group.Name] = $group.Count
            }
        }
    } catch {
    }

    return $counts
}

function Get-BrowserProcesses {
    param(
        [string]$BrowserId,
        [switch]$IncludeAlternates
    )

    $tcpCounts = Get-NetworkConnectionCountMap -Protocol TCP
    $udpCounts = Get-NetworkConnectionCountMap -Protocol UDP
    $processDetailsById = @{}

    foreach ($processInfo in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processDetailsById[[int]$processInfo.Id] = $processInfo
    }

    $allProcesses = @()
    foreach ($processRecord in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $imageName = ([string]$processRecord.Name).ToLowerInvariant()
        if (-not $script:BrowserProcessMap.ContainsKey($imageName)) {
            continue
        }

        $resolvedBrowserId = $script:BrowserProcessMap[$imageName]
        if ($BrowserId -and $resolvedBrowserId -ne $BrowserId) {
            continue
        }

        $resolvedProcessId = [int]$processRecord.ProcessId
        $role = Get-BrowserRole -CommandLine $processRecord.CommandLine
        $mainWindowTitle = ""
        if ($processDetailsById.ContainsKey($resolvedProcessId)) {
            $mainWindowTitle = [string]$processDetailsById[$resolvedProcessId].MainWindowTitle
        }

        $selectionHint = if (-not [string]::IsNullOrWhiteSpace($mainWindowTitle)) {
            $mainWindowTitle
        } else {
            Get-CommandSummary -CommandLine $processRecord.CommandLine -Role $role
        }

        $allProcesses += [pscustomobject]@{
            Browser = $resolvedBrowserId
            Name = [string]$processRecord.Name
            ProcessId = $resolvedProcessId
            ParentProcessId = [int]$processRecord.ParentProcessId
            Role = $role
            TcpConnections = if ($tcpCounts.ContainsKey($resolvedProcessId)) { $tcpCounts[$resolvedProcessId] } else { 0 }
            UdpEndpoints = if ($udpCounts.ContainsKey($resolvedProcessId)) { $udpCounts[$resolvedProcessId] } else { 0 }
            MainWindowTitle = $mainWindowTitle
            StartedAt = [DateTime]$processRecord.CreationDate
            CommandLine = [string]$processRecord.CommandLine
            SelectionHint = Shorten-Text -Text $selectionHint
            Recommended = $false
            RecommendationReason = ""
        }
    }

    if ($allProcesses.Count -eq 0) {
        return @()
    }

    $candidateProcesses = @()
    foreach ($group in ($allProcesses | Group-Object -Property Browser)) {
        $groupCandidates = @(
            $group.Group | Where-Object {
                $_.Role -in @("browser", "network-service", "socket") -or
                $_.TcpConnections -gt 0 -or
                $_.UdpEndpoints -gt 0 -or
                -not [string]::IsNullOrWhiteSpace($_.MainWindowTitle)
            }
        )

        if ($groupCandidates.Count -eq 0) {
            $groupCandidates = @($group.Group)
        }

        if (Test-IsChromiumBrowser -BrowserId $group.Name) {
            $preferredChromiumCandidates = @($groupCandidates | Where-Object { $_.Role -ne "browser" })
            if ($preferredChromiumCandidates.Count -gt 0) {
                $groupCandidates = $preferredChromiumCandidates
            } else {
                $fallbackChromiumCandidates = @(
                    $group.Group | Where-Object {
                        $_.Role -notin @("crashpad", "gpu", "browser")
                    }
                )
                if ($fallbackChromiumCandidates.Count -gt 0) {
                    $groupCandidates = $fallbackChromiumCandidates
                }
            }
        } else {
            $preferredBrowserCandidates = @($groupCandidates | Where-Object { $_.Role -notin @("crashpad", "gpu") })
            if ($preferredBrowserCandidates.Count -gt 0) {
                $groupCandidates = $preferredBrowserCandidates
            }
        }

        $candidateProcesses += $groupCandidates
    }

    foreach ($group in ($candidateProcesses | Group-Object -Property Browser)) {
        $preferred = $null
        $recommendationReason = ""
        if (Test-IsChromiumBrowser -BrowserId $group.Name) {
            $preferred = @(
                $group.Group |
                    Where-Object { $_.Role -eq "network-service" } |
                    Sort-Object `
                        @{ Expression = { $_.TcpConnections }; Descending = $true }, `
                        @{ Expression = { $_.UdpEndpoints }; Descending = $true }, `
                        ProcessId |
                    Select-Object -First 1
            )
            if ($preferred) {
                $recommendationReason = "Role=network-service, usually owns Chromium network sockets and ETW traffic."
            }
        }

        if (-not $preferred) {
            $preferred = @(
                $group.Group |
                    Sort-Object `
                        @{ Expression = { $_.TcpConnections }; Descending = $true }, `
                        @{ Expression = { $_.UdpEndpoints }; Descending = $true }, `
                        ProcessId |
                    Select-Object -First 1
            )
            if ($preferred) {
                $recommendationReason = "No network-service candidate available; selected highest observed TCP/UDP activity."
            }
        }

        foreach ($item in $preferred) {
            $item.Recommended = $true
            $item.RecommendationReason = $recommendationReason
        }
    }

    $sortedCandidates = @(
        $candidateProcesses |
            Sort-Object `
                Browser, `
                @{ Expression = { [int]$_.Recommended }; Descending = $true }, `
                @{ Expression = { Get-RoleRank -Role $_.Role } }, `
                @{ Expression = { $_.TcpConnections }; Descending = $true }, `
                @{ Expression = { $_.UdpEndpoints }; Descending = $true }, `
                ProcessId
    )

    if ($IncludeAlternates.IsPresent) {
        return $sortedCandidates
    }

    return @($sortedCandidates | Where-Object { $_.Recommended })
}

function Write-BrowserProcessTable {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Processes
    )

    Write-Host "[*] Browser process candidates:"
    for ($index = 0; $index -lt $Processes.Count; $index++) {
        $entry = $Processes[$index]
        $marker = if ($entry.Recommended) { "*" } else { " " }
        $line = "{0}{1,2}. {2,-8} PID {3,-6} role {4}" -f `
            $marker, `
            ($index + 1), `
            $entry.Browser, `
            $entry.ProcessId, `
            $entry.Role
        Write-Host $line
    }

}

function Resolve-BrowserProcess {
    param(
        [int]$RequestedProcessId,
        [string]$BrowserId,
        [bool]$ListOnly
    )

    if ($RequestedProcessId -gt 0) {
        $processes = @(Get-BrowserProcesses -BrowserId $BrowserId -IncludeAlternates)
    } else {
        $processes = @(Get-BrowserProcesses -BrowserId $BrowserId)
    }
    if ($processes.Count -eq 0) {
        if ($BrowserId) {
            throw "No running '$BrowserId' browser processes were found."
        }

        throw "No supported browser processes are running."
    }

    if ($RequestedProcessId -gt 0) {
        $matchedProcess = @($processes | Where-Object { $_.ProcessId -eq $RequestedProcessId } | Select-Object -First 1)
        if (-not $matchedProcess) {
            throw "ProcessId $RequestedProcessId is not a supported running browser process."
        }

        return $matchedProcess[0]
    }

    if ($ListOnly) {
        Write-BrowserProcessTable -Processes $processes
        return $null
    }

    if ($processes.Count -eq 1) {
        return $processes[0]
    }

    Write-BrowserProcessTable -Processes $processes
    $choice = Read-Host "Select a browser process by list number or PID"
    if ([string]::IsNullOrWhiteSpace($choice)) {
        throw "No browser process was selected."
    }

    $trimmedChoice = $choice.Trim()
    if ($trimmedChoice -notmatch '^\d+$') {
        throw "Selection must be a numeric list number or PID."
    }

    $numericChoice = [int]$trimmedChoice
    if ($numericChoice -ge 1 -and $numericChoice -le $processes.Count) {
        return $processes[$numericChoice - 1]
    }

    $selectedByPid = @($processes | Where-Object { $_.ProcessId -eq $numericChoice } | Select-Object -First 1)
    if ($selectedByPid) {
        return $selectedByPid[0]
    }

    throw "Selection '$trimmedChoice' did not match any browser process."
}

function Test-EtwInterfaceAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $interfaces = @(& $Path -D 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to query Wireshark capture interfaces."
    }

    if (-not ($interfaces | Where-Object { [string]$_ -match '\betwdump\b' })) {
        throw "Wireshark ETW capture interface 'etwdump' is not available. Make sure Wireshark extcap support is installed."
    }
}

function Resolve-EtwdumpPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TsharkPath
    )

    $wiresharkDirectory = Split-Path -Parent $TsharkPath
    $candidatePaths = @(
        (Join-Path (Join-Path $wiresharkDirectory "extcap") "etwdump.exe"),
        (Join-Path $wiresharkDirectory "etwdump.exe")
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    $expectedLocations = ($candidatePaths | ForEach-Object { "'$_'" }) -join ", "
    throw "etwdump.exe was not found. Expected one of: $expectedLocations"
}

function Get-PidDisplayFilter {
    param(
        [Parameter(Mandatory = $true)]
        [int]$BrowserProcessId
    )

    return ('frame.comment contains "PID={0}"' -f $BrowserProcessId)
}

function Get-CompareDisplayFilter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidDisplayFilter
    )

    return "tls.handshake.type == 1"
}

function Wait-ForCaptureStartup {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]
        [string]$StderrPath,
        [string]$ReadyPattern = "Capturing on",
        [int]$TimeoutMilliseconds = 10000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            break
        }

        if (-not [string]::IsNullOrWhiteSpace($ReadyPattern)) {
            $stderrText = Get-TextFileContent -Path $StderrPath
            if ($stderrText -and $stderrText -match $ReadyPattern) {
                return
            }
        }

        Start-Sleep -Milliseconds 200
    }

    if (-not $Process.HasExited -and [string]::IsNullOrWhiteSpace($ReadyPattern)) {
        return
    }

    if ($Process.HasExited) {
        $stderrText = Get-TextFileContent -Path $StderrPath
        if ($stderrText) {
            throw "Capture tool exited before capture startup completed. stderr: $stderrText"
        }

        throw "Capture tool exited before capture startup completed."
    }
}

function Invoke-CaptureReportGeneration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TsharkPath,
        [Parameter(Mandatory = $true)]
        [string]$CapturePath,
        [Parameter(Mandatory = $true)]
        [string]$DisplayFilter,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $reportArgs = @(
        "-2",
        "-r", $CapturePath,
        "-Y", $DisplayFilter,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=|",
        "-e", "frame.number",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tcp.reassembled.data",
        "-e", "udp.payload",
        "-e", "tcp.payload",
        "-e", "data.data"
    )
    $reportResult = @(& $TsharkPath @reportArgs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($reportResult | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        if ([string]::IsNullOrWhiteSpace($errorText)) {
            $errorText = "tshark exited with code $LASTEXITCODE."
        }

        throw ("Failed to generate report with tshark fallback. {0}" -f $errorText.Trim())
    }

    $reportLines = @()
    foreach ($rawLine in $reportResult) {
        $line = [string]$rawLine
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = @($line -split '\|', 8)
        while ($parts.Count -lt 8) {
            $parts += ""
        }

        $protocol = ([string]$parts[1]).Trim()
        $info = ([string]$parts[2]).Trim()
        $sni = ([string]$parts[3]).Trim()
        $tcpReassembledData = ([string]$parts[4]).Trim()
        $udpPayload = ([string]$parts[5]).Trim()
        $tcpPayload = ([string]$parts[6]).Trim()
        $rawData = ([string]$parts[7]).Trim()

        $summary = $info
        if ($summary -match '^(?<label>[^,(]+)') {
            $summary = $matches["label"].Trim()
        }

        if ([string]::IsNullOrWhiteSpace($summary)) {
            $summary = "Client Hello"
        }

        $hexDump = @(
            $tcpReassembledData,
            $udpPayload,
            $tcpPayload,
            $rawData
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

        if ([string]::IsNullOrWhiteSpace($protocol)) {
            $protocol = "Unknown"
        }

        $titleLine = if ([string]::IsNullOrWhiteSpace($sni)) {
            "{0} | {1}" -f $protocol, $summary
        } else {
            "{0} | {1} | SNI={2}" -f $protocol, $summary, $sni
        }

        if ([string]::IsNullOrWhiteSpace($hexDump)) {
            $hexDump = "(no handshake payload bytes found)"
        }

        $amneziaLine = if ($hexDump -match '^[0-9a-fA-F]+$') {
            "i1=<b 0x{0}>" -f $hexDump.ToLowerInvariant()
        } else {
            "i1=<b 0x>"
        }

        $reportLines += @(
            $titleLine,
            "hex dump:",
            $hexDump,
            "AmneziaWG i:",
            $amneziaLine,
            "-----"
        )
    }

    if ($reportLines.Count -eq 0) {
        $reportLines = @("No browser Client Hello packets matched the report filter.")
    }

    Set-Content -LiteralPath $OutputPath -Value $reportLines -Encoding UTF8
}

function Invoke-CaptureFiltering {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TsharkPath,
        [Parameter(Mandatory = $true)]
        [string]$InputCapturePath,
        [Parameter(Mandatory = $true)]
        [string]$DisplayFilter,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $filterArgs = @(
        "-r", $InputCapturePath,
        "-Y", $DisplayFilter,
        "-w", $OutputPath
    )
    $filterResult = @(& $TsharkPath @filterArgs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($filterResult | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        if ([string]::IsNullOrWhiteSpace($errorText)) {
            $errorText = "tshark exited with code $LASTEXITCODE."
        }

        throw ("Failed to filter captured packets by browser PID. {0}" -f $errorText.Trim())
    }

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        throw "Filtered capture '$OutputPath' was not created."
    }

    $countArgs = @(
        "-r", $OutputPath,
        "-T", "fields",
        "-e", "frame.number"
    )
    $countResult = @(& $TsharkPath @countArgs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $errorText = ($countResult | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        if ([string]::IsNullOrWhiteSpace($errorText)) {
            $errorText = "tshark exited with code $LASTEXITCODE."
        }

        throw ("Filtered capture was created, but packet count verification failed. {0}" -f $errorText.Trim())
    }

    $packetCount = @(
        $countResult |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ -match '^\d+$' }
    ).Count
    return $packetCount
}

function Request-ElevationIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters,
        [bool]$AllowPrompt = $true
    )

    if (Test-IsAdministrator) {
        return $false
    }

    if (-not $AllowPrompt) {
        throw "Administrator privileges are required for ETW capture. Please run this script from an elevated PowerShell window."
    }

    Write-Host "Administrator privileges are required for ETW capture." -ForegroundColor Yellow
    $answer = Read-Host "Run this script as administrator now? [Y/N]"
    if ($answer -match '^(?i:y|yes)$') {
        Restart-ScriptElevated -BoundParameters $BoundParameters
        return $true
    }

    throw "Administrator privileges are required for ETW capture. Please run this script as administrator."
}

if (-not (Test-Path -LiteralPath $TsharkPath)) {
    throw "tshark.exe was not found at '$TsharkPath'."
}

Test-EtwInterfaceAvailable -Path $TsharkPath
$etwdumpPath = Resolve-EtwdumpPath -TsharkPath $TsharkPath

if (-not $ListBrowsers -and -not (Test-IsAdministrator)) {
    if (Request-ElevationIfNeeded -BoundParameters $PSBoundParameters -AllowPrompt (-not $SkipElevation.IsPresent)) {
        return
    }
}

$selectedProcess = Resolve-BrowserProcess -RequestedProcessId $ProcessId -BrowserId $Browser -ListOnly $ListBrowsers.IsPresent
if ($ListBrowsers) {
    return
}

$scriptDirectory = Split-Path -Parent $PSCommandPath
if (-not $OutputDirectory) {
    $OutputDirectory = $scriptDirectory
}

if (-not $OutputPath) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $timestamp = Get-Date -Format "dd.MM.yyyy-HHmmss"
    $fileName = "{0}-{1}.pcapng" -f $selectedProcess.Browser, $timestamp
    $OutputPath = Join-Path $OutputDirectory $fileName
} else {
    $outputParent = Split-Path -Parent $OutputPath
    if ($outputParent) {
        New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
    }
}

$resolvedPidFilter = Get-PidDisplayFilter -BrowserProcessId $selectedProcess.ProcessId
$resolvedCompareFilter = Get-CompareDisplayFilter -PidDisplayFilter $resolvedPidFilter
$stdoutPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("payloadgen-etw-{0}.stdout.log" -f [guid]::NewGuid().ToString("N")))
$stderrPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("payloadgen-etw-{0}.stderr.log" -f [guid]::NewGuid().ToString("N")))
$rawCapturePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("payloadgen-etw-{0}.raw.pcapng" -f [guid]::NewGuid().ToString("N")))
$etwProvider = "--p=Microsoft-Windows-NDIS-PacketCapture"

$captureArguments = @(
    "--extcap-interface", "etwdump",
    "--fifo", $rawCapturePath,
    "--capture",
    "--params", $etwProvider
)

if ($IncludeUndecidableEvents) {
    $captureArguments += "--iue"
}

$captureProcess = $null

try {
    $selectedBrowserLabel = if ([string]::IsNullOrWhiteSpace($selectedProcess.Browser)) {
        "Browser"
    } else {
        $selectedProcess.Browser.Substring(0, 1).ToUpperInvariant() + $selectedProcess.Browser.Substring(1)
    }
    Write-Host "Dont use vpn or proxy!"
    Write-Host ("{0} selected." -f $selectedBrowserLabel)
    Write-Host "Open something in browser."
    Write-Host "Press Enter to stop capture."

    $captureProcess = Start-Process `
        -FilePath $etwdumpPath `
        -ArgumentList $captureArguments `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    Wait-ForCaptureStartup `
        -Process $captureProcess `
        -StderrPath $stderrPath `
        -ReadyPattern $null `
        -TimeoutMilliseconds 1500
    [void][System.Console]::ReadLine()
    Start-Sleep -Milliseconds 750
    Stop-CaptureProcess -Process $captureProcess

    for ($attempt = 0; $attempt -lt 60 -and -not (Test-Path -LiteralPath $rawCapturePath); $attempt++) {
        Start-Sleep -Milliseconds 500
    }

    if (-not (Test-Path -LiteralPath $rawCapturePath)) {
        $captureStderr = Get-TextFileContent -Path $stderrPath
        if ($captureStderr) {
            throw "Capture stopped, but raw capture '$rawCapturePath' was not created. capture stderr: $captureStderr"
        }

        throw "Capture stopped, but raw capture '$rawCapturePath' was not created."
    }

    $filteredPacketCount = Invoke-CaptureFiltering `
        -TsharkPath $TsharkPath `
        -InputCapturePath $rawCapturePath `
        -DisplayFilter $resolvedPidFilter `
        -OutputPath $OutputPath

    if ($filteredPacketCount -le 0) {
        Write-Host "No packets were found for the selected browser. Please try again with VPN or proxy disabled." -ForegroundColor Yellow
        return
    }

    $captureFile = Get-Item -LiteralPath $OutputPath
    $resolvedOutputPath = $captureFile.FullName
    $resolvedReportPath = [System.IO.Path]::ChangeExtension($resolvedOutputPath, ".txt")
    Invoke-CaptureReportGeneration `
        -TsharkPath $TsharkPath `
        -CapturePath $resolvedOutputPath `
        -DisplayFilter $resolvedCompareFilter `
        -OutputPath $resolvedReportPath

    $captureFileName = [System.IO.Path]::GetFileName($resolvedOutputPath)
    $reportFileName = [System.IO.Path]::GetFileName($resolvedReportPath)
    Write-Host "Saved:"
    Write-Host $captureFileName
    Write-Host $reportFileName
}
finally {
    Stop-CaptureProcess -Process $captureProcess

    if (Test-Path -LiteralPath $stdoutPath) {
        Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $stderrPath) {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $rawCapturePath) {
        Remove-Item -LiteralPath $rawCapturePath -Force -ErrorAction SilentlyContinue
    }
}
