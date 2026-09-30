#Requires -Version 5.1
<#
.SYNOPSIS
Read-only local troubleshooting of Azure platform connectivity on a Windows VM.
.DESCRIPTION
Tests 168.63.129.16 and collects bounded, relevant guest evidence. Does not change
services, firewall, IP, proxy, registry, execution policy, or Azure configuration.
Writes summary.txt and diagnostics.json into a NEW local report directory.
See AzurePlatformConnectivity-README.md for interpretation and limitations.
.PARAMETER OutputDirectory
New directory to create. An existing path is refused to avoid overwriting reports.
.PARAMETER TimeoutSeconds
Per TCP/HTTP attempt and DNS subprocess deadline, 1 through 15 seconds.
.PARAMETER RetryCount
TOTAL attempts per TCP port and HTTP endpoint, 1 through 5 (not additional retries).
.PARAMETER EventLookbackHours
System/Application event lookback, 1 through 168 hours; scan caps still apply.
.PARAMETER DnsName
ASCII DNS hostname for optional A-record resolution tests. Default: learn.microsoft.com.
.PARAMETER SkipDns
Omit DNS queries. DNS is separate from the VM Agent's TCP 80/32526 requirements.
.PARAMETER ExpectedPrimaryIPv4
Compare a user-supplied expected Azure primary address with local address evidence.
The script cannot obtain or confirm the actual Azure NIC primary address.
.PARAMETER SourceIPv4
Bind TCP probes to this guest IPv4 address. HTTP and DNS remain unbound; their
source can differ. This option does not change guest IP configuration.
.PARAMETER IncludeLogSnippets
Include small, best-effort-redacted matching log/event excerpts. OFF by default.
Redaction is NOT guaranteed. Review every report before sharing.
.EXAMPLE
.\Test-AzurePlatformConnectivity.ps1
.EXAMPLE
.\Test-AzurePlatformConnectivity.ps1 -TimeoutSeconds 5 -RetryCount 3 -SkipDns
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateRange(1, 15)][int]$TimeoutSeconds = 3,
    [ValidateRange(1, 5)][int]$RetryCount = 2,
    [ValidateRange(1, 168)][int]$EventLookbackHours = 24,
    [ValidateLength(1, 253)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')][string]$DnsName = 'learn.microsoft.com',
    [switch]$SkipDns,
    [string]$ExpectedPrimaryIPv4,
    [string]$SourceIPv4,
    [switch]$IncludeLogSnippets
)

$ErrorActionPreference = 'Stop'
$script:StartedUtc = [DateTime]::UtcNow
$script:Target = '168.63.129.16'
$script:Checks = New-Object 'System.Collections.Generic.List[object]'
$script:Evidence = [ordered]@{}
$script:NextSteps = New-Object 'System.Collections.Generic.List[object]'
$script:Limits = [ordered]@{
    TcpAttemptsPerPort = $RetryCount
    HttpAttempts = $RetryCount
    ProbeTimeoutSeconds = $TimeoutSeconds
    HttpBodyBytes = 16384
    HttpVersionValues = 32
    DnsQueries = 4
    DnsAnswersPerQuery = 20
    EventsScannedPerLog = 300
    RelatedEventsRetainedPerLog = 40
    EventExcerptsPerLog = 10
    FirewallRulesInspected = 100
    FirewallCandidatesRetained = 50
    FirewallFilterValuesRetained = 32
    FirewallAddressTokensEvaluated = 256
    FirewallPortTokensEvaluated = 64
    LogTailBytesPerFile = 262144
    LogTailLinesPerFile = 400
    LogSnippetsPerFile = 20
    LogSnippetCharacters = 400
    NetworkAdapters = 64
    IPv4Addresses = 256
    NetworkInterfacesAndRoutes = 128
}

function Limit-Text {
    param([AllowNull()][object]$Value, [int]$Maximum = 500)
    $text = [string]$Value
    if ($text.Length -gt $Maximum) { return ($text.Substring(0, $Maximum) + ' [truncated]') }
    return $text
}

function Protect-Excerpt {
    param([AllowNull()][object]$Value, [int]$Maximum = 400)
    $text = [string]$Value
    if ($text -match '(?i)password|passwd|secret|token|authorization|bearer|private.?key|protected.?settings|connection.?string|sharedaccesssignature|[?&]sig=') {
        return '[redacted sensitive-looking line; review source locally]'
    }
    $text = [regex]::Replace($text, 'https?://[^\s"<>]+', '[URL redacted]')
    $text = [regex]::Replace($text, '[^\s;=@]+:[^\s;@]+@', '[credentials redacted]@')
    $text = [regex]::Replace($text, '[A-Za-z0-9+/=_-]{80,}', '[long value redacted]')
    return (Limit-Text -Value $text -Maximum $Maximum)
}

function Get-RootException {
    param([Exception]$Exception)
    for ($depth = 0; $depth -lt 8 -and $Exception.InnerException; $depth++) {
        $Exception = $Exception.InnerException
    }
    return $Exception
}

function Add-Check {
    param([string]$Id, [string]$Category,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'INFO', 'ERROR', 'SKIPPED')][string]$Status,
        [string]$Summary, [AllowNull()][object]$Details = $null)
    [void]$script:Checks.Add([pscustomobject][ordered]@{
        Id = $Id; Category = $Category; Status = $Status
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        Summary = $Summary; Details = $Details
    })
}

function Add-NextStep {
    param([int]$Priority, [string]$Reason, [string]$Action)
    [void]$script:NextSteps.Add([pscustomobject][ordered]@{
        Priority = $Priority; Reason = $Reason; Action = $Action
    })
}

function Invoke-ReadSection {
    param([string]$Key, [scriptblock]$Body)
    try {
        $data = @(& $Body)
        $script:Evidence[$Key] = [pscustomobject][ordered]@{
            CollectedUtc = [DateTime]::UtcNow.ToString('o')
            CollectionStatus = 'Collected'; Data = $data; Error = $null
        }
    } catch {
        $errorText = Protect-Excerpt $_.Exception.Message 500
        $script:Evidence[$Key] = [pscustomobject][ordered]@{
            CollectedUtc = [DateTime]::UtcNow.ToString('o')
            CollectionStatus = 'Error'; Data = @(); Error = $errorText
        }
        Add-Check "collection.$Key" 'Collection' 'ERROR' "Could not collect $Key; this is an evidence gap, not a failed connectivity test." $errorText
    }
}

function Get-SectionData {
    param([string]$Key)
    if ($script:Evidence.Contains($Key)) { return $script:Evidence[$Key].Data }
    return @()
}

function Assert-IPv4Parameter {
    param([string]$Value, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if ($Value -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "$Name must be a dotted-decimal IPv4 address." }
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must be a valid IPv4 address."
    }
    foreach ($part in $Value.Split('.')) {
        if ([int]$part -gt 255 -or ($part.Length -gt 1 -and $part.StartsWith('0'))) {
            throw "$Name must use ordinary decimal octets without leading zeroes."
        }
    }
    if ($parsed.Equals([Net.IPAddress]::Any) -or $parsed.Equals([Net.IPAddress]::Broadcast) -or $Value.StartsWith('127.')) {
        throw "$Name must be a guest unicast address, not unspecified, broadcast, or loopback."
    }
}

function Test-TcpAttempt {
    param([int]$Port, [int]$Attempt)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $client = $null; $waitHandle = $null
    $result = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o'); Attempt = $Attempt
        Destination = $script:Target; Port = $Port; RequestedSourceIPv4 = $SourceIPv4
        ActualLocalEndpoint = $null; LocalEndpointCollectionError = $null
        Status = 'FAIL'; ErrorKind = $null; SocketErrorCode = $null
        Error = $null; CleanupErrors = @(); ElapsedMilliseconds = 0
    }
    try {
        $client = New-Object Net.Sockets.TcpClient ([Net.Sockets.AddressFamily]::InterNetwork)
        if ($SourceIPv4) {
            $client.Client.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($SourceIPv4), 0)))
        }
        $pending = $client.BeginConnect($script:Target, $Port, $null, $null)
        $waitHandle = $pending.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($TimeoutSeconds * 1000)) {
            $result.ErrorKind = 'Timeout'
            $result.Error = "TCP connection did not complete within $TimeoutSeconds seconds."
        } else {
            $client.EndConnect($pending)
            $result.Status = 'PASS'
        }
        try {
            if ($client.Client.LocalEndPoint) { $result.ActualLocalEndpoint = [string]$client.Client.LocalEndPoint }
        } catch { $result.LocalEndpointCollectionError = Protect-Excerpt $_.Exception.Message 300 }
    } catch {
        $rootError = Get-RootException $_.Exception
        $result.ErrorKind = $rootError.GetType().Name
        if ($rootError -is [Net.Sockets.SocketException]) { $result.SocketErrorCode = [string]$rootError.SocketErrorCode }
        $result.Error = Protect-Excerpt $rootError.Message 500
    } finally {
        try { if ($client) { $client.Close() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        try { if ($waitHandle) { $waitHandle.Close() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        if ($result.CleanupErrors.Count -gt 0) { Add-Check "probe.tcp.cleanup.$Port.$Attempt" 'Collection' 'ERROR' 'A TCP probe resource-cleanup error occurred; see the attempt details.' $result.CleanupErrors }
        $watch.Stop(); $result.ElapsedMilliseconds = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
    }
    return [pscustomobject]$result
}

function Read-VersionXml {
    param([byte[]]$Bytes)
    $memory = $null; $reader = $null
    try {
        $memory = New-Object IO.MemoryStream (,$Bytes)
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 16384
        $reader = [Xml.XmlReader]::Create($memory, $settings)
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        $nodes = @($document.SelectNodes("//*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='version']"))
        $values = @($nodes | Select-Object -First 32 | ForEach-Object { Limit-Text $_.InnerText 100 })
        return [pscustomobject]@{
            XmlParsed = $true; RootName = $document.DocumentElement.LocalName
            VersionValues = $values; VersionValuesCapped = ($nodes.Count -gt 32)
            ParseError = $null
        }
    } catch {
        return [pscustomobject]@{
            XmlParsed = $false; RootName = $null; VersionValues = @()
            VersionValuesCapped = $false; ParseError = (Protect-Excerpt $_.Exception.Message 300)
        }
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($memory) { $memory.Dispose() }
    }
}

function Test-HttpAttempt {
    param([int]$Attempt)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $request = $null; $response = $null; $stream = $null; $memory = $null
    $servicePoint = $null
    $connectionGroup = 'AzurePlatformDiagnostic-' + [Guid]::NewGuid().ToString('N')
    $result = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o'); Attempt = $Attempt
        Uri = 'http://168.63.129.16/?comp=versions'; MetadataHeader = 'true'
        ProxyUsed = $false; RedirectsAllowed = $false; SourceBindingApplied = $false
        ActualLocalEndpoint = 'Not exposed by HttpWebRequest; HTTP is unbound and can differ from bound TCP probes.'
        Status = 'FAIL'; HttpStatusCode = $null; HttpStatusDescription = $null
        BodyBytesRead = 0; BodyComplete = $false; BodyLimitReached = $false
        XmlParsed = $false; XmlRootName = $null; VersionValues = @()
        VersionValuesCapped = $false; ParseError = $null; ErrorKind = $null
        WebExceptionStatus = $null; Error = $null; CleanupErrors = @(); ElapsedMilliseconds = 0
    }
    try {
        $request = [Net.HttpWebRequest]::Create($result.Uri)
        $request.Method = 'GET'
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.KeepAlive = $false
        $request.AutomaticDecompression = [Net.DecompressionMethods]::None
        $request.Timeout = $TimeoutSeconds * 1000
        $request.ReadWriteTimeout = $TimeoutSeconds * 1000
        $request.ConnectionGroupName = $connectionGroup
        $request.Headers['Metadata'] = 'true'
        $servicePoint = $request.ServicePoint
        try {
            $response = [Net.HttpWebResponse]$request.GetResponse()
        } catch {
            $webError = Get-RootException $_.Exception
            if ($webError -is [Net.WebException] -and $webError.Response) {
                $response = [Net.HttpWebResponse]$webError.Response
                $result.HttpStatusCode = [int]$response.StatusCode
                $result.HttpStatusDescription = Limit-Text $response.StatusDescription 100
            }
            throw
        }
        $result.HttpStatusCode = [int]$response.StatusCode
        $result.HttpStatusDescription = Limit-Text $response.StatusDescription 100
        if ($result.HttpStatusCode -lt 200 -or $result.HttpStatusCode -ge 300) {
            $result.ErrorKind = 'HttpStatus'
            $result.Error = 'Non-success HTTP status; redirects are deliberately not followed and failure bodies are not retained.'
        } else {
            $stream = $response.GetResponseStream()
            $memory = New-Object IO.MemoryStream
            $buffer = New-Object byte[] 2048
            while ($memory.Length -lt 16384) {
                $remaining = ($TimeoutSeconds * 1000) - [int]$watch.ElapsedMilliseconds
                if ($remaining -le 0) { throw (New-Object TimeoutException 'HTTP attempt deadline reached while reading response.') }
                $take = [math]::Min($buffer.Length, 16384 - [int]$memory.Length)
                $readWait = $null
                try {
                    $pendingRead = $stream.BeginRead($buffer, 0, $take, $null, $null)
                    $readWait = $pendingRead.AsyncWaitHandle
                    if (-not $readWait.WaitOne($remaining)) {
                        $request.Abort()
                        throw (New-Object TimeoutException 'HTTP attempt deadline reached while awaiting response bytes.')
                    }
                    $read = $stream.EndRead($pendingRead)
                } finally { if ($readWait) { $readWait.Close() } }
                if ($read -eq 0) { $result.BodyComplete = $true; break }
                $memory.Write($buffer, 0, $read)
            }
            $result.BodyBytesRead = [int]$memory.Length
            $result.BodyLimitReached = ($memory.Length -ge 16384)
            if ($result.BodyLimitReached -and $response.ContentLength -eq $memory.Length) {
                $result.BodyComplete = $true
            }
            if (-not $result.BodyComplete) {
                $result.Status = 'WARN'
                $result.ErrorKind = 'BodyLimit'
                $result.Error = 'HTTP responded, but the bounded body was not confirmed complete; version parsing was skipped.'
            } else {
                $parsed = Read-VersionXml -Bytes $memory.ToArray()
                $result.XmlParsed = $parsed.XmlParsed
                $result.XmlRootName = $parsed.RootName
                $result.VersionValues = $parsed.VersionValues
                $result.VersionValuesCapped = $parsed.VersionValuesCapped
                $result.ParseError = $parsed.ParseError
                if ($parsed.XmlParsed -and $parsed.RootName -ieq 'Versions' -and $parsed.VersionValues.Count -gt 0) {
                    $result.Status = 'PASS'
                } else {
                    $result.Status = 'WARN'
                    $result.ErrorKind = 'UnexpectedBody'
                    $result.Error = 'HTTP succeeded, but a versions XML response was not recognized. This is not an Agent Ready check.'
                }
            }
        }
    } catch {
        $rootError = Get-RootException $_.Exception
        $result.Status = 'FAIL'; $result.ErrorKind = $rootError.GetType().Name
        if ($rootError -is [Net.WebException]) { $result.WebExceptionStatus = [string]$rootError.Status }
        $result.Error = Protect-Excerpt $rootError.Message 500
        if ($memory) { $result.BodyBytesRead = [int]$memory.Length }
    } finally {
        try { if ($stream) { $stream.Dispose() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        try { if ($memory) { $memory.Dispose() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        try { if ($response) { $response.Close() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        try { if ($request) { $request.Abort() } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        try { if ($servicePoint) { [void]$servicePoint.CloseConnectionGroup($connectionGroup) } } catch { $result.CleanupErrors += Protect-Excerpt $_.Exception.Message 300 }
        if ($result.CleanupErrors.Count -gt 0) { Add-Check "probe.http.cleanup.$Attempt" 'Collection' 'ERROR' 'An HTTP probe resource-cleanup error occurred; see the attempt details.' $result.CleanupErrors }
        $watch.Stop(); $result.ElapsedMilliseconds = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
    }
    return [pscustomobject]$result
}

function Invoke-DnsProbe {
    param([string]$Mode, [string]$Server, [bool]$TcpOnly)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = $null
    $result = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o'); Mode = $Mode
        Name = $DnsName; Server = $Server; TcpOnly = $TcpOnly
        SourceBindingApplied = $false; Status = 'ERROR'; Answers = @()
        AnswersMayBeCapped = $false; ErrorKind = $null; Error = $null
        ElapsedMilliseconds = 0
    }
    try {
        $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { throw 'Windows PowerShell executable is unavailable for bounded DNS probing.' }
        # Constrained hostname characters and fixed IP server values prevent command injection.
        $childHeader = '$queryName = ''' + $DnsName + "'`r`n" + '$queryServer = ''' + $Server + "'`r`n"
        $childHeader += '$queryTcpOnly = $' + ([string]$TcpOnly).ToLowerInvariant() + "`r`n"
        $child = @'
$ErrorActionPreference = 'Stop'
try {
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{Success=$false; Kind='Unsupported'; Error='Resolve-DnsName is unavailable.'; Answers=@()} | ConvertTo-Json -Compress
        exit 3
    }
    $queryParameters = @{Name=$queryName; Type='A'; DnsOnly=$true; NoHostsFile=$true; QuickTimeout=$true; ErrorAction='Stop'}
    if ($queryServer) { $queryParameters.Server = $queryServer }
    if ($queryTcpOnly) { $queryParameters.TcpOnly = $true }
    $answers = @(Resolve-DnsName @queryParameters | Select-Object -First 20 | ForEach-Object {
        [pscustomobject]@{Name=$_.Name; Type=[string]$_.Type; IPAddress=$_.IPAddress; NameHost=$_.NameHost; TTL=$_.TTL}
    })
    [pscustomobject]@{Success=$true; Answers=$answers} | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    $message = [string]$_.Exception.Message
    if ($message.Length -gt 500) { $message = $message.Substring(0,500) }
    [pscustomobject]@{Success=$false; Kind=$_.Exception.GetType().Name; Error=$message; Answers=@()} | ConvertTo-Json -Depth 4 -Compress
    exit 2
}
'@
        $child = $childHeader + $child
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $engine
        $start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Could not start the DNS diagnostic subprocess.' }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $result.Status = 'FAIL'; $result.ErrorKind = 'Timeout'
            $result.Error = "DNS diagnostic subprocess exceeded $TimeoutSeconds seconds (startup included)."
            try { $process.Kill(); [void]$process.WaitForExit(1000) } catch {
                $result.Error += ' Cleanup could not confirm subprocess termination: ' + (Protect-Excerpt $_.Exception.Message 200)
            }
        } else {
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            if ($stdout.Length -gt 65536) { throw 'DNS subprocess output exceeded the parsing cap.' }
            if ([string]::IsNullOrWhiteSpace($stdout)) { throw ('DNS subprocess returned no result. ' + (Protect-Excerpt $stderr 300)) }
            $answer = $stdout | ConvertFrom-Json
            if ($answer.Success) {
                $result.Answers = @($answer.Answers)
                $result.AnswersMayBeCapped = ($result.Answers.Count -ge 20)
                if (@($result.Answers | Where-Object { $_.IPAddress }).Count -gt 0) {
                    $result.Status = 'PASS'
                } else {
                    $result.Status = 'FAIL'; $result.ErrorKind = 'NoARecord'
                    $result.Error = 'Resolver returned no IPv4 A-record address in the bounded result.'
                }
            } else {
                $result.Status = 'FAIL'
                if ($answer.Kind -eq 'Unsupported') { $result.Status = 'ERROR' }
                $result.ErrorKind = $answer.Kind
                $result.Error = Protect-Excerpt $answer.Error 500
            }
        }
    } catch {
        $result.Status = 'ERROR'; $result.ErrorKind = $_.Exception.GetType().Name
        $result.Error = Protect-Excerpt $_.Exception.Message 500
    } finally {
        if ($process) {
            try { if (-not $process.HasExited) { $process.Kill() } } catch { }
            $process.Dispose()
        }
        $watch.Stop(); $result.ElapsedMilliseconds = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
    }
    return [pscustomobject]$result
}

function Convert-IPv4Number {
    param([string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $bytes = $parsed.GetAddressBytes()
    return ([uint64]$bytes[0] * 16777216 + [uint64]$bytes[1] * 65536 + [uint64]$bytes[2] * 256 + [uint64]$bytes[3])
}

function Test-AddressFilter {
    param([object[]]$Values)
    $targetNumber = Convert-IPv4Number $script:Target
    $unknown = $false; $seen = 0
    foreach ($value in $Values) {
        foreach ($token in ([string]$value).Split(',')) {
            $seen++
            if ($seen -gt 256) { return 'Unknown' }
            $token = $token.Trim()
            if ($token -ieq 'Any' -or $token -eq '*') { return 'Match' }
            if ($token -eq $script:Target) { return 'Match' }
            if ($token -match '^([^/]+)/([0-9]{1,2})$') {
                $network = Convert-IPv4Number $Matches[1]; $bits = [int]$Matches[2]
                if ($null -ne $network -and $bits -ge 0 -and $bits -le 32) {
                    $blockSize = [math]::Pow(2, 32 - $bits)
                    if ([math]::Floor($targetNumber / $blockSize) -eq [math]::Floor($network / $blockSize)) { return 'Match' }
                } elseif ($token -notmatch ':') { $unknown = $true }
            } elseif ($token -match '^([0-9.]+)\s*-\s*([0-9.]+)$') {
                $first = Convert-IPv4Number $Matches[1]; $last = Convert-IPv4Number $Matches[2]
                if ($null -eq $first -or $null -eq $last -or $first -gt $last) { $unknown = $true }
                elseif ($targetNumber -ge $first -and $targetNumber -le $last) { return 'Match' }
            } elseif ($null -ne (Convert-IPv4Number $token)) {
                continue
            } elseif ($token -match ':') {
                continue
            } else { $unknown = $true }
        }
    }
    if ($Values.Count -eq 0 -or $unknown) { return 'Unknown' }
    return 'NoMatch'
}

function Test-PortFilter {
    param([object[]]$Values, [int]$Port)
    $unknown = $false; $seen = 0
    foreach ($value in $Values) {
        foreach ($token in ([string]$value).Split(',')) {
            $seen++
            if ($seen -gt 64) { return 'Unknown' }
            $token = $token.Trim()
            if ($token -ieq 'Any' -or $token -eq '*') { return 'Match' }
            if ($token -match '^\d+$') {
                if ([long]$token -eq $Port) { return 'Match' }
            } elseif ($token -match '^(\d+)\s*-\s*(\d+)$') {
                if ($Port -ge [long]$Matches[1] -and $Port -le [long]$Matches[2]) { return 'Match' }
            } else { $unknown = $true }
        }
    }
    if ($Values.Count -eq 0 -or $unknown) { return 'Unknown' }
    return 'NoMatch'
}

function Get-ErrorCategories {
    param([string]$Line)
    $patterns = [ordered]@{
        WireServerFailure = '(?i)((WireServer|GetVersions).{0,120}(fail|error|unreach|time.?out)|(fail|error|unreach|time.?out).{0,120}(WireServer|GetVersions))'
        Socket32526Denied = '(?i)(32526.{0,120}(forbidden|denied|permission|10013)|(forbidden|denied|permission|10013).{0,120}32526)'
        Http503Hint = '(?i)\b503\b|service unavailable'
        GuestStoppingHint = '(?i)(guest.?agent.{0,60}(stopping|stopped|not running)|(stopping|stopped).{0,60}guest.?agent)'
        CryptoOrKeyIsoHint = '(?i)RdCrypt|PFXImportCertStore|\bError\s*86\b|KeyIso'
        DotNetImageHint = '(?i)BadImageFormatException|Enable64Bit'
        DotNetConfigurationHint = '(?i)ConfigurationErrorsException|TypeInitializationException|machine\.config'
    }
    foreach ($key in $patterns.Keys) { if ($Line -match $patterns[$key]) { $key } }
}

function Get-TimestampText {
    param([string]$Line)
    if ($Line -match '\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,7})?(?:Z|[+-]\d{2}:?\d{2})?') { return $Matches[0] }
    return $null
}

function Test-MachineConfigXml {
    param([string]$ConfigPath)
    $result = [ordered]@{
        Path = $ConfigPath; FilePresent = $false; FileBytes = $null
        LastWriteTimeUtc = $null; XmlStatus = 'NotRead'; ParserLine = $null
        ParserColumn = $null; ErrorType = $null; WcfProfilingReferenceFound = $false
        ContentsExported = $false; FileLimitBytes = 2097152
        Meaning = 'XML well-formedness only; valid XML does not establish correct .NET configuration. No configuration types are loaded, and no file is changed.'
    }
    $reader = $null; $stream = $null
    try {
        $item = Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
        if ($item.PSIsContainer) { $result.XmlStatus = 'NotAFile'; return [pscustomobject]$result }
        $result.FilePresent = $true; $result.FileBytes = $item.Length
        $result.LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
        if ($item.Length -eq 0) { $result.XmlStatus = 'Empty'; return [pscustomobject]$result }
        if ($item.Length -gt 2097152) { $result.XmlStatus = 'SizeLimit'; return [pscustomobject]$result }
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 2097152
        $settings.CloseInput = $false
        $stream = [IO.File]::Open($ConfigPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $reader = [Xml.XmlReader]::Create($stream, $settings)
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                $nodeName = [string]$reader.LocalName
                $attributeName = [string]$reader.GetAttribute('name')
                $attributeType = [string]$reader.GetAttribute('type')
                if (($nodeName + ' ' + $attributeName + ' ' + $attributeType) -match 'Microsoft\.VisualStudio\.Diagnostics\.ServiceModelSink\.Behavior') {
                    $result.WcfProfilingReferenceFound = $true
                }
            }
        }
        $result.XmlStatus = 'WellFormed'
    } catch {
        $root = Get-RootException $_.Exception
        $result.ErrorType = $root.GetType().FullName
        if ($root -is [Xml.XmlException]) {
            $result.XmlStatus = 'InvalidXml'
            $result.ParserLine = $root.LineNumber; $result.ParserColumn = $root.LinePosition
        } elseif ($root -is [UnauthorizedAccessException] -or $root -is [Security.SecurityException]) {
            $result.XmlStatus = 'AccessDenied'
        } elseif ($_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound' -or $root -is [IO.FileNotFoundException] -or $root -is [IO.DirectoryNotFoundException]) {
            $result.XmlStatus = 'Missing'
        } else { $result.XmlStatus = 'ReadError' }
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
    return [pscustomobject]$result
}

Assert-IPv4Parameter $ExpectedPrimaryIPv4 'ExpectedPrimaryIPv4'
Assert-IPv4Parameter $SourceIPv4 'SourceIPv4'
foreach ($label in $DnsName.TrimEnd('.').Split('.')) {
    if ($label.Length -lt 1 -or $label.Length -gt 63 -or $label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') {
        throw 'DnsName must be an ASCII DNS hostname with labels of 1 through 63 characters; use punycode for international names.'
    }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Get-Location).Path ('AzurePlatformConnectivity-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
}
if ($OutputDirectory -match '^[\\]{2}') { throw 'OutputDirectory must be local, not a UNC network share; this script does not upload reports.' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $outputDrive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($OutputDirectory))
    if ($outputDrive.DriveType -eq [IO.DriveType]::Network) { throw 'OutputDirectory must not be on a mapped network drive.' }
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory already exists. Choose a NEW directory; existing reports are never overwritten.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)

$hostIsWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$isAdministrator = $false
$adminError = $null
if ($hostIsWindows) {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $principal = New-Object Security.Principal.WindowsPrincipal $identity
            $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } finally { $identity.Dispose() }
    } catch { $adminError = Protect-Excerpt $_.Exception.Message 300 }
}
$metadata = [ordered]@{
    ScriptName = 'Test-AzurePlatformConnectivity.ps1'; ScriptVersion = '1.1.0'
    StartedUtc = $script:StartedUtc.ToString('o'); CompletedUtc = $null
    ComputerName = [Environment]::MachineName; Platform = [string][Environment]::OSVersion.Platform
    IsWindows = $hostIsWindows; IsAdministrator = $isAdministrator
    PowerShellVersion = [string]$PSVersionTable.PSVersion
    ProcessIs64Bit = [Environment]::Is64BitProcess; OSIs64Bit = [Environment]::Is64BitOperatingSystem
    OutputDirectory = $OutputDirectory; PlatformIPv4 = $script:Target
    Parameters = [ordered]@{
        TimeoutSeconds = $TimeoutSeconds; TotalAttempts = $RetryCount
        EventLookbackHours = $EventLookbackHours; DnsName = $DnsName
        SkipDns = [bool]$SkipDns; ExpectedPrimaryIPv4 = $ExpectedPrimaryIPv4
        SourceIPv4 = $SourceIPv4; IncludeLogSnippets = [bool]$IncludeLogSnippets
    }
}
Add-Check 'privacy' 'Scope' 'INFO' 'Reports contain internal host, IP, DNS, proxy, service-path, firewall and event information. Review before sharing. No reports are uploaded.'
if ($IncludeLogSnippets) {
    Add-Check 'privacy.snippets' 'Scope' 'WARN' 'Small matching log/event excerpts were requested. Best-effort redaction is NOT guaranteed; review every excerpt locally.'
}
if (-not $hostIsWindows) {
    Add-Check 'platform.windows' 'Prerequisites' 'ERROR' 'Unsupported operating system. Windows VM checks and network probes were not run.'
    Add-Check 'platform.skipped' 'Prerequisites' 'SKIPPED' 'All Windows-specific collection and Azure probes skipped on a non-Windows host.'
} else {
    Add-Check 'platform.windows' 'Prerequisites' 'PASS' 'Windows host detected. This does not establish that the host is an Azure VM.'
    if ($isAdministrator) {
        Add-Check 'platform.admin' 'Prerequisites' 'PASS' 'Running elevated as Administrator.'
    } elseif ($adminError) {
        Add-Check 'platform.admin' 'Prerequisites' 'ERROR' 'Administrator status could not be determined; treat collection as potentially incomplete.' $adminError
    } else {
        Add-Check 'platform.admin' 'Prerequisites' 'WARN' 'Not elevated. Probes continue, but Microsoft Windows troubleshooting instructions require Administrator and some evidence may be unavailable.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Add-Check 'platform.bitness' 'Prerequisites' 'WARN' '32-bit PowerShell on a 64-bit OS. Prefer elevated 64-bit Windows PowerShell to avoid filesystem/module view differences.'
    }

    Invoke-ReadSection 'OperatingSystem' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        [pscustomobject]@{Caption=$os.Caption; Version=$os.Version; BuildNumber=$os.BuildNumber; OSArchitecture=$os.OSArchitecture; LastBootUpTime=$os.LastBootUpTime; SystemDirectory=$os.SystemDirectory}
        Add-Check 'os.inventory' 'Context' 'INFO' 'Collected OS version and last boot time; no support verdict is inferred from this inventory.'
    }
    Invoke-ReadSection 'SystemDisk' {
        $drive = $env:SystemDrive
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction Stop
        if (-not $disk -or -not $disk.Size) { throw 'System drive capacity could not be read.' }
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $percent = [math]::Round(100 * $disk.FreeSpace / $disk.Size, 1)
        [pscustomobject]@{Drive=$drive; SizeBytes=$disk.Size; FreeBytes=$disk.FreeSpace; FreeGiB=$freeGB; FreePercent=$percent; Heuristic='Warn below 2 GiB OR 10 percent free; this is a script heuristic, not a Microsoft support rule.'}
        if ($freeGB -lt 2 -or $percent -lt 10) {
            Add-Check 'disk.space' 'Context' 'WARN' "System disk free space is $freeGB GiB ($percent%). Low-space heuristic only; not a proven agent fault."
        } else { Add-Check 'disk.space' 'Context' 'INFO' "System disk free space is $freeGB GiB ($percent%); above this script's heuristic thresholds." }
    }

    Invoke-ReadSection 'AgentServices' {
        $serviceNames = @('RdAgent', 'WindowsAzureGuestAgent', 'WindowsAzureTelemetryService', 'KeyIso')
        $all = @(Get-CimInstance Win32_Service -Filter "Name='RdAgent' OR Name='WindowsAzureGuestAgent' OR Name='WindowsAzureTelemetryService' OR Name='KeyIso'" -ErrorAction Stop)
        foreach ($name in $serviceNames) {
            $service = $all | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if (-not $service) {
                [pscustomobject]@{Name=$name; Present=$false; State=$null; StartMode=$null; ProcessId=$null; ExecutablePath=$null; FileVersion=$null; VersionError=$null}
                if ($name -in @('RdAgent', 'WindowsAzureGuestAgent')) {
                    Add-Check "agent.service.$name" 'Agent' 'FAIL' "Required agent service $name was not found."
                } else { Add-Check "agent.service.$name" 'Agent' 'INFO' "$name is absent; absence of a separate telemetry service can be normal. KeyIso is only contextual crypto evidence." }
                continue
            }
            $exe = $null; $version = $null; $versionError = $null
            $expandedPath = [Environment]::ExpandEnvironmentVariables([string]$service.PathName)
            if ($expandedPath -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
            elseif ($expandedPath -match '^\s*(.+?\.exe)(?:\s|$)') { $exe = $Matches[1] }
            if ($exe) {
                try { $version = (Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo.FileVersion }
                catch { $versionError = Protect-Excerpt $_.Exception.Message 300 }
            }
            [pscustomobject]@{Name=$name; Present=$true; State=$service.State; StartMode=$service.StartMode; ProcessId=$service.ProcessId; ExecutablePath=$exe; FileVersion=$version; VersionError=$versionError}
            if ($name -in @('RdAgent', 'WindowsAzureGuestAgent')) {
                if ($service.State -ne 'Running') {
                    Add-Check "agent.service.$name" 'Agent' 'FAIL' "$name is $($service.State), not Running. No restart was attempted."
                } elseif ($service.StartMode -ne 'Auto') {
                    Add-Check "agent.service.$name" 'Agent' 'WARN' "$name is Running, but startup mode is $($service.StartMode), not Automatic."
                } else { Add-Check "agent.service.$name" 'Agent' 'PASS' "$name is Running with Automatic startup. This is not an Azure Agent Ready check." }
            } else {
                Add-Check "agent.service.$name" 'Agent' 'INFO' "$name state: $($service.State); startup: $($service.StartMode). Do not treat an idle/demand-start KeyIso service or optional telemetry service as a fault by itself."
            }
            if ($versionError -or -not $exe) {
                Add-Check "agent.version.$name" 'Collection' 'WARN' "Executable/version information for $name is incomplete; see AgentServices evidence."
            }
        }
    }
    Invoke-ReadSection 'AgentProcesses' {
        $names = @('RdAgent.exe', 'WaAppAgent.exe', 'WindowsAzureGuestAgent.exe', 'WindowsAzureTelemetryService.exe')
        $items = @(Get-CimInstance Win32_Process -Filter "Name='RdAgent.exe' OR Name='WaAppAgent.exe' OR Name='WindowsAzureGuestAgent.exe' OR Name='WindowsAzureTelemetryService.exe'" -ErrorAction Stop | Select-Object -First 65)
        if ($items.Count -gt 64) { Add-Check 'agent.process.cap' 'Collection' 'WARN' 'Agent process evidence capped at 64 entries.' }
        $items | Select-Object -First 64 | ForEach-Object {
            $agentProcess = $_; $activeVersion = $null; $activeProductVersion = $null
            $binaryLastWriteUtc = $null; $binaryVersionError = $null
            if ($agentProcess.ExecutablePath) {
                try {
                    $binary = Get-Item -LiteralPath $agentProcess.ExecutablePath -ErrorAction Stop
                    $activeVersion = $binary.VersionInfo.FileVersion
                    $activeProductVersion = $binary.VersionInfo.ProductVersion
                    $binaryLastWriteUtc = $binary.LastWriteTimeUtc.ToString('o')
                } catch { $binaryVersionError = Protect-Excerpt $_.Exception.Message 300 }
            }
            [pscustomobject]@{Name=$agentProcess.Name; ProcessId=$agentProcess.ProcessId; ExecutablePath=$agentProcess.ExecutablePath; CreationDate=$agentProcess.CreationDate; ActiveFileVersion=$activeVersion; ActiveProductVersion=$activeProductVersion; BinaryLastWriteUtc=$binaryLastWriteUtc; VersionError=$binaryVersionError; TimestampMeaning='File timestamp is not an authoritative agent installation or upgrade time.'}
        }
        Add-Check 'agent.processes' 'Agent' 'INFO' 'Captured matching agent process states, without command lines. Service state is the main local service check; process names vary by version.'
    }

    Invoke-ReadSection 'NetworkAdapters' {
        $items = @(Get-NetAdapter -ErrorAction Stop | Select-Object -First 65)
        if ($items.Count -gt 64) { Add-Check 'network.adapters.cap' 'Collection' 'WARN' 'Adapter evidence capped at 64 entries.' }
        $items | Select-Object -First 64 | Select-Object Name, InterfaceDescription, ifIndex, Status, LinkSpeed
    }
    Invoke-ReadSection 'IPv4Addresses' {
        $items = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 257)
        if ($items.Count -gt 256) { Add-Check 'network.addresses.cap' 'Collection' 'WARN' 'IPv4 address evidence capped at 256 entries.' }
        $items | Select-Object -First 256 | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, AddressState, PrefixOrigin, SuffixOrigin, SkipAsSource
    }
    Invoke-ReadSection 'IPv4Interfaces' {
        $items = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 129)
        if ($items.Count -gt 128) { Add-Check 'network.interfaces.cap' 'Collection' 'WARN' 'IPv4 interface evidence capped at 128 entries.' }
        $items | Select-Object -First 128 | Select-Object InterfaceAlias, InterfaceIndex, ConnectionState, Dhcp, InterfaceMetric, NlMtu
    }
    Invoke-ReadSection 'DnsServerConfiguration' {
        $items = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 129)
        if ($items.Count -gt 128) { Add-Check 'network.dns.cap' 'Collection' 'WARN' 'DNS configuration evidence capped at 128 interfaces.' }
        $items | Select-Object -First 128 | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses
    }
    Invoke-ReadSection 'DefaultRoutes' {
        $items = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 129)
        if ($items.Count -gt 128) { Add-Check 'network.routes.cap' 'Collection' 'WARN' 'Default route evidence capped at 128 entries.' }
        $items | Select-Object -First 128 | Select-Object InterfaceAlias, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, State, PolicyStore
    }
    Invoke-ReadSection 'DhcpConfiguration' {
        $items = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | Select-Object -First 65)
        if ($items.Count -gt 64) { Add-Check 'network.dhcp.cap' 'Collection' 'WARN' 'DHCP adapter evidence capped at 64 entries.' }
        $items | Select-Object -First 64 | ForEach-Object {
            [pscustomobject]@{Description=$_.Description; InterfaceIndex=$_.InterfaceIndex; DHCPEnabled=$_.DHCPEnabled; DHCPServer=$_.DHCPServer; IPv4Addresses=@($_.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }); DnsServers=@($_.DNSServerSearchOrder)}
        }
    }
    Add-Check 'network.routes.scope' 'Network' 'INFO' 'Default routes are local context only, NOT the effective route to 168.63.129.16. The platform VIP is not subject to user-defined routes. Azure NIC primary cannot be confirmed locally.'
    $addresses = @(Get-SectionData 'IPv4Addresses')
    $addressListCapped = (@($script:Checks | Where-Object { $_.Id -eq 'network.addresses.cap' }).Count -gt 0)
    $npcap = @(Get-SectionData 'NetworkAdapters' | Where-Object { $_.InterfaceDescription -match '(?i)npcap|npf loopback' })
    if ($npcap.Count -gt 0) { Add-Check 'network.npcap' 'Network' 'WARN' 'Npcap/NPF loopback adapter evidence found. It can affect fabric-address discovery in some cases; presence alone does not establish a cause.' }
    if ($SourceIPv4) {
        if ($addresses.Count -eq 0) { Add-Check 'network.source' 'Network' 'WARN' 'SourceIPv4 was requested, but local address collection is empty/unavailable. Binding failures will be recorded by each probe.' }
        elseif (@($addresses | Where-Object { $_.IPAddress -eq $SourceIPv4 }).Count -eq 0) {
            $sourceStatus = 'FAIL'
            if ($addressListCapped) { $sourceStatus = 'WARN' }
            Add-Check 'network.source' 'Network' $sourceStatus "Requested source $SourceIPv4 was not found in local IPv4 evidence. If the list was capped, absence is unconfirmed. A bad source selection can itself cause probe failures."
        } else { Add-Check 'network.source' 'Network' 'INFO' "Only TCP probes request source $SourceIPv4. HTTP and DNS are unbound and can use a different source; cross-test differences need careful interpretation." }
    }
    if ($ExpectedPrimaryIPv4) {
        $expected = @($addresses | Where-Object { $_.IPAddress -eq $ExpectedPrimaryIPv4 })
        if ($script:Evidence['IPv4Addresses'].CollectionStatus -ne 'Collected') {
            Add-Check 'network.expected' 'Network' 'ERROR' 'Cannot compare ExpectedPrimaryIPv4 because local address collection failed.'
        } elseif ($expected.Count -eq 0) {
            $expectedStatus = 'FAIL'
            if ($addressListCapped) { $expectedStatus = 'WARN' }
            Add-Check 'network.expected' 'Network' $expectedStatus "Expected primary $ExpectedPrimaryIPv4 was not found in guest IPv4 evidence. If the list was capped, absence is unconfirmed. Confirm the expected value and actual Azure NIC primary separately."
        } elseif (@($expected | Where-Object { -not $_.SkipAsSource -and [string]$_.AddressState -eq 'Preferred' }).Count -eq 0) {
            Add-Check 'network.expected' 'Network' 'WARN' "Expected address $ExpectedPrimaryIPv4 is present, but is not a Preferred/non-SkipAsSource candidate in the guest. Azure primary matching is still unverified."
        } else { Add-Check 'network.expected' 'Network' 'PASS' "Expected address $ExpectedPrimaryIPv4 is present as a Preferred/non-SkipAsSource local candidate. This does NOT confirm Azure NIC primary or actual agent source selection." }
    } else { Add-Check 'network.expected' 'Network' 'SKIPPED' 'No ExpectedPrimaryIPv4 supplied; Azure NIC primary matching cannot be checked locally.' }
    $staticAdapters = @(Get-SectionData 'DhcpConfiguration' | Where-Object { -not $_.DHCPEnabled -and @($_.IPv4Addresses | Where-Object { $_ -notmatch '^(127\.|169\.254\.)' }).Count -gt 0 })
    if ($staticAdapters.Count -gt 0) {
        Add-Check 'network.dhcp' 'Network' 'WARN' 'Guest-static IPv4 configuration found. Microsoft recommends guest DHCP for a single-private-IP VM; multi-IP configuration needs separate review. Do not blindly enable DHCP or remove secondary addresses.'
    } else { Add-Check 'network.dhcp' 'Network' 'INFO' 'No guest-static IPv4 adapter found in available DHCP evidence. This does not verify Azure-side addressing or exclude collection gaps.' }

    $tcp = New-Object 'System.Collections.Generic.List[object]'
    foreach ($port in @(80, 32526)) {
        for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
            [void]$tcp.Add((Test-TcpAttempt -Port $port -Attempt $attempt))
        }
        $samples = @($tcp | Where-Object { $_.Port -eq $port })
        $passed = @($samples | Where-Object { $_.Status -eq 'PASS' }).Count
        if ($passed -eq $RetryCount) {
            Add-Check "probe.tcp.$port" 'Connectivity' 'PASS' "All $RetryCount TCP connections to 168.63.129.16:$port succeeded from this process/source; this does not prove agent-specific filtering is absent."
        } elseif ($passed -eq 0) {
            Add-Check "probe.tcp.$port" 'Connectivity' 'FAIL' "All $RetryCount TCP connections to 168.63.129.16:$port failed. Review per-attempt errors; no root cause is inferred."
        } else { Add-Check "probe.tcp.$port" 'Connectivity' 'WARN' "$passed of $RetryCount TCP connections to 168.63.129.16:$port succeeded; intermittent evidence, not a consistently healthy result." }
    }
    $script:Evidence['TcpProbes'] = [pscustomobject]@{CollectionStatus='Collected'; CollectedUtc=[DateTime]::UtcNow.ToString('o'); Data=@($tcp.ToArray()); Error=$null}
    $http = New-Object 'System.Collections.Generic.List[object]'
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) { [void]$http.Add((Test-HttpAttempt -Attempt $attempt)) }
    $httpPassed = @($http | Where-Object { $_.Status -eq 'PASS' }).Count
    $httpStatus = 'WARN'
    if ($httpPassed -eq $RetryCount) { $httpStatus = 'PASS' }
    elseif (@($http | Where-Object { $_.Status -eq 'FAIL' }).Count -eq $RetryCount) { $httpStatus = 'FAIL' }
    Add-Check 'probe.http' 'Connectivity' $httpStatus "$httpPassed of $RetryCount direct Metadata=true GET requests returned recognized versions XML. No proxy or redirects were used. This does NOT establish Azure Agent Ready."
    $script:Evidence['HttpProbes'] = [pscustomobject]@{CollectionStatus='Collected'; CollectedUtc=[DateTime]::UtcNow.ToString('o'); Data=@($http.ToArray()); Error=$null}

    Invoke-ReadSection 'ProxySettings' {
        $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
        $winHttp = @(& $netsh winhttp show proxy 2>&1)
        $netshExit = $LASTEXITCODE
        $safeWinHttp = @($winHttp | Select-Object -First 30 | ForEach-Object { Protect-Excerpt $_ 300 })
        $currentUser = [ordered]@{Scope='Current user only; not necessarily the agent service identity'; ProxyEnable=$null; ProxyServer=$null; ProxyOverride=$null; AutoConfigURL=$null; AutoDetect=$null; CollectionError=$null}
        try {
            $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            if (Test-Path -LiteralPath $path) {
                $settings = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
                foreach ($key in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')) {
                    $property = $settings.PSObject.Properties[$key]
                    if ($property) { $currentUser[$key] = Protect-Excerpt $property.Value 500 }
                }
            }
        } catch { $currentUser.CollectionError = Protect-Excerpt $_.Exception.Message 300 }
        [pscustomobject]@{WinHttpCommandExitCode=$netshExit; WinHttpText=$safeWinHttp; WinHttpTextMayBeCapped=($winHttp.Count -gt 30); CurrentUser=[pscustomobject]$currentUser}
        if ($netshExit -ne 0 -or $currentUser.CollectionError) {
            Add-Check 'proxy.collection' 'Collection' 'ERROR' 'Proxy evidence is incomplete. See the command exit code/current-user collection error.'
        }
        Add-Check 'proxy.scope' 'Proxy' 'INFO' 'Captured WinHTTP and selected current-user proxy settings, read-only. Agent service identities can use different settings. The HTTP probe deliberately bypasses proxies; it does not test the agent proxy configuration.'
    }
    Invoke-ReadSection 'FirewallProfiles' {
        Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, AllowLocalIPsecRules
    }
    $blockProfiles = @(Get-SectionData 'FirewallProfiles' | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.DefaultOutboundAction -eq 'Block' })
    if ($blockProfiles.Count -gt 0) { Add-Check 'firewall.defaultblock' 'Firewall' 'WARN' 'An enabled firewall profile has default outbound Block. Profile applicability and effective allow/block conditions require review; this is not proof it blocked these attempts.' }
    Invoke-ReadSection 'FirewallCandidates' {
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Block -ErrorAction Stop | Select-Object -First 101)
        $ruleCap = ($rules.Count -gt 100)
        $candidates = New-Object 'System.Collections.Generic.List[object]'
        $gaps = New-Object 'System.Collections.Generic.List[object]'
        $candidateCount = 0; $inspected = 0; $gapCount = 0
        foreach ($rule in ($rules | Select-Object -First 100)) {
            $inspected++
            try {
                $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
                $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
                $protocol = [string]$portFilter.Protocol
                $protocolMatch = 'Unknown'
                if ($protocol -in @('TCP', '6', 'Any', '256')) { $protocolMatch = 'Match' }
                elseif ($protocol -match '^\d+$' -or $protocol -in @('UDP', 'ICMPv4', 'ICMPv6')) { $protocolMatch = 'NoMatch' }
                $addressMatch = Test-AddressFilter @($address.RemoteAddress)
                $port80 = Test-PortFilter @($portFilter.RemotePort) 80
                $port32526 = Test-PortFilter @($portFilter.RemotePort) 32526
                if ($protocolMatch -ne 'NoMatch' -and $addressMatch -ne 'NoMatch' -and ($port80 -ne 'NoMatch' -or $port32526 -ne 'NoMatch')) {
                    $candidateCount++
                    if ($candidates.Count -lt 50) {
                        [void]$candidates.Add([pscustomobject]@{
                            Name=$rule.Name; DisplayName=(Limit-Text $rule.DisplayName 200)
                            Profile=[string]$rule.Profile; PolicyStoreSourceType=[string]$rule.PolicyStoreSourceType
                            Protocol=$protocol; ProtocolMatch=$protocolMatch; RemoteAddressMatch=$addressMatch
                            Tcp80PortMatch=$port80; Tcp32526PortMatch=$port32526
                            LocalAddress=@($address.LocalAddress | Select-Object -First 32)
                            RemoteAddress=@($address.RemoteAddress | Select-Object -First 32)
                            LocalPort=@($portFilter.LocalPort | Select-Object -First 32)
                            RemotePort=@($portFilter.RemotePort | Select-Object -First 32)
                            Program=(Limit-Text $application.Program 500); Service=(Limit-Text $service.Service 200)
                            FilterValuesCapped=(@($address.LocalAddress).Count -gt 32 -or @($address.RemoteAddress).Count -gt 32 -or @($portFilter.LocalPort).Count -gt 32 -or @($portFilter.RemotePort).Count -gt 32)
                            Meaning='Candidate only: local/source ports, profile, interface, program, service, policy and third-party filters can change applicability.'
                        })
                    }
                }
            } catch {
                $gapCount++
                if ($gaps.Count -lt 10) { [void]$gaps.Add([pscustomobject]@{RuleName=$rule.Name; Error=(Protect-Excerpt $_.Exception.Message 300)}) }
                $candidateCount++
            }
        }
        [pscustomobject]@{RulesInspected=$inspected; RulesCapped=$ruleCap; CandidateOrUnclassifiedCount=$candidateCount; CandidatesRetained=$candidates.Count; CandidatesCapped=($candidateCount -gt 50); Candidates=@($candidates.ToArray()); CollectionGapCount=$gapCount; CollectionGapExamples=@($gaps.ToArray()); CollectionGapsMayBeCapped=($gapCount -gt 10)}
        if ($ruleCap -or $candidateCount -gt 50) { Add-Check 'firewall.cap' 'Collection' 'WARN' 'Firewall scan/result cap reached; uninspected or unretained rules can matter.' }
        if ($gaps.Count -gt 0) { Add-Check 'firewall.filters.error' 'Collection' 'ERROR' 'Some firewall rule filters could not be read. Unclassified rules are not assumed harmless; see bounded gap examples.' }
        if ($candidateCount -gt 0) {
            Add-Check 'firewall.candidates' 'Firewall' 'WARN' "$candidateCount candidate or unclassified outbound block rules found. Candidate matching is NOT proof of effective blocking."
        } else {
            Add-Check 'firewall.candidates' 'Firewall' 'INFO' 'No candidates found in the bounded Windows firewall scan. This does NOT exclude uninspected rules, IPsec, application/service-specific filtering, or third-party firewall/security controls.'
        }
    }

    if ($SkipDns) { Add-Check 'dns.skipped' 'DNS' 'SKIPPED' 'DNS probes were disabled with SkipDns; no DNS health conclusion is available.' }
    else {
        $dnsResults = New-Object 'System.Collections.Generic.List[object]'
        foreach ($mode in @('ConfiguredResolver', 'DirectAzureDns')) {
            $server = ''
            if ($mode -eq 'DirectAzureDns') { $server = $script:Target }
            foreach ($tcpOnly in @($false, $true)) {
                $dnsResult = Invoke-DnsProbe -Mode $mode -Server $server -TcpOnly $tcpOnly
                [void]$dnsResults.Add($dnsResult)
                $transport = 'default transport (may use cache, UDP and/or TCP)'
                if ($tcpOnly) { $transport = 'TCP-only resolver option' }
                $status = $dnsResult.Status
                if ($mode -eq 'DirectAzureDns' -and $status -eq 'FAIL') { $status = 'WARN' }
                Add-Check ("dns.$mode.$tcpOnly") 'DNS' $status "$mode, $transport, A query for ${DnsName}: $($dnsResult.Status). Direct Azure DNS failure is advisory in a custom-DNS environment, not proof of an agent-port fault." $dnsResult
            }
        }
        $script:Evidence['DnsProbes'] = [pscustomobject]@{CollectionStatus='Collected'; CollectedUtc=[DateTime]::UtcNow.ToString('o'); Data=@($dnsResults.ToArray()); Error=$null}
        Add-Check 'dns.scope' 'DNS' 'INFO' 'DNS uses TCP/UDP 53 and different NSG rules. Default resolver success does not prove UDP-only transport. No PTR query is made: 168.63.129.16 has no reverse DNS.'
    }

    Invoke-ReadSection 'RecentEvents' {
        foreach ($logName in @('System', 'Application')) {
            $events = @()
            try {
                $events = @(Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=(Get-Date).AddHours(-$EventLookbackHours)} -MaxEvents 300 -ErrorAction Stop)
            } catch {
                if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                    $eventError = Protect-Excerpt $_.Exception.Message 500
                    [pscustomobject]@{LogName=$logName; CollectionStatus='Error'; Error=$eventError}
                    Add-Check "events.collection.$logName" 'Collection' 'ERROR' "Could not read the bounded $logName event sample; the other log is checked independently." $eventError
                    continue
                }
            }
            $retained = New-Object 'System.Collections.Generic.List[object]'
            $matched = 0; $messageGaps = 0; $excerpts = 0
            foreach ($event in $events) {
                $message = $null
                try { $message = [string]$event.Message } catch { $messageGaps++; continue }
                if ($message -notmatch '(?i)WindowsAzure|WaAppAgent|RdAgent|WindowsAzureGuestAgent|guest.?agent|WireServer|32526') { continue }
                $matched++
                if ($retained.Count -ge 40) { continue }
                $excerpt = $null
                if ($IncludeLogSnippets -and $excerpts -lt 10) { $excerpt = Protect-Excerpt $message 400; $excerpts++ }
                $eventTime = $null
                if ($event.TimeCreated) { $eventTime = $event.TimeCreated.ToUniversalTime().ToString('o') }
                [void]$retained.Add([pscustomobject]@{TimeCreatedUtc=$eventTime; Id=$event.Id; ProviderName=$event.ProviderName; Level=$event.LevelDisplayName; RecordId=$event.RecordId; KeywordCategories=@(Get-ErrorCategories $message); Excerpt=$excerpt})
            }
            [pscustomobject]@{LogName=$logName; LookbackHours=$EventLookbackHours; EventsScanned=$events.Count; ScanCapReached=($events.Count -ge 300); RelatedEventsObserved=$matched; RelatedEventsRetained=$retained.Count; RelatedEventsCapped=($matched -gt 40); MessageCollectionGaps=$messageGaps; Events=@($retained.ToArray())}
            if ($events.Count -ge 300 -or $matched -gt 40) { Add-Check "events.cap.$logName" 'Collection' 'WARN' "$logName event scan/retention cap reached. Older or unretained relevant events may be missing." }
            if ($messageGaps -gt 0) { Add-Check "events.messages.$logName" 'Collection' 'ERROR' "$messageGaps event messages could not be rendered in $logName; relevance could not be evaluated." }
            if ($matched -gt 0) { Add-Check "events.related.$logName" 'Logs' 'INFO' "$matched potentially agent-related events found in the bounded $logName sample. Presence is not a cause; review timestamp, level and event ID." }
            else { Add-Check "events.related.$logName" 'Logs' 'INFO' "No agent-related events matched in the bounded $logName sample; this does not exclude historical issues." }
        }
    }

    Invoke-ReadSection 'AgentLogTails' {
        $roots = @('C:\WindowsAzure\Logs')
        $systemRoot = Join-Path $env:SystemDrive 'WindowsAzure\Logs'
        if ($systemRoot -ne $roots[0]) { $roots += $systemRoot }
        foreach ($root in $roots) {
            foreach ($fileName in @('WaAppAgent.log', 'TransparentInstaller.log')) {
                $path = Join-Path $root $fileName
                $fileStream = $null; $textReader = $null
                try {
                    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                        [pscustomobject]@{Path=$path; Present=$false; CollectionStatus='NotFound'; Meaning='Absence at this conventional location does not establish a missing agent; location/version can differ.'}
                        Add-Check "logs.absent.$path" 'Logs' 'INFO' "$path was not found; no custom log-location discovery was attempted."
                        continue
                    }
                    $item = Get-Item -LiteralPath $path -ErrorAction Stop
                    $fileStream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                    $startOffset = [math]::Max(0, $fileStream.Length - 262144)
                    [void]$fileStream.Seek($startOffset, [IO.SeekOrigin]::Begin)
                    $bytes = New-Object byte[] 262144
                    $total = 0
                    while ($total -lt $bytes.Length) {
                        $read = $fileStream.Read($bytes, $total, $bytes.Length - $total)
                        if ($read -eq 0) { break }
                        $total += $read
                    }
                    $tail = [Text.Encoding]::UTF8.GetString($bytes, 0, $total)
                    $lines = @($tail -split '\r?\n')
                    if ($startOffset -gt 0 -and $lines.Count -gt 0) { $lines = @($lines | Select-Object -Skip 1) }
                    $linesBeforeCap = $lines.Count
                    $lines = @($lines | Select-Object -Last 400)
                    $counts = [ordered]@{WireServerFailure=0; Socket32526Denied=0; Http503Hint=0; GuestStoppingHint=0; CryptoOrKeyIsoHint=0; DotNetImageHint=0; DotNetConfigurationHint=0}
                    $snippets = New-Object 'System.Collections.Generic.List[object]'
                    $timestamps = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($line in $lines) {
                        $stamp = Get-TimestampText $line
                        if ($stamp) { [void]$timestamps.Add($stamp) }
                        $categories = @(Get-ErrorCategories $line)
                        foreach ($category in $categories) { $counts[$category]++ }
                        if ($IncludeLogSnippets -and $categories.Count -gt 0 -and $snippets.Count -lt 20) {
                            [void]$snippets.Add([pscustomobject]@{TimestampText=$stamp; Categories=$categories; Text=(Protect-Excerpt $line 400)})
                        }
                    }
                    $firstStamp = $null; $lastStamp = $null
                    if ($timestamps.Count -gt 0) { $firstStamp = $timestamps[0]; $lastStamp = $timestamps[$timestamps.Count - 1] }
                    [pscustomobject]@{Path=$path; Present=$true; CollectionStatus='Collected'; FileBytes=$item.Length; LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o'); BytesRead=$total; LinesScanned=$lines.Count; ByteTailLimited=($startOffset -gt 0 -or $total -ge 262144); LineTailLimited=($linesBeforeCap -gt 400); FirstTimestampText=$firstStamp; LastTimestampText=$lastStamp; TimestampMeaning='Text extracted from sampled lines; timezone may be unknown and age is not filtered by EventLookbackHours.'; EncodingAssumption='UTF-8; partial first line discarded if seeking into file.'; CategoryLineCounts=[pscustomobject]$counts; Snippets=@($snippets.ToArray()); SnippetsLimit=20}
                    $hints = @($counts.Keys | Where-Object { $counts[$_] -gt 0 })
                    if ($hints.Count -gt 0) { Add-Check "logs.hints.$path" 'Logs' 'WARN' "Keyword hints found in the bounded tail of $fileName. Counts are matching lines, not a root-cause diagnosis; correlate timestamps and nearby context locally." ([pscustomobject]$counts) }
                    else { Add-Check "logs.hints.$path" 'Logs' 'INFO' "No selected keyword hints found in the bounded tail of $fileName; this does not prove the agent is healthy." }
                } catch {
                    [pscustomobject]@{Path=$path; CollectionStatus='Error'; Error=(Protect-Excerpt $_.Exception.Message 500)}
                    Add-Check "logs.collection.$path" 'Collection' 'ERROR' "Could not read bounded log tail: $path." (Protect-Excerpt $_.Exception.Message 300)
                } finally {
                    if ($textReader) { $textReader.Dispose() }
                    if ($fileStream) { $fileStream.Dispose() }
                }
            }
        }
    }
    Invoke-ReadSection 'AgentDotNetEvents' {
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='.NET Runtime'; Id=1026; StartTime=(Get-Date).AddHours(-$EventLookbackHours)} -MaxEvents 50 -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
        }
        $matches = New-Object 'System.Collections.Generic.List[object]'
        foreach ($event in $events) {
            $message = [string]$event.Message
            if ($message -notmatch '(?i)WindowsAzureGuestAgent|WaAppAgent|RdAgent') { continue }
            if ($message -notmatch '(?i)ConfigurationErrorsException|TypeInitializationException') { continue }
            $excerpt = $null
            if ($IncludeLogSnippets) { $excerpt = Protect-Excerpt $message 400 }
            $eventTime = $null
            if ($event.TimeCreated) { $eventTime = $event.TimeCreated.ToUniversalTime().ToString('o') }
            [void]$matches.Add([pscustomobject]@{TimeCreatedUtc=$eventTime; Id=$event.Id; Provider=$event.ProviderName; RecordId=$event.RecordId; Categories=@(Get-ErrorCategories $message); Excerpt=$excerpt})
        }
        [pscustomobject]@{EventsScanned=$events.Count; ScanCapReached=($events.Count -ge 50); MatchingEvents=@($matches.ToArray()); LookbackHours=$EventLookbackHours}
        if ($events.Count -ge 50) { Add-Check 'dotnet.events.cap' 'Collection' 'WARN' 'The targeted .NET Runtime event 1026 scan reached its 50-event cap; older events may be omitted.' }
        if ($matches.Count -gt 0) {
            Add-Check 'dotnet.events.configuration' 'Agent context' 'WARN' "$($matches.Count) agent-specific configuration/startup exception events matched. Correlate their UTC times with machine.config and agent-version evidence; no cause is proven."
        } else { Add-Check 'dotnet.events.configuration' 'Agent context' 'INFO' 'No agent-specific configuration/startup exception matched in the targeted bounded .NET Runtime event 1026 sample. This does not exclude older or unlogged errors.' }
    }
    Invoke-ReadSection 'MachineConfigXml' {
        $configPath = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config'
        $frameworkPath = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319'
        $configResult = Test-MachineConfigXml -ConfigPath $configPath
        $configResult
        switch ($configResult.XmlStatus) {
            'WellFormed' { Add-Check 'dotnet.configxml' 'Agent context' 'INFO' 'Framework64 machine.config is readable and well-formed XML. This does NOT validate .NET section types, assembly references, permissions of the agent identity or configuration semantics.' }
            'Missing' {
                if (Test-Path -LiteralPath $frameworkPath -PathType Container) { Add-Check 'dotnet.configxml' 'Agent context' 'WARN' 'Framework64 exists but machine.config is missing. Correlate with current agent startup exceptions; no replacement was attempted.' }
                else { Add-Check 'dotnet.configxml' 'Agent context' 'SKIPPED' 'Framework64 v4 directory is not present. Its installation/support state is not established by this check.' }
            }
            'InvalidXml' { Add-Check 'dotnet.configxml' 'Agent context' 'FAIL' "machine.config XML parsing failed at line $($configResult.ParserLine), column $($configResult.ParserColumn). The parser prohibits DTDs and external resolution. This is configuration evidence, not proof of incident causation." }
            'Empty' { Add-Check 'dotnet.configxml' 'Agent context' 'FAIL' 'machine.config exists but is empty. No replacement or service restart was attempted.' }
            'SizeLimit' { Add-Check 'dotnet.configxml' 'Collection' 'WARN' 'machine.config exceeds the 2 MiB limit; XML validation was not attempted.' }
            default { Add-Check 'dotnet.configxml' 'Collection' 'ERROR' "machine.config could not be validated: $($configResult.XmlStatus). A collection/access failure is not a healthy result." $configResult.ErrorType }
        }
        if ($configResult.WcfProfilingReferenceFound) { Add-Check 'dotnet.wcfprofiling' 'Agent context' 'WARN' 'A ServiceModelSink WCF-profiling reference was observed in machine.config. Presence alone is not a fault; correlate with current startup exceptions and approved profiling configuration.' }
    }
    Invoke-ReadSection 'DotNetContext' {
        $baseKey = $null; $key = $null
        $registryView = [Microsoft.Win32.RegistryView]::Registry32
        if ([Environment]::Is64BitOperatingSystem) { $registryView = [Microsoft.Win32.RegistryView]::Registry64 }
        $value = $null; $valuePresent = $false; $keyPresent = $false
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $registryView)
            $key = $baseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework', $false)
            if ($key) { $keyPresent = $true; $valuePresent = ($key.GetValueNames() -contains 'Enable64Bit'); $value = $key.GetValue('Enable64Bit', $null) }
        } finally {
            if ($key) { $key.Dispose() }
            if ($baseKey) { $baseKey.Dispose() }
        }
        $configPath = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config'
        $frameworkDirectory = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319'
        $directoryExists = Test-Path -LiteralPath $frameworkDirectory -PathType Container
        $configExists = Test-Path -LiteralPath $configPath -PathType Leaf
        $configBytes = $null; $configWrite = $null
        if ($configExists) { $config = Get-Item -LiteralPath $configPath -ErrorAction Stop; $configBytes = $config.Length; $configWrite = $config.LastWriteTimeUtc.ToString('o') }
        [pscustomobject]@{RegistryView=[string]$registryView; DotNetRegistryKeyPresent=$keyPresent; Enable64BitExplicitlyPresent=$valuePresent; Enable64BitValue=$value; Framework64V4DirectoryPresent=$directoryExists; MachineConfigPath=$configPath; MachineConfigPresent=$configExists; MachineConfigBytes=$configBytes; MachineConfigLastWriteUtc=$configWrite; MachineConfigContentsRead=$false; Meaning='Presence/size and one registry value only; no integrity, permissions, crypto-key access or .NET health validation.'}
        if ([Environment]::Is64BitOperatingSystem -and $valuePresent -and $value -eq 0) {
            Add-Check 'dotnet.enable64bit' 'Agent context' 'WARN' 'Enable64Bit is explicitly 0 in the 64-bit .NET registry view. Correlate with BadImageFormatException before considering any approved repair; no value was changed.'
        } else { Add-Check 'dotnet.enable64bit' 'Agent context' 'INFO' 'No explicit Enable64Bit=0 evidence found in the inspected view. An absent value is not automatically an error.' }
        if ([Environment]::Is64BitOperatingSystem -and $directoryExists -and (-not $configExists -or $configBytes -eq 0)) {
            Add-Check 'dotnet.machineconfig' 'Agent context' 'WARN' 'Framework64 v4 directory exists, but machine.config is absent/empty. Correlate with agent .NET configuration errors; no repair or file-content collection was attempted.'
        } else { Add-Check 'dotnet.machineconfig' 'Agent context' 'INFO' 'Collected Framework64 v4 machine.config presence/size only; presence does not prove correctness and a missing framework directory is not diagnosed here.' }
    }
}

Add-Check 'azure.boundaries' 'Scope' 'INFO' 'Local-only: cannot query Azure Agent Ready, confirm Azure NIC primary, inspect AzurePlatformDNS NSG rules, or validate inbound load-balancer health probes. All PASS does not mean the VM is fully healthy.'
Add-Check 'azure.agent.networkrules' 'Scope' 'INFO' 'VM Agent connections to 168.63.129.16 on TCP 80/32526 are not subject to configured NSGs; the VIP is not subject to UDRs. DNS and inbound AzureLoadBalancer probes have different rules.'

$badTcp = @($script:Checks | Where-Object { $_.Id -like 'probe.tcp.*' -and $_.Status -in @('FAIL', 'WARN') })
if ($badTcp.Count -gt 0) {
    Add-NextStep 1 'Failed or intermittent platform TCP attempts' 'Review the per-attempt timeout/socket errors and actual source endpoints. Check guest firewall/security application policy and source/address configuration with the VM/security owner. These specific TCP 80/32526 connections are NSG-exempt; do not assume an NSG or UDR change will fix them.'
}
if ($SourceIPv4 -and @($script:Checks | Where-Object { $_.Id -eq 'network.source' -and $_.Status -in @('FAIL', 'WARN') }).Count -gt 0) {
    Add-NextStep 1 'Requested probe source may be unsuitable or unverified' 'Confirm the source address is assigned and usable on the intended guest NIC. Compare with an unbound run in a NEW folder; a bind/address error is not proof of platform failure.'
}
if (@($script:Checks | Where-Object { $_.Id -like 'agent.service.*' -and $_.Status -in @('FAIL', 'WARN') }).Count -gt 0) {
    Add-NextStep 1 'Required local agent service evidence is abnormal' 'Review RdAgent and WindowsAzureGuestAgent states/startup modes, installation/version and contemporaneous agent logs. Follow Microsoft supported troubleshooting under change control; this script neither restarts nor reinstalls anything.'
}
if (@($script:Checks | Where-Object { $_.Id -eq 'probe.http' -and $_.Status -in @('FAIL', 'WARN') }).Count -gt 0) {
    Add-NextStep 2 'Direct versions endpoint did not consistently pass' 'Compare HTTP status, XML parsing, body cap and TCP 80 results. A successful socket is not a successful WireServer exchange. Check guest interception/proxy behavior and time-correlated agent logs; the direct probe does not reproduce every service identity or proxy setting.'
}
if (@($script:Checks | Where-Object { $_.Id -in @('firewall.candidates', 'firewall.defaultblock') -and $_.Status -eq 'WARN' }).Count -gt 0) {
    Add-NextStep 2 'Windows firewall candidate/default-block evidence' 'Review effective policy applicability (program, service, source/local port, address, profile, interface and policy source) with the security owner. Candidate rules are not proof of a block; keep protection enabled and avoid blanket exceptions.'
}
if (@($script:Checks | Where-Object { $_.Id -like 'dns.*' -and $_.Status -in @('FAIL', 'WARN', 'ERROR') }).Count -gt 0) {
    Add-NextStep 2 'DNS failure or evidence gap' 'Check configured DNS resolution separately from agent TCP connectivity. In a custom-DNS design, direct Azure DNS failure can be expected/advisory. If Azure DNS is intended, review guest TCP/UDP 53 and AzurePlatformDNS-targeted NSG policy in Azure; default resolver success is not a UDP-only test.'
}
if (@($script:Checks | Where-Object { $_.Id -in @('network.expected', 'network.dhcp', 'network.npcap') -and $_.Status -in @('FAIL', 'WARN') }).Count -gt 0) {
    Add-NextStep 2 'Guest address/DHCP/adapter evidence needs review' 'Verify the Azure NIC primary IPv4 against the guest intended primary, especially with multiple private IPs. For single-IP guests, review DHCP and set stable addressing on the Azure NIC rather than blindly changing Windows. Npcap presence is only a lead, not a cause.'
}
if (@($script:Checks | Where-Object { ($_.Id -like 'logs.hints.*' -or $_.Id -like 'dotnet.*') -and $_.Status -eq 'WARN' }).Count -gt 0) {
    Add-NextStep 3 'Agent log/.NET/crypto hints' 'Correlate sampled timestamps with current failures. Use the README error-hint table to investigate WireServer, forbidden socket access, 503, shutdown, crypto/KeyIso or .NET issues. Presence-only and keyword evidence do not justify automatic registry, certificate-permission or machine.config changes.'
}
if (@($script:Checks | Where-Object { $_.Id -eq 'disk.space' -and $_.Status -eq 'WARN' }).Count -gt 0) {
    Add-NextStep 3 'Low system-disk-space heuristic' 'Review disk capacity and approved cleanup/expansion with the VM owner. The thresholds are only contextual; low space does not establish the connectivity cause.'
}
if (-not $isAdministrator -or @($script:Checks | Where-Object { $_.Status -eq 'ERROR' }).Count -gt 0) {
    Add-NextStep 3 'Prerequisite or collection gaps' 'Use an elevated 64-bit Windows PowerShell session on the affected Windows VM and inspect ERROR details/module availability. Re-run to a NEW local folder; do not treat missing evidence as a healthy result.'
}
if (@($script:Checks | Where-Object { $_.Status -in @('FAIL', 'WARN', 'ERROR') }).Count -eq 0) {
    Add-NextStep 4 'No failures found in this bounded local sample' 'No local cause was established. Verify Azure Agent Ready and affected extensions in Azure, and compare with the actual incident time. A successful sample is not full VM health certification.'
}
if (@($script:Checks | Where-Object { $_.Id -like 'dotnet.*' -and $_.Status -in @('FAIL', 'WARN', 'ERROR') }).Count -gt 0) {
    Add-NextStep 2 'Agent configuration/startup evidence' 'Review targeted .NET Runtime event 1026 and machine.config XML status together. A well-formed file can still have invalid .NET configuration semantics. Preserve the existing file; any replacement requires supported OS/.NET compatibility, custom-setting review, backup and change approval. No file or service was changed.'
}
Add-NextStep 4 'Power-state discrepancy or pre-Windows boot hang' 'Guest evidence does not validate Azure PowerState, portal-list freshness, hibernation or Citrix state. Compare contemporaneous Azure instance view, Activity Log, boot diagnostics and Citrix records with support. This script cannot run inside a deallocated/hibernated VM or before Windows starts.'
Add-NextStep 4 'Azure-side and inbound-probe boundaries' 'Separately verify Azure Agent Ready, Azure NIC primary and any intended AzurePlatformDNS policy. For load balancer issues, check the configured inbound probe port, listening application, guest firewall and AzureLoadBalancer NSG rules; outbound tests here cannot validate inbound probes.'

$metadata.CompletedUtc = [DateTime]::UtcNow.ToString('o')
$report = [ordered]@{
    SchemaVersion = '1.0'; Metadata = $metadata; Limits = $script:Limits
    Checks = @($script:Checks.ToArray()); Evidence = $script:Evidence
    NextSteps = @($script:NextSteps | Sort-Object Priority)
    Privacy = 'Local reports may contain sensitive internal information. No uploads. Snippet redaction is best-effort only.'
    Conclusions = 'Evidence only, not a root-cause diagnosis. PASS is scoped to the individual test; ERROR is a collection/prerequisite gap. Azure-side configuration and service-identity-specific behavior remain unverified.'
    References = @(
        'https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16',
        'https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/windows-azure-guest-agent',
        'https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows'
    )
}
$summary = New-Object 'System.Collections.Generic.List[string]'
[void]$summary.Add('AZURE PLATFORM CONNECTIVITY - LOCAL WINDOWS VM REPORT')
[void]$summary.Add(('Computer: {0} | Windows: {1} | Administrator: {2} | PowerShell: {3}' -f $metadata.ComputerName, $hostIsWindows, $isAdministrator, $metadata.PowerShellVersion))
[void]$summary.Add(('UTC start: {0} | UTC end: {1}' -f $metadata.StartedUtc, $metadata.CompletedUtc))
[void]$summary.Add(('Report folder: {0}' -f $OutputDirectory))
[void]$summary.Add(('Probe timeout: {0}s | TOTAL attempts per TCP port/HTTP: {1}' -f $TimeoutSeconds, $RetryCount))
[void]$summary.Add('READ BEFORE SHARING: Internal host/IP/DNS/proxy/service/firewall/event information may be sensitive.')
[void]$summary.Add('No root cause or Azure Agent Ready conclusion is made. All PASS does not mean full VM health.')
[void]$summary.Add('')
[void]$summary.Add('STATUS COUNTS')
foreach ($status in @('PASS', 'FAIL', 'WARN', 'INFO', 'ERROR', 'SKIPPED')) {
    [void]$summary.Add(('{0}: {1}' -f $status, @($script:Checks | Where-Object { $_.Status -eq $status }).Count))
}
[void]$summary.Add('')
[void]$summary.Add('CHECKS (FAIL=test failure; ERROR=collection/prerequisite gap)')
foreach ($check in $script:Checks) { [void]$summary.Add(('[{0}] {1}: {2}' -f $check.Status, $check.Id, $check.Summary)) }
[void]$summary.Add('')
[void]$summary.Add('TCP ATTEMPTS')
foreach ($probe in @(Get-SectionData 'TcpProbes')) {
    [void]$summary.Add(('{0} | port={1} attempt={2} {3} {4}ms | source={5} | {6}: {7}' -f $probe.TimestampUtc, $probe.Port, $probe.Attempt, $probe.Status, $probe.ElapsedMilliseconds, $probe.ActualLocalEndpoint, $probe.ErrorKind, $probe.Error))
}
[void]$summary.Add('')
[void]$summary.Add('DIRECT HTTP ATTEMPTS (no proxy; Metadata=true; no redirects)')
foreach ($probe in @(Get-SectionData 'HttpProbes')) {
    [void]$summary.Add(('{0} | attempt={1} {2} {3}ms | HTTP={4} bytes={5} complete={6} versions={7} | {8}: {9}' -f $probe.TimestampUtc, $probe.Attempt, $probe.Status, $probe.ElapsedMilliseconds, $probe.HttpStatusCode, $probe.BodyBytesRead, $probe.BodyComplete, ($probe.VersionValues -join ','), $probe.ErrorKind, $probe.Error))
    if ($probe.ParseError) { [void]$summary.Add(('  XML parse detail: {0}' -f $probe.ParseError)) }
}
[void]$summary.Add('')
[void]$summary.Add('DNS RESULTS (not an agent-port verdict)')
foreach ($probe in @(Get-SectionData 'DnsProbes')) {
    [void]$summary.Add(('{0} | {1} TCP-only={2} {3} {4}ms | addresses={5} | {6}: {7}' -f $probe.TimestampUtc, $probe.Mode, $probe.TcpOnly, $probe.Status, $probe.ElapsedMilliseconds, (@($probe.Answers | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join ','), $probe.ErrorKind, $probe.Error))
}
[void]$summary.Add('')
[void]$summary.Add('AGENT SERVICES')
foreach ($service in @(Get-SectionData 'AgentServices')) {
    [void]$summary.Add(('{0} | present={1} state={2} startup={3} PID={4} version={5} | {6}' -f $service.Name, $service.Present, $service.State, $service.StartMode, $service.ProcessId, $service.FileVersion, $service.ExecutablePath))
    if ($service.VersionError) { [void]$summary.Add(('  Version collection gap: {0}' -f $service.VersionError)) }
}
[void]$summary.Add('')
[void]$summary.Add('ACTIVE AGENT BINARY VERSIONS (file timestamps do not prove upgrade time)')
foreach ($processInfo in @(Get-SectionData 'AgentProcesses')) {
    [void]$summary.Add(('{0} | PID={1} version={2} product={3} | binary timestamp UTC={4} | {5}' -f $processInfo.Name, $processInfo.ProcessId, $processInfo.ActiveFileVersion, $processInfo.ActiveProductVersion, $processInfo.BinaryLastWriteUtc, $processInfo.ExecutablePath))
}
[void]$summary.Add('')
[void]$summary.Add('MACHINE.CONFIG XML EVIDENCE (no contents exported; valid XML is not .NET health)')
foreach ($configInfo in @(Get-SectionData 'MachineConfigXml')) {
    [void]$summary.Add(('{0} | XML={1} line={2} column={3} WCF-reference={4} | {5}' -f $configInfo.Path, $configInfo.XmlStatus, $configInfo.ParserLine, $configInfo.ParserColumn, $configInfo.WcfProfilingReferenceFound, $configInfo.ErrorType))
}
[void]$summary.Add('')
[void]$summary.Add('LOCAL IPv4 ADDRESS CONTEXT (up to 32 entries here; JSON has the bounded full collection)')
foreach ($address in @($addresses | Select-Object -First 32)) {
    [void]$summary.Add(('{0}/{1} | interface={2} index={3} state={4} origin={5} SkipAsSource={6}' -f $address.IPAddress, $address.PrefixLength, $address.InterfaceAlias, $address.InterfaceIndex, $address.AddressState, $address.PrefixOrigin, $address.SkipAsSource))
}
[void]$summary.Add('Default route inventory in JSON is NOT an effective platform VIP route or proof of Azure primary IP.')
[void]$summary.Add('')
[void]$summary.Add('PRIORITIZED REVIEW / NEXT STEPS (recommendations only; nothing changed)')
foreach ($step in @($script:NextSteps | Sort-Object Priority)) {
    [void]$summary.Add(('Priority {0} - {1}: {2}' -f $step.Priority, $step.Reason, $step.Action))
}
[void]$summary.Add('')
[void]$summary.Add('See diagnostics.json for bounded evidence, individual errors, caps and collection status.')
[void]$summary.Add('See AzurePlatformConnectivity-README.md for the decision tree, scope and Microsoft references.')

$utf8 = New-Object Text.UTF8Encoding $true
$jsonPath = Join-Path $OutputDirectory 'diagnostics.json'
$summaryPath = Join-Path $OutputDirectory 'summary.txt'
try {
    $json = $report | ConvertTo-Json -Depth 16
    # Round-trip checks serialization before writing the report; no depth-truncated data is expected.
    $roundTrip = $json | ConvertFrom-Json
    if ($roundTrip.SchemaVersion -ne '1.0' -or @($roundTrip.Checks).Count -ne $script:Checks.Count) { throw 'Report JSON round-trip validation failed.' }
    [IO.File]::WriteAllText($jsonPath, $json, $utf8)
    [IO.File]::WriteAllLines($summaryPath, $summary.ToArray(), $utf8)
    Write-Host ('Reports written: ' + $OutputDirectory)
    Write-Host ('Read summary:   ' + $summaryPath)
    Write-Host ('JSON evidence:  ' + $jsonPath)
    $failCount = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $errorCount = @($script:Checks | Where-Object { $_.Status -eq 'ERROR' }).Count
    $warnCount = @($script:Checks | Where-Object { $_.Status -eq 'WARN' }).Count
    Write-Host ("Checks: FAIL=$failCount ERROR=$errorCount WARN=$warnCount. This is evidence, not a root-cause verdict.")
    [pscustomobject]@{OutputDirectory=$OutputDirectory; SummaryPath=$summaryPath; DiagnosticsPath=$jsonPath; FailedChecks=$failCount; CollectionErrors=$errorCount; Warnings=$warnCount; AzureAgentReady='Not queried'}
} catch {
    throw "Could not complete reports in '$OutputDirectory'. A partial report may exist. $($_.Exception.Message)"
}
