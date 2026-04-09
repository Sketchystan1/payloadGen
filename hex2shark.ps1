# 1. Prompt the user for the input (handles multiple lines of pasted text)
Write-Host "Paste your hex string(s) (e.g., i1=<b 0x...>, i2=<b 0x...>). Press ENTER on a blank line when done:" -ForegroundColor Yellow
$userInput = ""
while ($true) {
    $line = Read-Host
    if ([string]::IsNullOrWhiteSpace($line)) { break }
    $userInput += $line + " "
}

# 2. Find all instances of the iX=<b 0x...> pattern
# The regex looks for "i" followed by numbers, "=", "<b 0x", and then grabs the hex
$regexPattern = '(?i)i\d+\s*=\s*<b 0x([a-f0-9]+)>'
$regexMatches = [regex]::Matches($userInput, $regexPattern)
$hexList = @()

if ($regexMatches.Count -gt 0) {
    Write-Host "`nFound $($regexMatches.Count) formatted payload(s)!" -ForegroundColor Cyan
    foreach ($match in $regexMatches) {
        $hexList += $match.Groups[1].Value
    }
} else {
    # Fallback: If no iX= tags are found, assume the whole input is just one raw hex stream
    Write-Host "`nNo 'iX=<b 0x...>' tags found. Treating input as a single raw hex stream." -ForegroundColor Cyan
    $cleaned = $userInput -replace '[^a-fA-F0-9]', ''
    if (-not [string]::IsNullOrEmpty($cleaned)) {
        $hexList += $cleaned
    }
}

# Ensure we actually have data before continuing
if ($hexList.Count -eq 0) {
    Write-Host "Error: No valid hex data was found in your input." -ForegroundColor Red
    exit
}

# 3. Set up temporary file paths
$tempTxt = "$env:TEMP\stun_payloads.txt"
$outputPcap = "$env:TEMP\stun_payloads.pcapng"

# Default Wireshark installation paths
$text2pcapPath = "C:\Program Files\Wireshark\text2pcap.exe"
$wiresharkPath = "C:\Program Files\Wireshark\Wireshark.exe"

# 4. Format the raw hex into a hexdump format
$formattedText = ""
$packetNumber = 1

foreach ($rawHex in $hexList) {
    # Adding a comment line for readability in the text file (text2pcap ignores lines starting with #)
    $formattedText += "# Packet $packetNumber`r`n"
    
    for ($i = 0; $i -lt $rawHex.Length; $i += 32) {
        # Grab up to 32 characters (16 bytes) at a time
        $chunkLength = [Math]::Min(32, $rawHex.Length - $i)
        $chunk = $rawHex.Substring($i, $chunkLength)
        
        # Insert a space between every 2 characters
        $spacedChunk = $chunk -replace '(..)', '$1 '
        
        # Calculate offset in hex (padded to 6 digits). 
        # Restarting at 000000 tells text2pcap this is a new packet.
        $offset = "{0:X6}" -f ($i / 2)
        
        $formattedText += "$offset $spacedChunk`r`n"
    }
    $formattedText += "`r`n" # Blank line between packets
    $packetNumber++
}

# Save the formatted text to a temporary file
$formattedText | Set-Content $tempTxt -Encoding ASCII

# 5. Check if Wireshark tools are installed, convert, and open
if (Test-Path $text2pcapPath) {
    Write-Host "Converting payloads to PCAP using dummy UDP port 3478..." -ForegroundColor Cyan
    
    # Run text2pcap quietly. -u 10000,3478 adds dummy IPv4/UDP headers.
    & $text2pcapPath -u 10000,3478 $tempTxt $outputPcap 2>$null
    
    if (Test-Path $outputPcap) {
        Write-Host "PCAP successfully generated! Opening Wireshark..." -ForegroundColor Green
        
        if (Test-Path $wiresharkPath) {
            & $wiresharkPath $outputPcap
        } else {
            Write-Host "Wireshark GUI not found at $wiresharkPath. You can manually open $outputPcap" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Failed to generate PCAP file." -ForegroundColor Red
    }
} else {
    Write-Host "Could not find text2pcap.exe at $text2pcapPath. Ensure Wireshark is installed in the default directory." -ForegroundColor Red
}

# Removed interactive pause so the script exits automatically after running.