<#
.SYNOPSIS
    pfnetbird - maintain NetBird on pfSense, the community way.
    Installs, updates or removes NetBird on a pfSense firewall over SSH.

.DESCRIPTION
    Usage: pfnetbird.ps1 [-Host [user@]host] [-NoLog] [-Key <path>] [-Version]
    See README for usage, requirements and credits.

.PARAMETER HostName
    Alias -Host. [user@]host: skip the start screen and connect at once.

.PARAMETER NoLog
    Do not write a session log (the menu can switch it on).

.PARAMETER Key
    Pin one SSH key: a private key file, or its .pub file (one agent key).

.PARAMETER Version
    Print "pfnetbird <version>" and exit 0.

.EXAMPLE
    pwsh ./pfnetbird.ps1

.EXAMPLE
    pwsh ./pfnetbird.ps1 -Host root@192.0.2.1

.NOTES
    pfnetbird 1.0.0 (pfnetbird.ps1)
    License: MIT, Copyright (c) 2026 Ulrik Boesen

.LINK
    https://github.com/uboesen/pfnetbird
#>
#Requires -Version 7.1
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias('Host')][string]$HostName,
    [switch]$NoLog,
    [string]$Key,
    [switch]$Version
)

# $Host is a PowerShell automatic variable, so the parameter is HostName with the alias Host.
# -Host [user@]host: captured here, because inside a function $PSBoundParameters is that function's own.
$script:HostGiven = $PSBoundParameters.ContainsKey('HostName')
$script:HostArg   = [string]$HostName
$script:HostUser  = ''
# -Key <path>: captured here for the same reason. KeyName is the basename, the only part shown or logged.
$script:KeyGiven  = $PSBoundParameters.ContainsKey('Key')
$script:KeyFile   = [string]$Key
$script:KeyName   = ''

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.0.0'
$RepoApi       = 'https://api.github.com/repos/netbirdio/pfsense-netbird'
$UrlPrefix     = 'https://github.com/netbirdio/pfsense-netbird/releases/download/'
$RemoteDir     = '/tmp/pfnetbird'
$IdentityFile  = '/var/db/netbird/config.json'
$MinFreeBsd    = 15
$ConfigXml     = '/cf/conf/config.xml'

# Auto-update (cron on the firewall). The cron command is constant on purpose (install_cron_job matches by it).
$AutoDir         = '/root/pfnetbird'
$AutoRunner      = "$AutoDir/pfnetbird-auto.php"
$AutoCmd         = "/usr/bin/nice -n20 /usr/local/bin/php -f $AutoRunner"
$AutoLock        = '/tmp/pfnetbird-auto.lock'
$AutoBusy        = '/tmp/pfnetbird-client.busy'
$AutoDefaultTime = '03:30'   # default schedule time (clear of rc.periodic: 03:01 daily, 04:15 Sat, 05:30 1st)

# Run-wide state. Session = the one ssh process. Ctx = paths named in error output.
$script:Session = $null
$script:Ctx     = @{ Backup = $null; Identity = $null }
$script:Downloaded = $false   # true once anything was written to /tmp/pfnetbird on the box
$script:BackupSize = 0
$script:BackupSha  = ''
$script:BackupEnc  = 'no'
$script:BackupSkipped = $false   # true when the user chose Skip (no backup) in the last Invoke-TakeBackup
$script:RemoteQuiet = $false   # true = remote output is never logged, not even on error
$script:Acb        = $null     # ACB preflight result of the connected box
$script:ConnHost   = ''
$script:LogOn      = -not $NoLog   # session log switch (-NoLog; start screen item 2; connected menu Logging item)
$script:LogFile    = $null         # this connection's log, once opened
$script:LogWhy     = ''            # reason Open-Log last failed (the text in the parentheses of the warning)
$script:LogDay     = $null         # yyyyMMdd of the connection start (fixed at login, used for the log file name)
$script:LogMute    = $false        # true while a screen is drawn (summarised in one log line)
$script:ConnUser   = ''
$script:ApiCache = @{}         # GitHub API replies by URL, cached in memory for 10 minutes (success only)
$script:RelLimited = $false    # last lookup hit the GitHub rate limit
$script:St = [pscustomobject]@{ Stage = 0; Box = $null; State = $null; Rel = $null }   # Stage: 0 nothing, 1 box, 2 NetBird, 3 release
$script:UseColor = [string]::IsNullOrEmpty($env:NO_COLOR) -and -not [Console]::IsOutputRedirected

# ---------------------------------------------------------------------------
# Terminal UI "1b" (frames): output layer. Every helper names its twin in pfnetbird.sh (ui_*).
# The source is pure ASCII: glyphs are built from code points. Map (1:1 per glyph, applied BEFORE
# measuring or padding; the session log always gets the ASCII form):
#
#   Unicode  ASCII     Unicode  ASCII
#   check    +         V-bar    |
#   triangle !         H-bar    -
#   cross    x         corners  +
#   dot      *         arrow    ->
#   mid-dot  /         gt-quote >
#   ellipsis ...       em dash  -
#
# Mode: PFNETBIRD_ASCII=1 > auto (Initialize-Ui). Width is fixed at 78 columns. Colour is
# status only, via the marker characters 2..5 inside a string, painted by Write-UiLine alone with
# direct SGR codes (ESC is built from [char]27, so the file stays ASCII). Every UI writer writes to the host and returns
# nothing; every Format-* result must be assigned (a stray value would change the exit code).
# ---------------------------------------------------------------------------
$script:UiU = @{
    Ok = [string][char]0x2713; Warn = [string][char]0x25B2; Err = [string][char]0x2717
    Dot = [string][char]0x25CF; Mid = [string][char]0x00B7; Ell = [string][char]0x2026
    Em = [string][char]0x2014; V = [string][char]0x2502; H = [string][char]0x2500
    TL = [string][char]0x250C; TJ = [string][char]0x251C; BL = [string][char]0x2514
    Arr = [string][char]0x2192; Gt = [string][char]0x203A
}
$script:UiA = @{
    Ok = '+'; Warn = '!'; Err = 'x'; Dot = '*'; Mid = '/'; Ell = '...'; Em = '-'
    V = '|'; H = '-'; TL = '+'; TJ = '+'; BL = '+'; Arr = '->'; Gt = '>'
}
$script:UiKeys = @('Ok', 'Warn', 'Err', 'Dot', 'Mid', 'Ell', 'Em', 'V', 'H', 'TL', 'TJ', 'BL', 'Arr', 'Gt')
$script:G      = $script:UiA     # the active glyph set; Initialize-Ui decides (ASCII until then)
$script:UiAscii = $true
$script:UiTty   = $false         # stdout is a terminal and TERM is not dumb (clear screen)
$script:UiW     = 78
$script:UiKvw   = 13             # label column of Write-UiKv
$script:UiPfx   = '|  '          # prefix of a frame line (Initialize-Ui sets the glyph)
$script:UiFrame = $false         # a frame is open
$script:UiLead  = ''             # the frame prefix while a frame is open, else ''
$script:UiStep  = $false         # a step is open: messages are buffered until Complete-UiStep
$script:UiNoteK = [System.Collections.Generic.List[string]]::new()
$script:UiNoteT = [System.Collections.Generic.List[string]]::new()
$script:UiAfter = [System.Collections.Generic.List[string]]::new()   # printed right after the frame closes
$script:UiFailT = ''             # red closing text if the action dies now (Set-UiStage)
$script:UiTotal = 0              # sum of the finished step times of this action
$script:UiSN = ''                # open step: name, running detail, start (whole seconds)
$script:UiSD = ''
$script:UiST0 = 0
$script:UiSpinOn = $false        # a spinner line is on screen
$script:UiSpinIx = 0
$script:UiSpinSet = @('-', '\', '|', '/')
$script:UiSpinLast = $null       # stopwatch since the last spinner draw
$script:UiPost = ''              # spinner text after the glyph: name column + detail
$script:SecClock = [System.Diagnostics.Stopwatch]::StartNew()   # twin of bash $SECONDS
$script:UiEsc = [string][char]27
$script:DlT = 0; $script:VfT = 0
$script:IdentDetail = ''; $script:PkgCfgFile = ''
$script:MenuUn = 'none'           # menu number of the Uninstall item ('none' = hidden)
$script:MenuAu = 'none'           # menu number of the Auto-update item ('none' = hidden)
$script:MenuLog = 4               # menu number of the Logging item (set by Show-SessionScreen)
$script:ActNav  = $false         # the running action ended with Back (no "Press Enter")
$script:BkKind = 'ok'; $script:BkDetail = ''
$script:UiOrigEnc = $null        # console output encoding to restore (Windows Terminal only)
# Colour markers (control characters 2..5, never in text: ConvertTo-UiSafe strips them).
$script:MkG = [string][char]2; $script:MkY = [string][char]3; $script:MkR = [string][char]4; $script:MkE = [string][char]5
# What the screens say about the login (plain ssh, the same texts as sh).
$script:UiAuthRow = 'like ssh (agent / ~/.ssh key, else password)'
$script:UiAuthSub = 'auth like ssh'

function Initialize-Ui {
    # Twin: ui_init. Picks the glyph set once, before anything is drawn.
    $useAscii = $false
    $term = [string]$env:TERM
    if ($env:PFNETBIRD_ASCII -eq '1') {
        $useAscii = $true
    } else {
        if ($term -eq 'dumb' -or $term -eq 'linux') { $useAscii = $true }
        if (-not $useAscii) {
            if ($IsWindows) {
                $inTerminal = -not [string]::IsNullOrEmpty($env:WT_SESSION)
                # UNVERIFIED (Windows Terminal and conhost are not tested): in Windows Terminal the output
                # encoding is set to UTF-8 for this session, so Unicode works without chcp. It is
                # restored in Invoke-Main's finally. Plain conhost and redirected output keep the rule.
                if ($inTerminal -and -not [Console]::IsOutputRedirected) {
                    try {
                        $script:UiOrigEnc = [Console]::OutputEncoding
                        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
                    } catch { $script:UiOrigEnc = $null }
                }
                $terminalLike = $inTerminal -or -not [string]::IsNullOrEmpty($env:TERM_PROGRAM) -or -not [string]::IsNullOrEmpty($env:SSH_CONNECTION)
                $cp = 0
                try { $cp = [int][Console]::OutputEncoding.CodePage } catch { $cp = 0 }
                if ($cp -ne 65001 -or -not $terminalLike) { $useAscii = $true }
            } else {
                # Not the code page: .NET reports UTF-8 even for LANG=C. LC_ALL > LC_CTYPE > LANG.
                $cm = [string]$env:LC_ALL
                if (-not $cm) { $cm = [string]$env:LC_CTYPE }
                if (-not $cm) { $cm = [string]$env:LANG }
                $cm = $cm.ToLowerInvariant()
                if (-not ($cm.Contains('utf-8') -or $cm.Contains('utf8'))) { $useAscii = $true }
            }
        }
    }
    $script:UiAscii = $useAscii
    $script:G = if ($useAscii) { $script:UiA } else { $script:UiU }
    $script:UiPfx = $script:G['V'] + '  '
    # Spinner: braille only on non-Windows Unicode; Windows and ASCII mode use - \ | /
    if ($useAscii -or $IsWindows) { $script:UiSpinSet = @('-', '\', '|', '/') }
    else { $script:UiSpinSet = @(0x280B, 0x2819, 0x2839, 0x2838, 0x283C, 0x2834, 0x2826, 0x2827, 0x2807, 0x280F | ForEach-Object { [string][char]$_ }) }
    $script:UiTty = $false
    try { if (-not [Console]::IsOutputRedirected -and $term -ne 'dumb') { $script:UiTty = $true } } catch { }
}

function Restore-UiEncoding {
    # Puts back the console output encoding that Initialize-Ui replaced (Windows Terminal only).
    if ($null -ne $script:UiOrigEnc) {
        $enc = $script:UiOrigEnc
        $script:UiOrigEnc = $null
        try { [Console]::OutputEncoding = $enc } catch { }
    }
}

function ConvertTo-UiGlyph {
    # Twin: ui_map. Text with the glyphs of the map above (ASCII mode or -ForceAscii) or unchanged.
    param([string]$Text, [switch]$ForceAscii)
    if ($script:UiAscii -or $ForceAscii) {
        foreach ($k in $script:UiKeys) { $Text = $Text.Replace($script:UiU[$k], $script:UiA[$k]) }
    }
    return $Text
}

function ConvertTo-UiSafe {
    # Twin: ui_sanitize. One line, no control or format characters (that includes the colour markers
    # and ESC, so a remote string can never inject colour, escapes or bidi tricks). A surrogate pair
    # (emoji, two columns wide) becomes ?; in ASCII mode every non-ASCII character does.
    param([string]$Text)
    $t = $Text.Replace("`t", ' ')
    $t = [regex]::Replace($t, '[\p{Cc}\p{Cf}]', '')
    $t = [regex]::Replace($t, '[\uD800-\uDBFF][\uDC00-\uDFFF]', '?')
    $t = [regex]::Replace($t, '[\uD800-\uDFFF]', '?')
    if ($script:UiAscii) { $t = [regex]::Replace($t, '[^\x00-\x7F]', '?') }
    return $t
}

function ConvertTo-UiClean {
    # Twin: ui_clean. ConvertTo-UiSafe for text with several lines; the line breaks survive.
    param([string]$Text)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($l in ($Text -split "`r?`n")) { $out.Add((ConvertTo-UiSafe $l)) }
    return ($out -join "`n")
}

function New-UiColor {
    # Twin: ui_c. Wraps Text in a colour marker pair. Kind: ok (green) | warn (yellow) | fail (red).
    param([string]$Kind, [string]$Text)
    switch ($Kind) {
        'ok'   { return "$($script:MkG)$Text$($script:MkE)" }
        'warn' { return "$($script:MkY)$Text$($script:MkE)" }
        'fail' { return "$($script:MkR)$Text$($script:MkE)" }
        default { return $Text }
    }
}

function Get-UiLength {
    # Twin: ui_len. Display length (every glyph is one UTF-16 unit and one column); markers not counted.
    param([string]$Text)
    return ([regex]::Replace($Text, '[\x02-\x05]', '')).Length
}

function Format-UiPad {
    # Twin: ui_pad. Pads with spaces to Width columns (-Right = right-align). Never use -f for this.
    param([string]$Text, [int]$Width, [switch]$Right)
    $n = Get-UiLength $Text
    $sp = if ($n -lt $Width) { ' ' * ($Width - $n) } else { '' }
    if ($Right) { return ($sp + $Text) }
    return ($Text + $sp)
}

function Format-UiShorten {
    # Twin: ui_shorten. Middle ellipsis when longer than Max. Plain text only (no markers).
    param([string]$Text, [int]$Max)
    if ($Max -lt 1) { $Max = 1 }
    if ($Text.Length -gt $Max) {
        $ell = $script:G['Ell']
        $keep = $Max - $ell.Length
        if ($keep -lt 2) {
            $Text = $ell.Substring(0, [Math]::Min($Max, $ell.Length))
        } else {
            $left = [int][Math]::Floor(($keep + 1) / 2)
            $right = $keep - $left
            $Text = $Text.Substring(0, $left) + $ell + $Text.Substring($Text.Length - $right)
        }
    }
    return $Text
}

function Format-UiWrap {
    # Twin: ui_wrap. Wraps to 78 columns including the prefix (default the frame prefix; both prefixes
    # must be equally wide). Each input line keeps its leading indent; continuation lines get Hang
    # extra spaces ('auto': the width of a list marker such as "1. " or "- " at the start of the line).
    # Words longer than a line are broken. Text must already be in the glyph set of the mode.
    # Returns the finished lines (a string[]); an empty text gives one empty line.
    param([string]$Text, [string]$Hang = '0', [string]$P1, [string]$Pn)
    if (-not $PSBoundParameters.ContainsKey('P1')) { $P1 = $script:UiPfx }
    if (-not $PSBoundParameters.ContainsKey('Pn')) { $Pn = $P1 }
    $avail = $script:UiW - $P1.Length
    $bl = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrEmpty($Text)) { return ,[string[]]@('') }
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = ConvertTo-UiSafe $raw
        $lead = ''
        $m = [regex]::Match($line, '^ *')
        if ($m.Success) { $lead = $m.Value }
        $rest = $line.Substring($lead.Length)
        if ($rest -eq '') {
            $bl.Add('')
        } elseif ($line.Length -le $avail) {
            $bl.Add($line)
        } else {
            $h = 0
            if ($Hang -eq 'auto') {
                $lm = [regex]::Match($rest, '^([0-9]+[.)]|[a-z][.)]|[-*]) +')
                if ($lm.Success) { $h = $lm.Length }
            } else { $h = [int]$Hang }
            $cind = $lead + (' ' * $h)
            $cur = $lead
            $have = $false
            # A number and its unit ("120 s", "30 s") stay together: they are merged into one token.
            $words = [System.Collections.Generic.List[string]]::new()
            foreach ($t in @($rest -split ' +' | Where-Object { $_ -ne '' })) {
                if ($words.Count -gt 0 -and $words[$words.Count - 1] -match '^\(?[0-9]+([.,][0-9]+)?$' -and $t -cmatch '^(s|ms|min|h|d|KB|MB|GB|TB|kB)[).,;:]*$') {
                    $words[$words.Count - 1] += ' ' + $t
                } else { $words.Add($t) }
            }
            foreach ($w in $words) {
                $hv = if ($have) { 1 } else { 0 }
                if (($w.StartsWith('http://') -or $w.StartsWith('https://') -or $w -match '^[0-9a-fA-F]{64}$') -and ($cur.Length + $hv + $w.Length -gt $avail)) {
                    # A URL or a hash is never broken: it gets a line of its own and may run past the width.
                    if ($have) { $bl.Add($cur) }
                    $bl.Add($cind + $w)
                    $cur = $cind
                    $have = $false
                    continue
                }
                while ($true) {
                    $sep = if ($have) { ' ' } else { '' }
                    if ($cur.Length + $sep.Length + $w.Length -le $avail) {
                        $cur += $sep + $w
                        $have = $true
                        break
                    }
                    if ($have) {
                        if ($w.Length -gt $avail - $cind.Length) {
                            # Unbreakable word (a path): start it on this line, so a leading glyph is not left alone.
                            $room = $avail - $cur.Length - 1
                            if ($room -ge 1) {
                                $bl.Add($cur + ' ' + $w.Substring(0, $room))
                                $w = $w.Substring($room)
                                $cur = $cind
                                $have = $false
                                if ($w -eq '') { break }
                                continue
                            }
                        }
                        $bl.Add($cur)
                        $cur = $cind
                        $have = $false
                        continue
                    }
                    $room = $avail - $cur.Length
                    if ($room -lt 1) { $room = 1 }
                    if ($room -gt $w.Length) { $room = $w.Length }
                    $bl.Add($cur + $w.Substring(0, $room))
                    $w = $w.Substring($room)
                    $cur = $cind
                    if ($w -eq '') { break }
                }
            }
            if ($have) { $bl.Add($cur) }
        }
    }
    $out = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $bl.Count; $i++) {
        $p = if ($i -eq 0) { $P1 } else { $Pn }
        if ($bl[$i] -eq '') { $p = $p.TrimEnd(' ') }
        $out.Add($p + $bl[$i])
    }
    return ,[string[]]$out.ToArray()
}

function Write-UiLine {
    # Twin: ui_paint + printf. THE only painter: writes one line, turning the colour markers into the
    # SGR codes sh uses (32 green, 33 yellow, 31 red, 0 reset), or into nothing when colour is off
    # (NO_COLOR or redirected output). ESC is built from [char]27, so the source stays ASCII. Written
    # with [Console]::Out so it also works while a Ctrl-C unwinds. Returns nothing.
    param([string]$Text)
    $esc = $script:UiEsc
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Text.ToCharArray()) {
        switch ([int]$ch) {
            2 { if ($script:UseColor) { $null = $sb.Append($esc + '[32m') } }
            3 { if ($script:UseColor) { $null = $sb.Append($esc + '[33m') } }
            4 { if ($script:UseColor) { $null = $sb.Append($esc + '[31m') } }
            5 { if ($script:UseColor) { $null = $sb.Append($esc + '[0m') } }
            default { $null = $sb.Append($ch) }
        }
    }
    [Console]::Out.Write($sb.ToString() + "`n")
}

# --- Frames: open on the right (no right border). One frame per screen or action. -------------
function Open-UiFrame {
    # Twin: ui_open. "+- Title ------- Right", filled with the H glyph to 78 columns. Too long: the
    # right part is shortened in the middle.
    param([string]$Title, [string]$Right = '')
    if ($script:UiFrame) { Exit-UiFrame }
    Stop-UiSpin
    $script:UiStep = $false
    $script:UiNoteK.Clear(); $script:UiNoteT.Clear()
    $script:UiFailT = ''; $script:UiTotal = 0
    $tl = $script:G['TL']; $hh = $script:G['H']
    $t = ConvertTo-UiSafe (ConvertTo-UiGlyph $Title)
    $r = ''
    if ($Right) { $r = ConvertTo-UiSafe (ConvertTo-UiGlyph $Right) }
    $script:UiFrame = $true
    $script:UiLead = $script:UiPfx
    if (-not $r) {
        $t = Format-UiShorten $t ($script:UiW - 3)
        Write-UiLine "$tl$hh $t"
        return
    }
    $room = $script:UiW - 8
    if ($t.Length + $r.Length -gt $room) {
        if ($room - $t.Length -ge 12) {
            $r = Format-UiShorten $r ($room - $t.Length)
        } else {
            $t = Format-UiShorten $t 28
            $r = Format-UiShorten $r ($room - $t.Length)
        }
    }
    $fill = $hh * [Math]::Max(0, $room - $t.Length - $r.Length + 3)
    Write-UiLine "$tl$hh $t $fill $r"
}

function Write-UiBlank {
    # Twin: ui_blank. A blank frame line.
    Write-UiLine $script:G['V']
}

function Write-UiSection {
    # Twin: ui_section. A blank frame line, then "+- Name".
    param([string]$Name)
    $n = ConvertTo-UiSafe (ConvertTo-UiGlyph $Name)
    $n = Format-UiShorten $n ($script:UiW - 3)
    Write-UiLine $script:G['V']
    Write-UiLine ($script:G['TJ'] + $script:G['H'] + ' ' + $n)
}

function Close-UiFrame {
    # Twin: ui_close. "+-" or "+- text"; Kind ok|warn|fail puts a coloured status glyph in front of
    # the text. Then prints what Add-UiAfter collected. Does nothing when no frame is open.
    param([string]$Kind = '', [string]$Text = '')
    if (-not $script:UiFrame) { return }
    Stop-UiStep
    $script:UiFrame = $false
    $script:UiLead = ''
    $script:UiFailT = ''
    $bl = $script:G['BL']; $hh = $script:G['H']
    $p1 = "$bl$hh "; $pn = '   '
    $g = ''
    switch ($Kind) {
        'ok'   { $g = $script:G['Ok'] }
        'warn' { $g = $script:G['Warn'] }
        'fail' { $g = $script:G['Err'] }
    }
    if ([string]::IsNullOrEmpty($Text)) {
        Write-UiLine "$bl$hh"
    } else {
        $t = ConvertTo-UiGlyph $Text
        if ($g) { $lines = Format-UiWrap "$g $t" '2' $p1 $pn } else { $lines = Format-UiWrap $t '0' $p1 $pn }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            if ($i -eq 0 -and $g -and $l.StartsWith($p1 + $g, [System.StringComparison]::Ordinal)) {
                $l = $p1 + (New-UiColor $Kind $g) + $l.Substring($p1.Length + $g.Length)
            }
            Write-UiLine $l
        }
    }
    foreach ($a in $script:UiAfter) { Write-UiLine $a }
    $script:UiAfter.Clear()
}

function Add-UiAfter {
    # Twin: ui_after. A line printed right after the frame closes (for example `netbird status -d`,
    # shown there and never logged). Printed at once when no frame is open.
    param([string]$Text)
    $l = ConvertTo-UiClean $Text
    if ($script:UiFrame) { $script:UiAfter.Add($l) } else { Write-UiLine $l }
}

function Stop-UiStep {
    # Twin: ui_unstep. Ends an open step as failed (prints its line) and wipes the spinner.
    if ($script:UiStep) { Complete-UiStep 'fail' '' }
    Stop-UiSpin
}

# --- Steps ------------------------------------------------------------------------------------
# "|  <status> <Name padded to 12><detail><time right-aligned>". Start-UiStep opens a step: while it is
# open Write-Info/Ok/Warn/Fail print nothing on screen (the log is written as always) and, on a
# terminal, a spinner with the elapsed seconds is redrawn on the same line by Invoke-UiTick (called
# while waiting for the firewall). Complete-UiStep prints the one final line; a buffered warn / fail
# turns the glyph into the warning / error glyph and its text is printed under the line.
function Start-UiSpin {
    # Twin: ui_spin_start. Prepares the text after the glyph and draws the first frame.
    $nm = ConvertTo-UiSafe (ConvertTo-UiGlyph $script:UiSN)
    $len = $nm.Length
    $nm = Format-UiPad $nm 12
    if ($len -ge 12) { $nm += ' ' }
    $d = ConvertTo-UiSafe (ConvertTo-UiGlyph $script:UiSD)
    $d = Format-UiShorten $d ($script:UiW - $script:UiPfx.Length - 2 - $nm.Length - 7)
    $script:UiPost = $nm + $d
    $script:UiSpinIx = 0
    $script:UiSpinOn = $true
    $script:UiSpinLast = $null
    Write-UiSpinFrame
}

function Write-UiSpinFrame {
    # Twin: the body of ui_spin_loop. One redraw of the spinner line: CR, the line, erase to the end.
    $set = $script:UiSpinSet
    $t = '' + ((Get-UiSeconds) - $script:UiST0) + 's'
    $pad = $script:UiW - $script:UiPfx.Length - 2 - $script:UiPost.Length - $t.Length
    if ($pad -lt 1) { $pad = 1 }
    $line = "`r" + $script:UiPfx + $set[$script:UiSpinIx] + ' ' + $script:UiPost + (' ' * $pad) + $t + $script:UiEsc + '[K'
    [Console]::Out.Write($line)
    $script:UiSpinIx = ($script:UiSpinIx + 1) % $set.Count
    $script:UiSpinLast = [System.Diagnostics.Stopwatch]::StartNew()
}

function Invoke-UiTick {
    # Called while waiting. Redraws the spinner about every 0.2 s; does nothing without an open step.
    if (-not $script:UiSpinOn) { return }
    if ($null -ne $script:UiSpinLast -and $script:UiSpinLast.ElapsedMilliseconds -lt 200) { return }
    Write-UiSpinFrame
}

function Stop-UiSpin {
    # Twin: ui_spin_stop. Wipes the spinner line. Safe to call at any time.
    if ($script:UiSpinOn) {
        $script:UiSpinOn = $false
        [Console]::Out.Write("`r" + $script:UiEsc + '[K')
    }
}

function Wait-UiSleep {
    # Sleeps Seconds in 200 ms slices, ticking the spinner (twin: sleep with the ticker running).
    param([int]$Seconds)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $Seconds * 1000) {
        Start-Sleep -Milliseconds 200
        Invoke-UiTick
    }
}

function Start-UiStep {
    # Twin: ui_step_begin. Never open a step around a prompt, and end it before Close-UiFrame.
    param([string]$Name, [string]$Detail = '')
    Stop-UiSpin
    $script:UiStep = $true
    $script:UiSN = $Name; $script:UiSD = $Detail; $script:UiST0 = Get-UiSeconds
    $script:UiNoteK.Clear(); $script:UiNoteT.Clear()
    if ($script:UiTty -and $script:UiFrame) { Start-UiSpin }
}

function Complete-UiStep {
    # Twin: ui_step_end. Kind ok|warn|fail. Seconds default to the time since Start-UiStep.
    param([string]$Kind, [string]$Detail = '', [long]$Seconds = -1)
    if (-not $script:UiStep) { return }
    Stop-UiSpin
    $s = if ($Seconds -ge 0) { $Seconds } else { (Get-UiSeconds) - $script:UiST0 }
    $script:UiStep = $false
    $script:UiTotal += $s
    $w = $Kind
    $kinds = @($script:UiNoteK)
    $texts = @($script:UiNoteT)
    $script:UiNoteK.Clear(); $script:UiNoteT.Clear()
    foreach ($k in $kinds) {
        if ($k -eq 'fail') { $w = 'fail' }
        elseif ($k -eq 'warn' -and $w -eq 'ok') { $w = 'warn' }
    }
    Write-UiStepLine $w $script:UiSN $Detail ([int]$s)
    foreach ($t in $texts) { Write-UiStepNote $t }
}

function Write-UiStepLine {
    # Twin: ui_step_line. The finished step line (no state change). The name column is 12 wide, the time
    # sits right-aligned at column 78, a long detail wraps under the detail column.
    param([string]$Kind, [string]$Name, [string]$Detail, [int]$Secs)
    $gm = ' '
    switch ($Kind) {
        'ok'   { $gm = New-UiColor 'ok' $script:G['Ok'] }
        'warn' { $gm = New-UiColor 'warn' $script:G['Warn'] }
        'fail' { $gm = New-UiColor 'fail' $script:G['Err'] }
    }
    $n = ConvertTo-UiSafe (ConvertTo-UiGlyph $Name)
    $d = ConvertTo-UiSafe (ConvertTo-UiGlyph $Detail)
    $t = ''; $tl = 0
    if ($Secs -gt 0) { $t = "${Secs}s"; $tl = $t.Length + 1 }
    $nm = Format-UiPad $n 12
    if ($n.Length -ge 12) { $nm += ' ' }
    $hang = 2 + $nm.Length
    $av = $script:UiW - $script:UiPfx.Length - $hang - $tl
    $sp = ' ' * ($script:UiW - $av)
    $wrapped = Format-UiWrap $d '0' $sp $sp
    $ls = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $wrapped) { if ($l.Length -ge $sp.Length) { $ls.Add($l.Substring($sp.Length)) } else { $ls.Add('') } }
    $x = ' ' * $hang
    for ($i = 0; $i -lt $ls.Count; $i++) {
        if ($i -eq 0) { $ln = $script:UiPfx + $gm + ' ' + $nm + $ls[$i] } else { $ln = $script:UiPfx + $x + $ls[$i] }
        if ($i -eq $ls.Count - 1 -and $t) {
            $ln = Format-UiPad $ln ($script:UiW - $t.Length)
            $ln += $t                                   # the time sits on the last line
        } else {
            $ln = $ln.TrimEnd(' ')                      # no trailing spaces
        }
        Write-UiLine $ln
    }
}

function Write-UiStepNote {
    # Twin: ui_step_note. The text of a buffered message, printed under its step line (wrapped, no glyph).
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $t = ConvertTo-UiGlyph $Text
    $pf = $script:UiPfx + (' ' * 14)
    foreach ($l in (Format-UiWrap $t 'auto' $pf $pf)) { Write-UiLine $l }
}

function Start-UiAction {
    # Twin: ui_begin. The frame of an action. Opens one; inside an already open frame it only starts a
    # new section.
    param([string]$Title)
    if ($script:UiFrame) { Write-UiSection $Title } else { Open-UiFrame $Title; Write-UiBlank }
}

function Set-UiStage {
    # Twin: ui_stage. What to say in the red closing line if the action dies from here on.
    param([string]$Text)
    $script:UiFailT = $Text
}

function Exit-UiFrame {
    # Twin: ui_abort. Closes the open step and frame on the way out (error, finally).
    Stop-UiStep
    if ($script:UiFrame) {
        if ($script:UiFailT) { Close-UiFrame 'fail' $script:UiFailT } else { Close-UiFrame }
    }
}

function Write-UiPlan {
    # Twin: ui_plan. The "Plan (nothing is changed)" section of a dry run; opens a frame with Title
    # when none is open.
    param([string]$Title = 'Dry run')
    if (-not $script:UiFrame) { Open-UiFrame $Title }
    Write-UiSection 'Plan (nothing is changed)'
}

# --- Rows -------------------------------------------------------------------------------------
function Write-UiKv {
    # Twin: ui_kv. "|  Label        value". The value may hold colour markers. A value wider than
    # 62 columns wraps by words under the value column and keeps its colour; with -Path (a path or
    # URL) it is middle-shortened instead. Callers shorten long plain parts BEFORE colouring.
    param([string]$Label, [string]$Value, [switch]$Path)
    $kl = ConvertTo-UiGlyph $Label
    $kv = ConvertTo-UiGlyph $Value
    $kw = $script:UiKvw
    $kn = Get-UiLength $kl
    if ($kn -ge $kw) { $kw = $kn + 1 }          # always a separator space
    $kl = Format-UiPad $kl $kw
    $ka = $script:UiW - $script:UiPfx.Length - $kw
    $kn = Get-UiLength $kv
    $klines = [System.Collections.Generic.List[string]]::new()
    if ($kn -le $ka) {
        $klines.Add($kv)
    } else {
        $kx = [regex]::Replace($kv, '[\x02-\x05]', '')
        $words = @($kv -split ' +' | Where-Object { $_ -ne '' })
        $widest = 0
        foreach ($c in $words) { $ci = Get-UiLength $c; if ($ci -gt $widest) { $widest = $ci } }
        if ($Path -or $widest -gt $ka) {
            # A path or URL (or an unbreakable word): middle-shorten, plain.
            $klines.Add((Format-UiShorten $kx $ka))
        } else {
            # Words wrap under the value column; a colour that spans a line break is closed and reopened.
            $cur = ''; $cl = 0; $open = ''
            foreach ($c in $words) {
                $ci = Get-UiLength $c
                if ($cl -gt 0 -and $cl + 1 + $ci -gt $ka) {
                    if ($open) { $cur += $script:MkE }
                    $klines.Add($cur)
                    $cur = $open + $c
                    $cl = $ci
                } elseif ($cl -gt 0) {
                    $cur += ' ' + $c
                    $cl += 1 + $ci
                } else {
                    $cur = $c
                    $cl = $ci
                }
                foreach ($ch in $c.ToCharArray()) {
                    $s = [string]$ch
                    if ($s -eq $script:MkG -or $s -eq $script:MkY -or $s -eq $script:MkR) { $open = $s }
                    elseif ($s -eq $script:MkE) { $open = '' }
                }
            }
            $klines.Add($cur)
        }
    }
    $first = $true
    foreach ($v in $klines) {
        if ($first) { Write-UiLine ($script:UiPfx + $kl + $v); $first = $false }
        else { Write-UiLine ($script:UiPfx + (' ' * $kw) + $v) }
    }
}

function Write-UiMenu1 {
    # Twin: ui_menu1. One-column menu, one item per line in the frame (the connected screen; same look as
    # the submenus). An item longer than the frame is shortened.
    param([string[]]$Items)
    foreach ($it in $Items) {
        $a = ConvertTo-UiSafe (ConvertTo-UiGlyph $it)
        Write-UiLine ($script:UiPfx + (Format-UiShorten $a ($script:UiW - $script:UiPfx.Length)))
    }
}

function Write-UiMenu2 {
    # Twin: ui_menu2. Two-column menu. Items 1-3 on the left, 4 and up on the right, the LAST item
    # (the 0 item) on its own row below. The left column is at least 30 wide.
    param([string[]]$Items)
    $left = [System.Collections.Generic.List[string]]::new()
    $right = [System.Collections.Generic.List[string]]::new()
    $zero = ''
    $lw = 30
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $a = ConvertTo-UiSafe (ConvertTo-UiGlyph $Items[$i])
        if ($i -eq $Items.Count - 1) { $zero = $a }
        elseif ($i -lt 3) { $left.Add($a); if ($a.Length + 2 -gt $lw) { $lw = $a.Length + 2 } }
        else { $right.Add($a) }
    }
    if ($lw -gt 40) {
        $lw = 40
        for ($i = 0; $i -lt $left.Count; $i++) { $left[$i] = Format-UiShorten $left[$i] ($lw - 2) }
    }
    $rw = $script:UiW - $script:UiPfx.Length - $lw
    for ($i = 0; $i -lt $right.Count; $i++) { $right[$i] = Format-UiShorten $right[$i] $rw }
    $rows = [Math]::Max($left.Count, $right.Count)
    for ($i = 0; $i -lt $rows; $i++) {
        $l = if ($i -lt $left.Count) { $left[$i] } else { '' }
        $r = if ($i -lt $right.Count) { $right[$i] } else { '' }
        if ($r) { Write-UiLine ($script:UiPfx + (Format-UiPad $l $lw) + $r) }
        else { Write-UiLine ($script:UiPfx + $l) }
    }
    if ($zero) { Write-UiLine ($script:UiPfx + $zero) }
}

function Read-UiLine {
    # One line from the keyboard (or redirected input); $null at end of input. Not Read-Host: that one
    # adds its own terminal escapes. Prints nothing itself.
    if ([Console]::IsInputRedirected) { return [Console]::In.ReadLine() }
    # Interactive: [Console]::In.ReadLine() would swallow Ctrl-C until Enter. So the line is read key by
    # key, polling KeyAvailable (Ctrl-C then ends the script at once, as in sh); typing, Backspace, Enter
    # and Ctrl-D (end of input on an empty line) behave like a normal terminal line.
    $sb = [System.Text.StringBuilder]::new()
    while ($true) {
        while (-not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 50 }
        $k = [Console]::ReadKey($true)
        $ctrl = (($k.Modifiers -band [System.ConsoleModifiers]::Control) -ne 0)
        if ($k.Key -eq [System.ConsoleKey]::Enter) { [Console]::Out.Write("`n"); return $sb.ToString() }
        if ($ctrl -and $k.Key -eq [System.ConsoleKey]::D) {
            if ($sb.Length -eq 0) { return $null }
            continue
        }
        if ($k.Key -eq [System.ConsoleKey]::Backspace) {
            if ($sb.Length -gt 0) { $null = $sb.Remove($sb.Length - 1, 1); [Console]::Out.Write("`b `b") }
            continue
        }
        $c = $k.KeyChar
        if ($c -ne [char]0 -and -not [char]::IsControl($c)) { $null = $sb.Append($c); [Console]::Out.Write([string]$c) }
    }
}

function Read-UiPrompt {
    # Twin: ui_prompt. Prints Text (with the frame prefix when a frame is open) and reads one line.
    # Returns $null at end of input.
    param([string]$Text)
    $q = ConvertTo-UiGlyph $Text
    [Console]::Out.Write($script:UiLead + $q + ' ')
    return (Read-UiLine)
}

function Write-UiSay {
    # Twin: ui_say. The body of Write-Info/Ok/Warn/Fail. Kind: info | ok | warn | fail. Inside a frame
    # the text is wrapped with the frame prefix and ok/warn/fail get a coloured status glyph in front
    # (instead of the words WARNING: / ERROR:); outside a frame it is one line with the glyph. Screen
    # only: the log is written by the callers.
    param([string]$Kind, [string]$Text)
    $g = ''
    switch ($Kind) {
        'ok'   { $g = $script:G['Ok'] }
        'warn' { $g = $script:G['Warn'] }
        'fail' { $g = $script:G['Err'] }
    }
    if ($script:UiStep) {                      # hook for stop 2: messages of an open step are buffered
        $script:UiNoteK.Add($Kind); $script:UiNoteT.Add($Text)
        return
    }
    $t = ConvertTo-UiGlyph $Text
    if (-not $script:UiFrame) {
        $t = ConvertTo-UiClean $t
        if ($g) { Write-UiLine ((New-UiColor $Kind $g) + ' ' + $t) } else { Write-UiLine $t }
        return
    }
    if ($t -eq '' -and -not $g) { Write-UiLine $script:G['V']; return }    # '' = a blank frame line
    if ($g) {
        $t = $t.Replace("`n", "`n  ")            # explicit line breaks hang under the text
        if ($t) { $lines = Format-UiWrap "$g $t" '2' } else { $lines = Format-UiWrap $g '0' }
    } else {
        $lines = Format-UiWrap $t 'auto'
    }
    $lead = $script:UiPfx + $g
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($i -eq 0 -and $g -and $l.StartsWith($lead, [System.StringComparison]::Ordinal)) {
            $l = $script:UiPfx + (New-UiColor $Kind $g) + $l.Substring($lead.Length)
        }
        Write-UiLine $l
    }
}

function Write-UiPara {
    # Twin: ui_para. Like Write-UiSay but for a long paragraph OUTSIDE a frame: wrapped to 78
    # columns (a glyph message hangs under its text). Inside a frame it is Write-UiSay.
    param([string]$Kind, [string]$Text)
    if ($script:UiFrame -or $script:UiStep) { Write-UiSay $Kind $Text; return }
    $g = ''
    switch ($Kind) {
        'ok'   { $g = $script:G['Ok'] }
        'warn' { $g = $script:G['Warn'] }
        'fail' { $g = $script:G['Err'] }
    }
    $t = ConvertTo-UiGlyph $Text
    if ($g) { $lines = Format-UiWrap "$g $t" '2' '' '' } else { $lines = Format-UiWrap $t '0' '' '' }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($i -eq 0 -and $g -and $l.StartsWith($g, [System.StringComparison]::Ordinal)) { $l = (New-UiColor $Kind $g) + $l.Substring($g.Length) }
        Write-UiLine $l
    }
}

function Format-UiHome {
    # Twin: fmt_home. A leading $HOME becomes ~ (display only).
    param([string]$Path)
    $h = [string]$HOME
    if ($h) {
        $sep = [string][System.IO.Path]::DirectorySeparatorChar
        $cmp = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        if ($Path.StartsWith($h + $sep, $cmp)) { return ('~' + $Path.Substring($h.Length)) }
    }
    return $Path
}

function Clear-UiScreen {
    # Twin: clear_screen. Menu screens only, terminal only. Not logged.
    if (-not $script:UiTty) { return }
    try {
        if ($IsWindows) { [Console]::Clear() }
        else {
            # Like sh: home + erase screen, but keep the scrollback ([Console]::Clear() wipes it on Linux).
            $esc = [string][char]27
            [Console]::Write("$esc[H$esc[2J")
        }
    } catch { }
}

function Wait-UiEnter {
    # Twin: pause_menu. Waits for Enter so action output can be read before the screen is cleared.
    [Console]::Out.Write('Press Enter to return to the menu ')
    if ($null -eq (Read-UiLine)) { [Console]::Out.Write("`n") }
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Log {
    # Appends text to the session log, one timestamped line per text line. Does nothing when logging is off or no log
    # exists. Never fails the script. The log is ASCII (glyphs mapped)
    # and has no frame, step or spinner lines.
    param([string]$Text)
    if (-not $script:LogOn -or $script:LogMute -or -not $script:LogFile) { return }
    try {
        $ts = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        $plain = ConvertTo-UiGlyph $Text -ForceAscii
        $out = [string[]]@(($plain -split "`r?`n") | ForEach-Object { "$ts $_" })
        [System.IO.File]::AppendAllLines($script:LogFile, $out)
    } catch { }
}

function Write-Info { param([string]$Text) Write-UiSay 'info' $Text; Write-Log $Text }
function Write-Ok   { param([string]$Text) Write-UiSay 'ok' $Text; Write-Log "OK: $Text" }
function Write-Warn { param([string]$Text) Write-UiSay 'warn' $Text; Write-Log "WARNING: $Text" }
function Write-Fail { param([string]$Text) Write-UiSay 'fail' $Text; Write-Log "ERROR: $Text" }
# Long paragraphs (wrapped on screen outside a frame; the log gets the text as one piece).
function Write-InfoW { param([string]$Text) Write-UiPara 'info' $Text; Write-Log $Text }
function Write-WarnW { param([string]$Text) Write-UiPara 'warn' $Text; Write-Log "WARNING: $Text" }
function Write-FailW { param([string]$Text) Write-UiPara 'fail' $Text; Write-Log "ERROR: $Text" }

function Open-Log {
    # Opens this connection's log in the Downloads folder: one file per firewall per day, appended to when it exists
    # (one blank line, then the header). The day is the one fixed at login. Called right after the login.
    # -Retry: no warning here; the Logging menu item reports the failure itself (reason in $script:LogWhy).
    param([string]$HostName, [switch]$Retry)
    if (-not $script:LogOn) { return }
    $script:LogWhy = ''
    $appending = $false
    try {
        $dir = Get-DownloadsDir
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        elseif (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw 'File exists' }   # same reason as sh mkdir -p on a file
        $safe = $HostName -replace '[^A-Za-z0-9._-]', '_'
        if (-not $script:LogDay) { $script:LogDay = [DateTime]::Now.ToString('yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture) }
        $path = Join-Path $dir ("pfnetbird-$safe-{0}.log" -f $script:LogDay)
        $created = $false
        try {
            [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite).Dispose()
            $created = $true
        } catch [System.IO.IOException] { if (-not (Test-Path -LiteralPath $path)) { throw } }   # already exists (maybe made by another session a moment ago): append; any other error is real
        if ($created) {
            if (-not $IsWindows) {
                try {
                    [System.IO.File]::SetUnixFileMode($path, [System.IO.UnixFileMode]'UserRead, UserWrite')
                } catch {
                    & chmod 600 $path 2>$null
                }
            }
        } else {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$path is not a file" }
            $appending = (([System.IO.FileInfo]::new($path)).Length -gt 0)
            # Must be writable, else no log (same warning as a failed create). Nothing is written here.
            [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite).Dispose()
        }
    } catch {
        $script:LogWhy = Get-FileErrorReason $_.Exception
        if (-not $Retry) { Write-Warn "cannot create the session log ($($script:LogWhy)); continuing without it" }
        return
    }
    $script:LogFile = $path
    if ($appending) { try { [System.IO.File]::AppendAllLines($path, [string[]]@('')) } catch { } }
    Write-Log "pfnetbird $ScriptVersion session log started"
}

function Close-Log {
    # Closes the log and prints its path once.
    if ($script:LogFile) {
        $path = $script:LogFile
        $script:LogFile = $null
        [Console]::Out.Write("Log saved: $path`n")
    }
}

function Get-LogStateWord { if ($script:LogOn) { 'on' } else { 'off' } }
# Connected menu: logging is on but no log file could be opened, so nothing is written.
function Get-LogMenuWord { if ($script:LogOn -and -not $script:LogFile) { 'off (cannot write)' } else { Get-LogStateWord } }

function Get-ExceptionChain {
    # The exception and its InnerException chain (covers MethodInvocationException and AggregateException).
    param($Exception)
    $list = [System.Collections.Generic.List[object]]::new()
    $e = $Exception
    while ($null -ne $e -and $list.Count -lt 20) { $list.Add($e); $e = $e.InnerException }
    return ,$list.ToArray()
}

function Get-ErrorMessage {
    # Message of the innermost exception, except for a lost session or a timeout: those carry their own
    # outer message (as in sh: "the ssh session ended unexpectedly").
    param($Exception)
    $chain = Get-ExceptionChain $Exception
    foreach ($e in $chain) {
        if ($e -is [System.IO.EndOfStreamException] -or $e -is [System.TimeoutException]) { return [string]$e.Message }
    }
    return [string]$chain[$chain.Length - 1].Message
}

function Get-FileErrorReason {
    # Short OS-style reason for a local file error, like the text after the last ": " of a sh error
    # ("Permission denied"), instead of the raw .NET message ('Exception calling "Open" ...').
    param($Exception)
    $chain = Get-ExceptionChain $Exception
    $e = $chain[$chain.Length - 1]
    if ($e -is [System.UnauthorizedAccessException]) { return 'Permission denied' }
    if ($e -is [System.IO.DirectoryNotFoundException] -or $e -is [System.IO.FileNotFoundException]) { return 'No such file or directory' }
    # Another process holds the file open without sharing: Windows sharing / lock violation (0x80070020, 0x80070021);
    # .NET on Linux emulates FileShare between its own processes and reports HResult 11 (EWOULDBLOCK).
    if ($e.GetType() -eq [System.IO.IOException] -and (($e.HResult -band 0xFFFF) -in 32, 33 -or $e.HResult -eq 11)) { return 'file is in use' }
    return [string]$e.Message
}

function Test-SessionLost {
    # True when the ssh session is gone: Send-RemoteLine / Read-RemoteResult raise EndOfStreamException
    # for that. Local file errors (also IOException) are NOT a lost session. -IncludeTimeout adds the
    # firewall timeout.
    param($Exception, [switch]$IncludeTimeout)
    foreach ($e in (Get-ExceptionChain $Exception)) {
        if ($e -is [System.IO.EndOfStreamException]) { return $true }
        if ($IncludeTimeout -and $e -is [System.TimeoutException]) { return $true }
    }
    return $false
}

function Send-RemoteLine {
    # Twin: send_line. One line to the ssh session; a broken pipe becomes EndOfStreamException.
    param($Session, [string]$Line)
    try {
        $Session.Proc.StandardInput.WriteLine($Line)
    } catch {
        throw [System.IO.EndOfStreamException]::new('the ssh session ended unexpectedly', $_.Exception)
    }
}

function Read-YesNo {
    # Twin: read_yes_no. The logged text stays the question as given.
    param([string]$Question)
    $q = ConvertTo-UiGlyph "${Question}:"
    if ($script:UiFrame) {
        # Framed: earlier wrapped lines are printed, the last one becomes the prompt.
        $lines = Format-UiWrap $q
        for ($i = 0; $i -lt $lines.Count - 1; $i++) { Write-UiLine $lines[$i] }
        $q = $lines[$lines.Count - 1]
    } else {
        $q = ConvertTo-UiClean $q
    }
    [Console]::Out.Write("$q ")
    $answer = ([string](Read-UiLine)).Trim().ToLowerInvariant()
    $shown = if ($answer) { $answer } else { '(empty)' }
    Write-Log "prompt: $Question -> answer: $shown"
    return ($answer -eq 'y' -or $answer -eq 'yes')
}

function Assert-Interactive {
    $noConsole = $false
    try {
        if ([Console]::IsInputRedirected -or $null -eq $Host.UI.RawUI) { $noConsole = $true }
    } catch { $noConsole = $true }
    if ($noConsole) { throw 'run pfnetbird from an interactive terminal' }
    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        throw 'the ssh client was not found on this machine (install OpenSSH client)'
    }
}

# ---------------------------------------------------------------------------
# Transport: ALL contact with the box lives in these three functions.
# ---------------------------------------------------------------------------
function Read-RemoteResult {
    # Reads stdout lines until this command's marker. Whole-command deadline.
    param($Session, [string]$Marker, [int]$TimeoutSec)
    $rx    = '^' + [regex]::Escape($Marker) + '_(\d+)$'
    $lines = [System.Collections.Generic.List[string]]::new()
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $remaining = ($TimeoutSec * 1000) - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0) { throw [System.TimeoutException]::new("timed out after $TimeoutSec s waiting for the firewall") }
        $task = $Session.Proc.StandardOutput.ReadLineAsync()
        # The wait is sliced (200 ms) on the SAME read, so nothing is consumed and the deadline is the
        # same; between slices the spinner of an open step is redrawn.
        $done = $false
        while (-not $done) {
            try { $done = $task.Wait([Math]::Min(200, $remaining)) }
            catch { throw [System.IO.EndOfStreamException]::new('the ssh session ended unexpectedly', $_.Exception) }
            Receive-SshStderr $Session
            if ($done) { break }
            $remaining = ($TimeoutSec * 1000) - [int]$clock.ElapsedMilliseconds
            if ($remaining -le 0) { throw [System.TimeoutException]::new("timed out after $TimeoutSec s waiting for the firewall") }
            Invoke-UiTick
        }
        Invoke-UiTick
        Receive-SshStderr $Session
        $line = $task.Result
        if ($null -eq $line) { throw [System.IO.EndOfStreamException]::new('the ssh session ended unexpectedly') }
        $line = $line.TrimEnd("`r")
        if ($line -match $rx) {
            while ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
            return [pscustomobject]@{ Output = [string[]]$lines.ToArray(); ExitCode = [int]$Matches[1] }
        }
        $lines.Add($line)
    }
}

function Receive-SshStderr {
    # Echoes the lines ssh has logged to its -E file so far to the console and keeps them in
    # ErrText (twin: the tee in connect_remote). Never blocks. -Final also takes a last line without
    # a newline.
    param($Session, [switch]$Final)
    if (-not $Session.ErrFile) { return }
    $chunk = ''
    try {
        $fs = [System.IO.FileStream]::new($Session.ErrFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        try {
            if ($fs.Length -gt $Session.ErrPos) {
                $null = $fs.Seek($Session.ErrPos, [System.IO.SeekOrigin]::Begin)
                $buf = [byte[]]::new([int]($fs.Length - $Session.ErrPos))
                $n = $fs.Read($buf, 0, $buf.Length)
                $Session.ErrPos += $n
                $chunk = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
            }
        } finally { $fs.Dispose() }
    } catch { return }
    $text = $Session.ErrPart + $chunk
    $parts = $text -split "`n"
    $Session.ErrPart = $parts[$parts.Count - 1]
    $last = $parts.Count - 2
    if ($Final -and $Session.ErrPart.Trim("`r") -ne '') { $last = $parts.Count - 1; $Session.ErrPart = '' }
    for ($i = 0; $i -le $last; $i++) {
        $line = $parts[$i].TrimEnd("`r")
        [Console]::Error.WriteLine($line)
        $null = $Session.ErrText.AppendLine($line)
    }
}

function Connect-Remote {
    param([string]$HostName, [string]$UserName)

    # [addr] and [addr]:port: ssh keeps brackets in a host name, so pass the bare address and the port as
    # -p. The screen and the log keep what was typed. (twin: connect_remote)
    $portOpts = @()
    $sshHost = $HostName
    if ($HostName -cmatch '\A\[([^\]]+)\](:([0-9]+))?\z') {
        $sshHost = $Matches[1]
        if ($Matches[3]) { $portOpts = @('-p', [string][int]$Matches[3]) }
    }
    $psi = [System.Diagnostics.ProcessStartInfo]::new('ssh')
    # Plain ssh: no key options, so ~/.ssh/config, the agent (SSH_AUTH_SOCK, IdentityAgent) and keys
    # apply; ssh prompts for the password only if no key works. One attempt (sshguard), never retried.
    # The method order is fixed to publickey, then password (twin: connect_remote in pfnetbird.sh):
    # NumberOfPasswordPrompts counts PER method, so the default order (publickey, keyboard-interactive,
    # password) asked twice on a wrong password (the PAM prompt, then "user@host's password:") and
    # counted two failed logins for sshguard. pfSense's sshd offers the password method in both modes
    # that take a password ("Key or Password" and "Require both": AuthenticationMethods
    # publickey,password); keyboard-interactive would fail without a prompt in the second.
    # PreferredAuthentications, not KbdInteractiveAuthentication (that aborts OpenSSH older than 8.7).
    $errFile = $null
    try { $errFile = [System.IO.Path]::GetTempFileName() } catch { }
    $errOpt = if ($errFile) { @('-E', $errFile) } else { @() }
    # With -Key: that key only, and no password fallback, so a rejected key is one failed attempt
    # (sshguard). Without it: the plain method order above. (twin: connect_remote, auth_opts)
    $authOpts = if ($script:KeyGiven) {
        @('-i', $script:KeyFile,
          '-o', 'IdentitiesOnly=yes',
          '-o', 'PubkeyAuthentication=yes',
          '-o', 'PasswordAuthentication=no',
          '-o', 'PreferredAuthentications=publickey')
    } else {
        @('-o', 'PreferredAuthentications=publickey,password')
    }
    foreach ($a in (@('-T') + $errOpt + $authOpts + $portOpts + @(
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'ConnectTimeout=15',
            '-o', 'ServerAliveInterval=30',
            "$UserName@$sshHost",
            'sh'))) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardInput    = $true
    $psi.RedirectStandardOutput   = $true
    # ssh's errors go to a private temp file (ssh -E; mode 600 on Linux, removed by Disconnect-Remote)
    # and Receive-SshStderr echoes them to the console, so a wrong password can be told from "no
    # answer" and the key hint shows only for "Too many authentication failures" (twin:
    # connect_remote). Redirecting stderr with a pipe is NOT used: with stdin, stdout and stderr all
    # redirected .NET leaves the terminal as pwsh has it, and ssh's password prompt (it reads
    # /dev/tty) then misbehaves. The prompt and what is typed never touch the file.
    $psi.RedirectStandardError    = $false
    $psi.UseShellExecute          = $false
    $psi.CreateNoWindow           = $false   # Windows: the password prompt needs the inherited console
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardInputEncoding    = $utf8
    $psi.StandardOutputEncoding   = $utf8

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        if ($errFile) { try { Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue } catch { } }
        throw
    }
    $proc.StandardInput.NewLine   = "`n"
    $proc.StandardInput.AutoFlush = $true

    $tok = [guid]::NewGuid().ToString('N')
    $script:Session = [pscustomobject]@{ Proc = $proc; Tok = $tok; Seq = 0; ErrFile = $errFile; ErrPos = 0L; ErrPart = ''; ErrText = [System.Text.StringBuilder]::new() }

    # PATH first, unlogged and without a marker (as sh does), then merge remote stderr into
    # stdout, then the handshake: echo + marker.
    $marker = $null
    try {
        Send-RemoteLine $script:Session 'export PATH="$PATH:/usr/local/bin:/usr/local/sbin"'
        Send-RemoteLine $script:Session 'exec 2>&1'
        $script:Session.Seq++
        $marker = "__PFNB_$($tok)_$($script:Session.Seq)"
        Send-RemoteLine $script:Session "echo handshake; printf '\n${marker}_%d\n' `"`$?`""
        # Generous deadline: a human types the password in this window.
        $null = Read-RemoteResult $script:Session $marker 180
    } catch {
        if (-not (Test-SessionLost $_.Exception)) { throw }
        $code = 'unknown'
        if ($proc.WaitForExit(5000)) { $code = $proc.ExitCode }
        # ssh's own error text: finish echoing it before our lines.
        Receive-SshStderr $script:Session -Final
        $err = $script:Session.ErrText.ToString()
        if ($err -match 'Connection timed out|Connection refused|No route to host|Could not resolve hostname') {
            # No answer at all: nothing was tried, so this is not a login failure and the key hint is wrong.
            $hit = $Matches[0]
            foreach ($eline in ($err -split "`n")) {
                if ($eline.Contains($hit)) { Write-Log "ssh: $($eline.Trim())"; break }
            }
            $nport = 22
            if ($HostName -cmatch '\A\[[^\]]+\]:([0-9]+)\z') { $nport = [int]$Matches[1] }
            throw "No answer from $HostName on port $nport. Check host and network. If you just had failed logins, pfSense (sshguard) may have blocked your IP; wait a few minutes."
        }
        if ($script:KeyGiven) {
            Write-WarnW 'pfSense sshguard blocks your IP after a few failed logins. Not retrying.'
            throw "login failed (ssh exit code $code)"
        }
        if ($err.Contains('Too many authentication failures')) {
            Write-WarnW 'ssh tries your SSH keys first, then the password. If ssh said "Too many authentication failures", your agent offers too many keys. Pin one for this host (IdentityFile <key>.pub + IdentitiesOnly yes in ~/.ssh/config, see 1Password''s SSH docs) or run with -Key <key>.pub.'
        }
        throw "Login failed (ssh exit code $code). Not retrying: pfSense login protection (sshguard) blocks your IP after about 3 failed attempts (default block 120 s, longer on repeats)."
    }
    Write-Ok 'Login OK'
}

function Invoke-Remote {
    param([Parameter(Mandatory)][string]$Command, [int]$TimeoutSec = 60)
    $s = $script:Session
    if ($null -eq $s) { throw 'not connected' }
    if ($Command -match "[`r`n]") { throw 'internal error: multi-line remote command' }
    $s.Seq++
    $marker = "__PFNB_$($s.Tok)_$($s.Seq)"
    # Brace group so </dev/null covers the whole command; $? is read right after it.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "remote> $Command"
    Send-RemoteLine $s "{ $Command; } </dev/null; printf '\n${marker}_%d\n' `"`$?`""
    $r = Read-RemoteResult $s $marker $TimeoutSec
    Write-Log ('remote< exit={0} duration={1}s lines={2}' -f $r.ExitCode, [int]$sw.Elapsed.TotalSeconds, $r.Output.Count)
    # Output is logged only for a failing command, and never while RemoteQuiet is set (config reads
    # and status output).
    if ($r.ExitCode -ne 0 -and -not $script:RemoteQuiet) {
        foreach ($l in $r.Output) { Write-Log "remote output: $l" }
    }
    return $r
}

function Invoke-RemoteSecret {
    # Like Invoke-Remote, but the command reads one line from stdin: the secret is sent as a here-doc
    # body (line 2) followed by the terminator (line 3). Only line 1 is logged; the secret never is.
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string]$Secret, [int]$TimeoutSec = 60, [string]$Note = 'secret on stdin, not logged')
    $s = $script:Session
    if ($null -eq $s) { throw 'not connected' }
    if ($Command -match "[`r`n]" -or $Secret -match "[`r`n]") { throw 'internal error: multi-line remote command' }
    $s.Seq++
    $marker = "__PFNB_$($s.Tok)_$($s.Seq)"
    $term = "__PFNB_S_$($s.Tok)_$($s.Seq)__"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "remote> $Command <<'$term' ($Note)"
    Send-RemoteLine $s "$Command <<'$term'; printf '\n${marker}_%d\n' `"`$?`""
    Send-RemoteLine $s $Secret
    Send-RemoteLine $s $term
    $r = Read-RemoteResult $s $marker $TimeoutSec
    Write-Log ('remote< exit={0} duration={1}s lines={2}' -f $r.ExitCode, [int]$sw.Elapsed.TotalSeconds, $r.Output.Count)
    if ($r.ExitCode -ne 0 -and -not $script:RemoteQuiet) {
        foreach ($l in $r.Output) { Write-Log "remote output: $l" }
    }
    return $r
}

function Invoke-RemotePayload {
    # Twin: remote_payload. Invoke-RemoteSecret for a non-secret payload (the auto-update runner, base64).
    # Logged as the command plus the payload size only.
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string]$Payload, [int]$TimeoutSec = 60)
    return (Invoke-RemoteSecret $Command $Payload $TimeoutSec "payload on stdin, $($Payload.Length) bytes, not logged")
}

function Disconnect-Remote {
    # Closes the session, prints the optional final message (also logged), closes the log.
    param([string]$Message)
    $s = $script:Session
    $script:Session = $null
    if ($null -ne $s) {
        try {
            if (-not $s.Proc.HasExited) {
                if ($script:Downloaded) { try { $s.Proc.StandardInput.WriteLine("rm -rf $RemoteDir") } catch { } }
                try { $s.Proc.StandardInput.WriteLine("rm -f $AutoBusy") } catch { }   # the "client change in progress" marker for the auto-update runner
                try { $s.Proc.StandardInput.WriteLine('exit') } catch { }
                if (-not $s.Proc.WaitForExit(5000)) { $s.Proc.Kill(); $null = $s.Proc.WaitForExit(2000) }
            }
        } catch { }
        try { $s.Proc.Dispose() } catch { }
        if ($s.ErrFile) { try { Remove-Item -LiteralPath $s.ErrFile -Force -ErrorAction SilentlyContinue } catch { } }
    }
    if ($Message) { Write-Info $Message }
    Close-Log
    $script:Downloaded = $false
    $script:Ctx.Backup = $null
    $script:Ctx.Identity = $null
    $script:Acb = $null
    $script:Au = New-AutoState
    $script:St = [pscustomobject]@{ Stage = 0; Box = $null; State = $null; Rel = $null }
}

function Invoke-Step {
    # A change step: a non-zero exit code stops the script.
    param([string]$Name, [string]$Command, [int]$TimeoutSec = 60)
    Write-Log "step: $Name"
    $r = Invoke-Remote $Command $TimeoutSec
    if ($r.ExitCode -ne 0) {
        $msg = "step '$Name' failed (exit code $($r.ExitCode)):"
        if ($r.Output.Count -gt 0) { $msg += "`n" + ($r.Output -join "`n") }   # twin: remote_step (no trailing newline without output)
        throw $msg
    }
    return $r
}

# ---------------------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------------------
function Test-HostName {
    # Twin: test_hostname. A host that is only digits and dots must be a valid IPv4 address (four numbers
    # 0-255, no leading zero except a single 0, because ssh reads 010 as octal): a bare "2", "192.0.2" or
    # "192.168.010.1" is rejected instead of being passed to ssh. A bracketed form is [addr] or [addr]:port
    # (port 1-65535); Connect-Remote strips the brackets before ssh sees the address. A port is only taken in
    # that bracketed form: an unbracketed host with exactly one ':' (host:port, 1.2.3.4:port) is rejected, an
    # IPv6 literal has at least two.
    param([string]$Value)
    if ($Value -cnotmatch '\A(\[[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*\](:[0-9]{1,5})?|[A-Za-z0-9][A-Za-z0-9._:-]*)\z') { return $false }
    if ($Value -cmatch '\A[^\[:]+:[^:]*\z') { return $false }
    if ($Value -cmatch '\]:([0-9]+)\z') {
        $pn = [int]$Matches[1]
        if ($pn -lt 1 -or $pn -gt 65535) { return $false }
    }
    if ($Value -cmatch '\A[0-9.]+\z') {
        if ($Value -cnotmatch '\A(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\z') { return $false }
        foreach ($i in 1..4) { if ([int]$Matches[$i] -gt 255) { return $false } }
    }
    return $true
}
function Test-UserName { param([string]$Value) return ($Value -cmatch '\A[A-Za-z0-9._][A-Za-z0-9._-]*\z') }

function Test-NetBirdRange {
    # 100.64.0.0/10
    param([string]$Value)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ip.GetAddressBytes()
    return ($b[0] -eq 100 -and (($b[1] -band 0xC0) -eq 64))
}

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------
function ConvertTo-PkgVersion {
    # Strip a pkg revision (_N) or epoch (,N) suffix, then parse.
    param([string]$Text)
    $clean = ($Text.Trim() -replace '[_,].*$', '')
    $v = $null
    if (-not [version]::TryParse($clean, [ref]$v)) { throw "cannot parse version '$Text'" }
    return $v
}

function Compare-PkgVersion {
    # Twin: version_cmp. The one version compare for every caller (up-to-date check, downgrade check).
    # -1, 0 or 1 (A older than, equal to, newer than B). Version strings as pkg and the release assets print
    # them: N.N[.N[.N]] with an optional revision _N and an optional epoch ,N. Numeric, part by part
    # (0.9.0 < 0.10.0); a missing part counts as 0, so 0.80 equals 0.80.0; the revision is compared last and
    # a missing revision counts as 0 (0.80.0 < 0.80.0_1 < 0.80.0_2). The epoch (,N) is ignored. Not [version]
    # -lt, which ranks 0.80 below 0.80.0.
    param([string]$A, [string]$B)
    $a = ($A -replace '\s', '') -replace ',.*$', ''
    $b = ($B -replace '\s', '') -replace ',.*$', ''
    $ra = [long]0; $rb = [long]0
    $ia = $a.IndexOf('_'); if ($ia -ge 0) { $null = [long]::TryParse($a.Substring($ia + 1), [ref]$ra); $a = $a.Substring(0, $ia) }
    $ib = $b.IndexOf('_'); if ($ib -ge 0) { $null = [long]::TryParse($b.Substring($ib + 1), [ref]$rb); $b = $b.Substring(0, $ib) }
    $pa = @($a.Split('.'))
    $pb = @($b.Split('.'))
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { $null = [long]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { $null = [long]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    if ($ra -lt $rb) { return -1 }
    if ($ra -gt $rb) { return 1 }
    return 0
}

function Test-Downgrade {
    # Twin: is_downgrade. True if the picked release is numerically older than the installed client.
    param($State, $Rel)
    if (-not $State.Installed) { return $false }
    return ((Compare-PkgVersion ([string]$State.Client) ([string]$Rel.Client.Version)) -gt 0)
}

# ---------------------------------------------------------------------------
# Box inspection
# ---------------------------------------------------------------------------
function Get-BoxInfo {
    $r = Invoke-Remote 'id -u'
    if ($r.ExitCode -ne 0 -or ($r.Output | Select-Object -Last 1).Trim() -ne '0') {
        throw 'needs admin or root (this login is not uid 0)'
    }

    $r = Invoke-Remote 'cat /etc/version'
    if ($r.ExitCode -ne 0 -or $r.Output.Count -eq 0) { throw 'cannot read /etc/version - is this a pfSense box?' }
    $ver = $r.Output[0].Trim()
    $edition = if ($ver -cmatch '\A2\.') { 'CE' } elseif ($ver -cmatch '\A[0-9]{2}\.[0-9]{2}') { 'Plus' } else { 'unknown' }

    $r = Invoke-Remote 'uname -p'
    if ($r.ExitCode -ne 0 -or $r.Output.Count -eq 0) { throw 'cannot read the CPU architecture (uname -p)' }
    $uname = $r.Output[0].Trim()
    $arch = switch ($uname) {
        'amd64'   { 'x86_64' }
        'arm64'   { 'aarch64' }
        'aarch64' { 'aarch64' }
        default   { throw "unsupported architecture '$uname'" }
    }

    $short = ''
    $full = ''
    $r = Invoke-Remote 'hostname'
    if ($r.ExitCode -eq 0 -and $r.Output.Count -gt 0) {
        $full = $r.Output[0].Trim()          # shown in the connected screen title, nothing else uses it
        $short = ($full -split '\.')[0]
    }

    $r = Invoke-Remote 'pkg config ABI'
    if ($r.ExitCode -ne 0 -or $r.Output.Count -eq 0) { throw 'cannot read the package ABI (pkg config ABI)' }
    $abi = $r.Output[0].Trim()
    if ($abi -cnotmatch '\A[Ff]ree[Bb][Ss][Dd]:([0-9]+):(.+)\z') { throw "unexpected package ABI '$abi'" }
    $major = [int]$Matches[1]
    if ($major -lt $MinFreeBsd) { throw "FreeBSD $major is too old (ABI $abi); minimum is FreeBSD $MinFreeBsd" }

    return [pscustomobject]@{
        Version = $ver; Edition = $edition
        Arch = $arch; HostShort = $short; Fqdn = $full; Abi = $abi; AbiMajor = $major
    }
}

function Get-NetBirdState {
    $r = Invoke-Remote 'pkg info -e netbird'
    if ($r.ExitCode -ne 0) {
        return [pscustomobject]@{ Installed = $false; Client = $null; Package = $null; ClientVersion = $null }
    }
    $client = (Invoke-Remote "pkg query '%v' netbird").Output | Select-Object -First 1
    $pkg    = (Invoke-Remote "pkg query '%v' pfSense-pkg-NetBird").Output | Select-Object -First 1
    if (-not $client) { throw 'netbird is installed but its version could not be read' }
    return [pscustomobject]@{
        Installed = $true; Client = $client.Trim(); Package = if ($pkg) { $pkg.Trim() } else { $null }
        ClientVersion = ConvertTo-PkgVersion $client
    }
}

# ---------------------------------------------------------------------------
# GitHub release lookup (runs on the client)
# ---------------------------------------------------------------------------
function Get-AssetDigest {
    param($Asset)
    $p = $Asset.PSObject.Properties['digest']
    $ok = ($null -ne $p) -and ([string]$p.Value -cmatch '\Asha256:([0-9a-fA-F]{64})\z')
    if (-not $ok) {
        throw "release asset '$($Asset.name)' has no usable sha256 digest; there is no fallback checksum source in v0.1"
    }
    return $Matches[1].ToLowerInvariant()
}

function Resolve-Asset {
    param($Assets, [string]$Pattern)
    $hit = @($Assets | Where-Object { $_.name -cmatch $Pattern }) | Select-Object -First 1
    if (-not $hit) { throw "no release asset matches $Pattern" }
    $null = ([string]$hit.name -cmatch $Pattern)
    $version = $Matches[1]
    $name = [string]$hit.name
    $url  = [string]$hit.browser_download_url
    if ($name -cnotmatch '\A[A-Za-z0-9._+-]+\z') { throw "unexpected asset file name '$name'" }
    if (-not $url.StartsWith($UrlPrefix)) { throw "unexpected download URL for '$name'" }
    if ($url.Contains("'")) { throw "unexpected download URL for '$name'" }
    return [pscustomobject]@{
        Name = $name; Url = $url; Digest = (Get-AssetDigest $hit)
        Version = $version
    }
}

function Get-GitHubCached {
    # One GitHub API reply per URL, cached in memory for 10 minutes (script scope, the raw reply).
    # Failures are never cached. A rate limit throws an exception marked with Data['pfnbRateLimit'].
    param([string]$Uri)
    $now = (Get-Date).ToUniversalTime()
    $hit = $script:ApiCache[$Uri]
    if ($null -ne $hit) {
        $age = ($now - $hit.At).TotalSeconds
        if ($age -ge 0 -and $age -lt 600) { return $hit.Data }
    }
    $data = Get-LatestReleaseRaw $Uri
    $script:ApiCache[$Uri] = [pscustomobject]@{ Data = $data; At = $now }
    return $data
}

function ConvertTo-ReleaseInfo {
    # The client and UI packages of one release object (API reply or list entry), for this architecture.
    param($Rel, [string]$Arch)
    $a = [regex]::Escape($Arch)
    $client = Resolve-Asset $Rel.assets "^netbird-(.+)-$a\.pkg$"
    $ui     = Resolve-Asset $Rel.assets "^pfSense-pkg-NetBird-(.+)-$a\.pkg$"
    return [pscustomobject]@{
        Tag = [string]$Rel.tag_name; Client = $client; Ui = $ui
        ClientVersion = ConvertTo-PkgVersion $client.Version
    }
}

function Get-LatestRelease {
    # The latest release, from the 10-minute cache (the asset match is per call).
    param([string]$Arch)
    $rel = Get-GitHubCached "$RepoApi/releases/latest"
    return ConvertTo-ReleaseInfo $rel $Arch
}

function Get-OlderRelease {
    # The 5 newest stable releases before the latest (newest first), as
    # release infos. One list call, cached for 10 minutes like the latest release.
    param([string]$Arch, [string]$LatestTag)
    $list = Get-GitHubCached "$RepoApi/releases?per_page=50"
    $a = [regex]::Escape($Arch)
    $items = @($list | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['tag_name'] })
    $seen = [bool]($LatestTag -and @($items | Where-Object { [string]$_.tag_name -eq $LatestTag }).Count -gt 0)
    $skipped = $false
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $items) {
        $tag = [string]$r.tag_name
        $isDraft = ($null -ne $r.PSObject.Properties['draft']) -and [bool]$r.draft
        $isPre = ($null -ne $r.PSObject.Properties['prerelease']) -and [bool]$r.prerelease
        $cl = $false
        if ($null -ne $r.PSObject.Properties['assets']) {
            foreach ($as in @($r.assets)) { if ([string]$as.name -cmatch "\Anetbird-(.+)-$a\.pkg\z") { $cl = $true } }
        }
        if ($isDraft -or $isPre -or -not $cl) { continue }
        if ($tag -cnotmatch '\A[A-Za-z0-9._-]+\z') { continue }
        # Everything up to and including the latest release is skipped (without a known latest: the first one).
        if (-not $skipped) {
            if ($seen) {
                if ($tag -eq $LatestTag) { $skipped = $true }
                continue
            }
            $skipped = $true
            continue
        }
        try { $out.Add((ConvertTo-ReleaseInfo $r $Arch)) } catch { Write-Log "release $tag skipped: $($_.Exception.Message)"; continue }
        if ($out.Count -ge 5) { break }
    }
    return @($out)
}

function Get-LatestReleaseRaw {
    param([string]$uri)
    $headers = @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = "pfnetbird/$ScriptVersion" }
    Write-Log "GitHub lookup: $uri"
    $tok = [string]$env:GITHUB_TOKEN
    if ($tok) {
        # Twin: gh_lookup. A token that cannot be a header value is not sent, and .NET's own error (which
        # would contain the token) never reaches the screen or the log.
        $bad = ''
        if ($tok -match '[\x00-\x1f\x7f]') { $bad = 'GITHUB_TOKEN contains a control character and cannot be sent' }
        elseif ($tok.Contains('"')) { $bad = 'GITHUB_TOKEN contains a double quote and cannot be sent' }
        elseif (-not [System.Net.Http.Headers.AuthenticationHeaderValue]::TryParse("Bearer $tok", [ref]$null)) { $bad = 'GITHUB_TOKEN contains a character that cannot be sent in an HTTP header' }
        if ($bad) {
            Write-Log 'GitHub HTTP status: none'
            throw "GitHub release lookup failed ($uri): $bad"
        }
        $headers['Authorization'] = "Bearer $tok"
    }
    try {
        $rel = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 30 -StatusCodeVariable httpCode
        Write-Log "GitHub HTTP status: $httpCode"
    } catch {
        $code = 'none'
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        Write-Log "GitHub HTTP status: $code"
        if ($code -ne 'none') {
            # Rate limit: HTTP 429, or HTTP 403 with X-RateLimit-Remaining: 0 or "rate limit" in the
            # message. Any other 403 stays the generic error below.
            $msg0 = ''
            try { $msg0 = [string](([string]$_.ErrorDetails.Message | ConvertFrom-Json).message) } catch { }
            $remain = ''
            try {
                $vals = $null
                if ($_.Exception.Response.Headers.TryGetValues('X-RateLimit-Remaining', [ref]$vals)) { $remain = [string]($vals | Select-Object -First 1) }
            } catch { }
            if ($code -eq 429 -or ($code -eq 403 -and ($remain -eq '0' -or $msg0 -match '(?i)rate limit'))) {
                $rl = [System.InvalidOperationException]::new('GitHub rate limit reached')
                $rl.Data['pfnbRateLimit'] = $true
                throw $rl
            }
            # Twin: get_latest_release. The GitHub "message" of the error body, when there is one.
            $msg = ''
            try { $msg = [string](([string]$_.ErrorDetails.Message | ConvertFrom-Json).message) } catch { }
            if ($msg) { throw "GitHub API returned HTTP $code for ${uri}: $msg" }
            throw "GitHub API returned HTTP $code for $uri"
        }
        $em = [string]$_.Exception.Message
        if ($tok) { $em = $em.Replace($tok, '***') }
        throw "GitHub release lookup failed ($uri): $em"
    }
    return $rel
}

# ---------------------------------------------------------------------------
# Downloads folder (the backups and the session log go there)
# ---------------------------------------------------------------------------
function Get-DownloadsDir {
    if ($IsWindows) {
        try {
            $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            $name = '{374DE290-123F-4565-9164-39C4925E467B}'
            $prop = (Get-ItemProperty -Path $key -ErrorAction Stop).PSObject.Properties[$name]
            if ($prop -and $prop.Value) {
                $dir = [Environment]::ExpandEnvironmentVariables([string]$prop.Value)
                if ($dir) { return $dir }
            }
        } catch { }
        return (Join-Path $env:USERPROFILE 'Downloads')
    }
    if (Get-Command xdg-user-dir -ErrorAction SilentlyContinue) {
        try {
            $dir = (& xdg-user-dir DOWNLOAD 2>$null | Select-Object -First 1)
            if ($dir -and $dir.Trim()) { return $dir.Trim() }
        } catch { }
    }
    return (Join-Path $HOME 'Downloads')
}

function Test-ConfigRoot {
    # Well-formed XML with root element <pfsense>. DTDs are refused.
    param([string]$Text)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($Text), $settings)
    try {
        $null = $reader.MoveToContent()
        $root = $reader.Name
        while ($reader.Read()) { }
        return ($root -eq 'pfsense')
    } finally { $reader.Dispose() }
}

# --- PHP run on the box, taken VERBATIM from pfnetbird.sh (same names, lower-camel). No single quotes
# inside: each is wrapped in php -r '...'.
$AcbPrePhp = 'require_once("config.inc"); require_once("acb.inc"); echo "ACB_CODE=".(function_exists("acb_backup_stage_upload")?"new":"legacy")."\n"; echo "ENABLED=".(config_get_path("system/acb/enable")=="yes"?1:0)."\n"; echo "PASSWORD_SET=".(strlen((string)config_get_path("system/acb/encryption_password"))>0?1:0)."\n"; echo "PENDING=".count((array)glob("/cf/conf/acb/*.form"))."\n";'
$AcbWritePhp = 'require_once("config.inc"); $w=write_config("pfnetbird: before @WHAT@-MaNuAlBaCkUp"); echo "WRITE=".(is_array($w)?1:0)."\n"; echo "REV=".config_get_path("revision/time")."\n";'
$AcbConfirmPhp = 'require_once("config.inc"); require_once("acb.inc"); $k=get_acb_device_key(); $l=(array)acb_backup_list($k); echo "LISTED=".count($l)."\n"; $b=null; foreach($l as $e){ if(stripos((string)$e["reason"],"pfnetbird")===false){continue;} if($b===null||strtotime($e["time"])>=strtotime($b["time"])){$b=$e;} } if($b===null){echo "REMOTE_MATCH=0\n"; exit(0);} $q=acb_backup_get($k,$b["time"]); $p=explode("++++",(string)$q[0],2); echo "REMOTE_MATCH=".(strtolower(trim($p[0]))=="@SHA@"?1:0)."\n"; echo "TIME=".(trim((string)$b["localtime"])!==""?$b["localtime"]:$b["time"])."\n";'
$ExportPhp = 'require_once("config.inc"); require_once("/usr/local/pfSense/include/www/backup.inc"); $p=["download"=>"Download","backuparea"=>"","donotbackuprrd"=>"yes","backupssh"=>"yes"]; if($e){$w=base64_decode(trim(stream_get_contents(STDIN))); $p["encrypt"]="yes"; $p["encrypt_password"]=$w; $p["encrypt_password_confirm"]=$w;} $r=execPost($p,[],false); if(!is_string($r)){ foreach((array)$r["input_errors"] as $m){echo "ERROR=".$m."\n";} exit(1);} $j=json_decode($r,true); $d=base64_decode($j["contents"]); echo "NAME=".$j["name"]."\n"."SIZE=".strlen($d)."\n"."SHA256=".hash("sha256",$d)."\n"."ENCRYPTED=".($e?1:0)."\n".chunk_split($j["contents"],76,"\n");'
$PkgCfgSavePhp = 'require_once("config.inc"); $c=config_get_path("installedpackages/netbird"); if (is_array($c) && !empty($c)) { $f="@FILE@"; file_put_contents($f, serialize($c)); chmod($f, 0600); echo "SAVED=1\n"; } else { echo "SAVED=0\n"; }'
$PkgCfgRestorePhp = 'require_once("config.inc"); $s=@unserialize((string)@file_get_contents("@FILE@"), ["allowed_classes"=>false]); if (!is_array($s) || empty($s)) { echo "RESTORE=none\n"; exit(0); } if (!config_read_file(true, false)) { echo "RESTORE=reread-failed\n"; exit(1); } $cur=config_get_path("installedpackages/netbird"); if (!is_array($cur) || empty($cur) || $cur != $s) { config_set_path("installedpackages/netbird", $s); $w=write_config("pfnetbird: restore NetBird package settings-NoReMoTeBaCkUp"); echo "RESTORE=".(is_array($w)?"restored":"failed")."\n"; } else { echo "RESTORE=unchanged\n"; }'
$UnCheckPhp = 'require_once("config.inc"); $a=0; $n0=""; $d0=""; foreach (config_get_path("interfaces", array()) as $n=>$i) { if (isset($i["if"]) && $i["if"]==="wt0") { $a=1; $n0=$n; $d0=isset($i["descr"])?$i["descr"]:""; break; } } echo "ASSIGNED=".$a.PHP_EOL; if ($a) { echo "IFNAME=".$n0.PHP_EOL; echo "DESCR=".$d0.PHP_EOL; $c=array("FW"=>"filter/rule","NAT"=>"nat/rule","ONAT"=>"nat/outbound/rule"); foreach ($c as $k=>$p) { $m=0; foreach (config_get_path($p, array()) as $r) { if (isset($r["interface"]) && in_array($n0, explode(",", $r["interface"]))) { $m++; } } echo $k."=".$m.PHP_EOL; } }'

# Auto-update PHP run on the box, taken VERBATIM from pfnetbird.sh (no single quotes inside: each is wrapped in php -r '...').
# Read: our cron job(s), runner sha256 (with the version string of the define() line replaced by @VERSION@, so a
# version bump alone does not change it), time zone, identity snapshots, last-result file.
$AutoReadPhp = 'require_once("config.inc"); $r="/root/pfnetbird/pfnetbird-auto.php"; $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $r) === false) { continue; } $n++; if ($n == 1) { foreach (["minute"=>"MIN","hour"=>"HOUR","mday"=>"MDAY","month"=>"MONTH","wday"=>"WDAY"] as $k=>$v) { echo $v."=".$i[$k]."\n"; } echo "EXACT=".(((string)$i["command"] === "/usr/bin/nice -n20 /usr/local/bin/php -f ".$r)?1:0)."\n"; } } echo "JOBS=".$n."\n"; echo "DIR=".(is_dir("/root/pfnetbird")?1:0)."\n"; echo "RUNNER_SHA=".(is_file($r)?hash("sha256",preg_replace("/^define\\(\\x27PFNB_RUNNER_VERSION\\x27, \\x27[^\\x27]*\\x27\\);$/m","define(\x27PFNB_RUNNER_VERSION\x27, \x27@VERSION@\x27);",file_get_contents($r))):"")."\n"; echo "TZ=".date("T")."\n"; $g=glob("/root/pfnetbird/identity-*.json"); echo "SNAPS=".(is_array($g)?count($g):0)."\n"; $f=@file("/root/pfnetbird/last-result", FILE_IGNORE_NEW_LINES); if (is_array($f)) { foreach ($f as $l) { echo "LAST_".$l."\n"; } } echo "READ=1\n";'
# Runner upload: base64 on stdin (payload), written to a .tmp file first.
$AutoWritePhp = '$d=base64_decode(trim(file_get_contents("php://stdin")), true); $t="/root/pfnetbird/pfnetbird-auto.php.tmp"; if (!is_string($d) || $d === "" || @file_put_contents($t, $d) !== strlen($d)) { echo "WRITE=0\n"; exit(1); } chmod($t, 0600); echo "WRITE=1\n";'
# Apply: prefixed with $m, $h, $d, $w. install_cron_job adds the job or updates it in place (no write when unchanged).
$AutoApplyPhp = 'require_once("config.inc"); require_once("services.inc"); $c="/usr/bin/nice -n20 /usr/local/bin/php -f /root/pfnetbird/pfnetbird-auto.php"; install_cron_job($c, true, $m, $h, $d, "*", $w, "root"); $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if ((string)$i["command"] === $c && (string)$i["minute"] === $m && (string)$i["hour"] === $h && (string)$i["mday"] === $d && (string)$i["month"] === "*" && (string)$i["wday"] === $w) { $n++; } } echo "APPLIED=".$n."\n"; $t=@file_get_contents("/etc/crontab"); echo "CRONTAB=".((is_string($t) && strpos($t, "/root/pfnetbird/pfnetbird-auto.php") !== false)?1:0)."\n";'
# Remove every job with the exact command (at most 10 loops), then count what still mentions the runner.
$AutoRemovePhp = 'require_once("config.inc"); require_once("services.inc"); $r="/root/pfnetbird/pfnetbird-auto.php"; $c="/usr/bin/nice -n20 /usr/local/bin/php -f ".$r; $x=0; for ($k=0; $k<10; $k++) { $f=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $c) !== false) { $f=1; break; } } if (!$f) { break; } install_cron_job($c, false); $x++; } $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $r) !== false) { $n++; } } echo "REMOVED=".$x."\n"; echo "LEFT=".$n."\n";'

# The runner (PHP, run by pfSense cron). Taken VERBATIM from pfnetbird.sh: the bytes hashed are the bytes sent.
# The placeholder @VERSION@ is replaced by Get-AutoRunnerBuild. Single-quoted here-string: nothing is expanded.
$AutoRunnerPhp = (@'
<?php
/*
 * pfnetbird-auto.php - unattended NetBird update on pfSense, run by pfSense cron.
 * Deployed and maintained by pfnetbird (menu: Auto-update). Do not edit: pfnetbird checks its sha256.
 * Newer stable release -> download + SHA-256 + ABI check -> ACB backup confirmed at Netgate ->
 * pkg add -f (both) -> netbird service restart -> wait for "Management: Connected".
 * Prints nothing. Writes /root/pfnetbird/auto.log and /root/pfnetbird/last-result, reports via the
 * GUI notices. Never logs the ACB device key, the ACB password, config content or netbird status output.
 */
define('PFNB_RUNNER_VERSION', '@VERSION@');
define('PFNB_DIR', '/root/pfnetbird');
define('PFNB_LOG', PFNB_DIR . '/auto.log');
define('PFNB_STATE', PFNB_DIR . '/last-result');
define('PFNB_LOCK', '/tmp/pfnetbird-auto.lock');
define('PFNB_BUSY', '/tmp/pfnetbird-client.busy');
define('PFNB_API', 'https://api.github.com/repos/netbirdio/pfsense-netbird/releases/latest');
define('PFNB_URL_PREFIX', 'https://github.com/netbirdio/pfsense-netbird/releases/download/');
define('PFNB_IDENTITY', '/var/db/netbird/config.json');
define('PFNB_LOG_MAX', 262144);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', PFNB_LOG);
ini_set('zend.exception_ignore_args', '1');
putenv('PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin');
putenv('HTTP_USER_AGENT=pfnetbird-auto/' . PFNB_RUNNER_VERSION);
umask(077);

$RUN = date('Ymd-His');
$TMP = '';
$FROM = '';
$TO = '';
$DONE = false;      /* set by pfnb_finish; a started run that ends without it crashed */
$STARTED = false;
$SNAP = '';         /* identity snapshot of this run while it exists */
$STOPPED = false;   /* NetBird was stopped by this run and not yet restarted */
$OBTAIL = '';       /* the last 4 KB pfSense code printed (pfnb_ob); nothing else of the output is kept */
$OBN = 0;           /* bytes pfSense code printed in all */
$ACB_DBG = file_exists('/tmp/acb_debug.txt');   /* acb.inc may leave this file behind; it is removed at the end, never read */

function pfnb_log($m) {
	@file_put_contents(PFNB_LOG, date('Y-m-d H:i:s') . ' [' . $GLOBALS['RUN'] . '] ' . $m . "\n", FILE_APPEND);
}

/* Runs a stock command. Output stays in memory; only pfnb_tail() ever logs part of it. */
function pfnb_sh($cmd, &$out = null) {
	$out = [];
	$rc = 0;
	exec($cmd . ' 2>&1', $out, $rc);
	return $rc;
}

function pfnb_tail($out, $n) {
	foreach (array_slice((array)$out, -$n) as $l) {
		pfnb_log('  | ' . substr((string)$l, 0, 200));
	}
}

/* Last lines of a command output file (package messages, no secrets). */
function pfnb_tail_file($f, $n) {
	$l = @file($f, FILE_IGNORE_NEW_LINES);
	if (is_array($l)) { pfnb_tail($l, $n); }
}

/* After a restart NetBird must run. "service netbird status" checks the daemon(8) supervisor by its pidfile
 * /var/run/netbird.pid; if it is not running, start it once more. rc.subr and daemon -P refuse a start while
 * the pidfile is held, so this never starts a second daemon. Restart and start run under timeout --foreground:
 * without it FreeBSD timeout(1) is the reaper of all descendants, waits for the new daemon and kills it at expiry. */
function pfnb_ensure_running() {
	if (pfnb_sh('timeout 20 service netbird status </dev/null >/dev/null 2>&1') == 0) { return; }
	pfnb_log('netbird is not running after the restart; starting it once more');
	pfnb_log('netbird service start: exit ' . pfnb_sh('timeout --foreground 120 netbird service start </dev/null >/dev/null 2>&1'));
}

/* The NetBird private key of an identity file, or null. Compared only, never logged. */
function pfnb_pk($f) {
	$j = @json_decode((string)@file_get_contents($f), true);
	return (is_array($j) && isset($j['PrivateKey']) && is_string($j['PrivateKey']) && $j['PrivateKey'] !== '') ? $j['PrivateKey'] : null;
}

/* The values that must never reach the log: the ACB password, the ACB device key (the one in the config and
 * the legacy one derived from the SSH host key; get_acb_device_key() is not called, it can write the config)
 * and the NetBird private key, each also in its white-space-collapsed form (as pfnb_piece collapses the text),
 * values under 4 bytes left out, longest first (so a shorter one inside a longer one cannot break its mask).
 * null when they cannot be read. */
function pfnb_secrets() {
	$x = [];
	try {
		if (function_exists('config_get_path')) {
			foreach (['system/acb/encryption_password', 'system/acb/device_key'] as $k) { $x[] = config_get_path($k); }
		}
		if (function_exists('get_acb_legacy_device_key')) { $x[] = get_acb_legacy_device_key(); }
		$x[] = pfnb_pk(PFNB_IDENTITY);
		if ($GLOBALS['SNAP'] !== '') { $x[] = pfnb_pk($GLOBALS['SNAP']); }
	} catch (Throwable $e) {
		return null;
	}
	$r = [];
	foreach ($x as $v) {
		if (!is_string($v)) { continue; }
		foreach ([$v, trim(preg_replace('/[\x00-\x20\x7f]+/', ' ', $v))] as $w) {
			if (strlen($w) >= 4 && !in_array($w, $r, true)) { $r[] = $w; }
		}
	}
	usort($r, function ($a, $b) { return strlen($b) - strlen($a); });
	return $r;
}

/* One piece of an error text for the log. The secrets are masked FIRST, then the piece is cut, so a cut never
 * splits a secret. The raw text is masked, control characters and runs of white space become one space, and it
 * is masked again (the collapse can rebuild a secret that holds white space printed differently). $open names
 * the edge where $s itself was cut from a longer text ('head': $s is the start of it, so its end is open; 'tail':
 * its start is open; '': $s is whole). A secret can straddle that edge, so then that edge of the collapsed text
 * is dropped by the length of the longest secret. Last the piece is cut to $len bytes, keeping the side $keep
 * ('head' or 'tail'). */
function pfnb_piece($s, $open, $keep, $len) {
	$x = pfnb_secrets();
	if ($x === null) { return 'the error text was not logged (it could not be checked for secrets)'; }
	$s = (string)$s;
	$m = 0;
	foreach ($x as $v) { $s = str_replace($v, '***', $s); $m = max($m, strlen($v)); }
	$s = trim(preg_replace('/[\x00-\x20\x7f]+/', ' ', $s));
	foreach ($x as $v) { $s = str_replace($v, '***', $s); }
	if ($m > 0 && $open === 'head') { $s = rtrim((string)substr($s, 0, max(0, strlen($s) - $m))); }
	if ($m > 0 && $open === 'tail') { $s = ltrim((string)substr($s, $m)); }
	if (strlen($s) > $len) { $s = $keep === 'tail' ? '...' . substr($s, -$len) : substr($s, 0, $len) . '...'; }
	return $s;
}

/* One log line from a whole error text: masked, one line, capped at $max bytes. */
function pfnb_clean($s, $max = 400) {
	return pfnb_piece($s, '', 'head', $max);
}

/* Output handler of ob_start(): keeps only the last 4 KB of what pfSense code prints (raw: pfnb_why masks it
 * before it cuts it), counts the bytes, prints nothing. With a chunk size the buffer is handed over every
 * 4 KB, so the output never piles up in memory. */
function pfnb_ob($buf, $phase) {
	$GLOBALS['OBN'] += strlen($buf);
	$GLOBALS['OBTAIL'] = substr($GLOBALS['OBTAIL'] . substr($buf, -4096), -4096);
	return '';
}

/* Why a started run ended without pfnb_finish: the last fatal PHP error, else the last bytes that pfSense
 * code printed before it called exit or die (pfnb_ob), and the last PHP warning or notice if any. Bounded:
 * each part is taken raw at 4 KB at most, masked, then cut (message 300, file 100, output 300 bytes). */
function pfnb_why() {
	$names = [E_ERROR => 'PHP Fatal error', E_PARSE => 'PHP Parse error', E_CORE_ERROR => 'PHP Core error',
	          E_COMPILE_ERROR => 'PHP Compile error', E_USER_ERROR => 'PHP User error', E_RECOVERABLE_ERROR => 'PHP Recoverable error'];
	$e = error_get_last();
	$last = '';
	if (is_array($e)) {
		$msg = (string)$e['message'];
		$file = (string)$e['file'];
		$last = pfnb_piece(substr($msg, 0, 4096), strlen($msg) > 4096 ? 'head' : '', 'head', 300)
		      . ' in ' . pfnb_piece(substr($file, -1024), strlen($file) > 1024 ? 'tail' : '', 'tail', 100) . ':' . (int)$e['line'];
	}
	if (is_array($e) && isset($names[$e['type']])) { $t = $names[$e['type']] . ': ' . $last; }
	else {
		$cur = ob_get_level() > 0 ? (string)ob_get_contents() : '';
		$n = $GLOBALS['OBN'] + strlen($cur);
		$raw = substr($GLOBALS['OBTAIL'] . substr($cur, -4096), -4096);
		$out = $n > 0 ? pfnb_piece($raw, $n > strlen($raw) ? 'tail' : '', 'tail', 300) : '';
		$t = $out !== '' ? 'exit with output: ' . $out : 'exit without a message';
		if ($last !== '') { $t .= '; last PHP message (type ' . (int)$e['type'] . '): ' . $last; }
	}
	return strlen($t) > 400 ? substr($t, 0, 400) . '...' : $t;   /* every part is masked already */
}

function pfnb_ver($raw) {
	$v = preg_replace('/[_,].*$/', '', trim((string)$raw));
	return preg_match('/^[0-9]+(\.[0-9]+){1,3}$/', $v) ? $v : null;
}

function pfnb_last() {
	$r = ['RESULT' => '', 'TO' => ''];
	$f = @file(PFNB_STATE, FILE_IGNORE_NEW_LINES);
	if (is_array($f)) {
		foreach ($f as $l) {
			$p = explode('=', $l, 2);
			if (count($p) == 2) { $r[$p[0]] = $p[1]; }
		}
	}
	return $r;
}

/* Writes last-result (atomic). */
function pfnb_state($result, $detail) {
	global $FROM, $TO;
	$s = 'TIME=' . date('Y-m-d H:i:s') . "\n" . 'RESULT=' . $result . "\n" . 'DETAIL=' . $detail . "\n"
	   . 'FROM=' . $FROM . "\n" . 'TO=' . $TO . "\n" . 'RUNNER=' . PFNB_RUNNER_VERSION . "\n";
	if (@file_put_contents(PFNB_STATE . '.tmp', $s) !== false) { @rename(PFNB_STATE . '.tmp', PFNB_STATE); }
}

/* Ends the run. $prio: -1 no notice, 0 info, 1 warning, 2 error.
 * $dedup: notice only when RESULT or TO differs from the previous run (conditions that repeat daily).
 * A success notice (prio 0) is local only: no mail / Telegram / Pushover for it. */
function pfnb_finish($result, $detail, $prio, $dedup = false) {
	global $TO, $DONE;
	$DONE = true;
	$detail = str_replace(["\r", "\n"], ' ', $detail);
	$last = pfnb_last();
	pfnb_log('result=' . $result . ' ' . $detail);
	pfnb_state($result, $detail);
	if ($prio >= 0 && !($dedup && $last['RESULT'] === $result && $last['TO'] === $TO)) {
		file_notice('pfnetbird', 'pfnetbird auto-update: ' . $detail, 'pfnetbird', '', $prio, $prio == 0);
	}
	exit(($result === 'updated' || $result === 'uptodate') ? 0 : 1);
}

/* Shutdown: a started run that never reached pfnb_finish crashed or was killed on an error. */
function pfnb_cleanup() {
	global $TMP, $DONE, $STARTED, $SNAP, $ACB_DBG, $STOPPED;
	if ($STARTED && !$DONE) {
		$d = 'the run ended unexpectedly (PHP error); check ' . PFNB_LOG . ($SNAP !== '' && file_exists($SNAP) ? '. Identity snapshot kept: ' . $SNAP : '');
		if ($STOPPED) {   /* do not leave the tunnel down */
			pfnb_log('netbird service restart after the crash: exit ' . pfnb_sh('timeout --foreground 120 netbird service restart </dev/null >/dev/null 2>&1'));
			pfnb_ensure_running();
		}
		pfnb_log('result=failed-crash ' . $d);
		pfnb_state('failed-crash', $d);
		file_notice('pfnetbird', 'pfnetbird auto-update: ' . $d, 'pfnetbird', '', 2);
	}
	if (!$ACB_DBG && file_exists('/tmp/acb_debug.txt')) { @unlink('/tmp/acb_debug.txt'); }
	if ($TMP !== '' && strpos($TMP, '/tmp/pfnetbird-auto.') === 0) {
		pfnb_sh('rm -rf ' . escapeshellarg($TMP));
	}
	/* Last, after the restart, last-result and the notice: finding the cause must not stop those. */
	if ($STARTED && !$DONE) { pfnb_log('crash cause: ' . pfnb_why()); }
	while (ob_get_level() > 0) { ob_end_clean(); }   /* the runner prints nothing itself; a crash text is in the log */
}

function pfnb_asset($j, $re) {
	foreach ((array)($j['assets'] ?? []) as $a) {
		$n = (string)($a['name'] ?? '');
		if (!preg_match($re, $n, $m)) { continue; }
		$u = (string)($a['browser_download_url'] ?? '');
		$d = (string)($a['digest'] ?? '');
		$v = pfnb_ver($m[1]);
		if (!preg_match('/^[A-Za-z0-9._+-]+$/', $n) || strpos($u, PFNB_URL_PREFIX) !== 0 || strpos($u, "'") !== false
		    || !preg_match('/^sha256:([0-9a-fA-F]{64})$/', $d, $dm) || $v === null) {
			return null;
		}
		return ['name' => $n, 'url' => $u, 'sha' => strtolower($dm[1]), 'raw' => $m[1], 'ver' => $v];
	}
	return null;
}

/* ---- 0. Log size, lock, client busy marker, includes, boot, clock ---- */
if (!is_dir(PFNB_DIR)) { exit(1); }
clearstatcache();
if (@filesize(PFNB_LOG) > PFNB_LOG_MAX) { @rename(PFNB_LOG, PFNB_LOG . '.1'); }
$lockfh = @fopen(PFNB_LOCK, 'ce');   /* e: close-on-exec, so children (netbird service) do not inherit the lock */
if ($lockfh === false || !flock($lockfh, LOCK_EX | LOCK_NB)) { pfnb_log('another run holds the lock; exiting'); exit(0); }
register_shutdown_function('pfnb_cleanup');
ob_start('pfnb_ob', 4096);   /* keeps the last bytes pfSense code prints before an exit or die, for the crash log line */
if (file_exists(PFNB_BUSY) && time() - filemtime(PFNB_BUSY) < 3600) { pfnb_log('a pfnetbird change is in progress; exiting'); exit(0); }

require_once('config.inc');
require_once('util.inc');
require_once('notices.inc');
require_once('acb.inc');

if (function_exists('is_platform_booting') && is_platform_booting()) { pfnb_log('system is booting; exiting'); exit(0); }
$STARTED = true;
pfnb_log('start: runner ' . PFNB_RUNNER_VERSION);
pfnb_main();

/* The run is a function, so none of its variables is a PHP global. pfSense code reads globals such as $g
 * (g_get(), lock(), the config paths) and $config. Up to 0.20.1 the run was top-level code and its
 * $g = glob(...) replaced pfSense's $g, so config_read_file() then looked for /config.xml and died. */
function pfnb_main() {
	global $RUN, $TMP, $FROM, $TO, $DONE, $SNAP, $STOPPED;
try {   /* body not re-indented, so the diff to 0.20.1 stays readable */
	if (time() < mktime(0, 0, 0, 1, 1, 2025)) {
		pfnb_finish('failed-clock', 'the system clock is not plausible (' . date('Y-m-d') . '); nothing was changed', 1, true);
	}

	/* ---- 1. NetBird must be installed: auto-update only updates ---- */
	if (pfnb_sh('pkg info -e netbird') != 0) {
		pfnb_finish('skipped-not-installed', 'NetBird is not installed; auto-update only updates. Disable it in pfnetbird (Auto-update > Disable).', 1, true);
	}
	pfnb_sh('pkg query %v netbird', $o);
	$FROM = trim((string)($o[0] ?? ''));
	$inst = pfnb_ver($FROM);
	if ($inst === null) { pfnb_finish('failed-internal', 'cannot read the installed netbird version; nothing was changed', 2, true); }

	/* ---- 2. Box ABI and architecture (as pfnetbird.sh get_box_info) ---- */
	pfnb_sh('pkg config ABI', $o);
	$box_abi = trim((string)($o[0] ?? ''));
	if (!preg_match('/^freebsd:([0-9]+):(.+)$/i', $box_abi, $m)) { pfnb_finish('failed-internal', 'unexpected package ABI of the box; nothing was changed', 2, true); }
	$box_major = (int)$m[1];
	$box_arch = $m[2];
	pfnb_sh('uname -p', $o);
	$u = trim((string)($o[0] ?? ''));
	if ($u === 'amd64') { $arch = 'x86_64'; }
	elseif ($u === 'arm64' || $u === 'aarch64') { $arch = 'aarch64'; }
	else { pfnb_finish('failed-internal', 'unsupported architecture ' . $u . '; nothing was changed', 2, true); }

	/* ---- 3. Latest stable release (fetch, no token) ---- */
	$TMP = '/tmp/pfnetbird-auto.' . $RUN;
	if (!@mkdir($TMP, 0700)) { $TMP = ''; pfnb_finish('failed-internal', 'cannot create the temp directory; nothing was changed', 2, true); }
	$rc = pfnb_sh('fetch -q -T 30 -o ' . escapeshellarg($TMP . '/release.json') . ' ' . escapeshellarg(PFNB_API), $o);
	if ($rc != 0) { pfnb_tail($o, 2); pfnb_finish('failed-lookup', 'the GitHub release lookup failed (fetch exit ' . $rc . '); nothing was changed', 1, true); }
	$j = json_decode((string)@file_get_contents($TMP . '/release.json'), true);
	$tag = is_array($j) ? (string)($j['tag_name'] ?? '') : '';
	if (!preg_match('/^[A-Za-z0-9._-]+$/', $tag) || !empty($j['draft']) || !empty($j['prerelease'])) {
		pfnb_finish('failed-lookup', 'the GitHub response has no usable stable release; nothing was changed', 1, true);
	}
	$cl = pfnb_asset($j, '/^netbird-(.+)-' . $arch . '\.pkg$/');
	$ui = pfnb_asset($j, '/^pfSense-pkg-NetBird-(.+)-' . $arch . '\.pkg$/');
	if ($cl === null || $ui === null) { pfnb_finish('failed-lookup', 'release ' . $tag . ' has no usable package for ' . $arch . '; nothing was changed', 1, true); }
	$TO = $cl['raw'];

	/* ---- 4. Compare: the client version decides, as in pfnetbird.sh ---- */
	if (version_compare($inst, $cl['ver'], '>=')) {
		/* Up to date: a left-over snapshot of an update that did connect is stale. Remove it only when NetBird is connected. */
		$sn = glob(PFNB_DIR . '/identity-*.json');
		if (is_array($sn) && count($sn) > 0) {
			pfnb_sh('timeout 20 netbird status </dev/null', $o);
			if (preg_match('/management:\s*connected/i', implode("\n", (array)$o)) === 1) {
				foreach ($sn as $f) { @unlink($f); }
				pfnb_log('stale identity snapshot removed');
			}
			$o = [];
		}
		foreach ((array)glob(PFNB_DIR . '/paused-*') as $f) { @unlink($f); }
		pfnb_finish('uptodate', 'netbird ' . $FROM . ' is up to date (release ' . $tag . ')', -1);
	}
	pfnb_log('update available: netbird ' . $FROM . ' -> ' . $TO . ' (release ' . $tag . ')');
	/* A failed attempt for this version (or a kept identity snapshot) blocks further runs: no new ACB backup
	 * every night. last-result is left untouched so the block stays; Disable + Enable in pfnetbird clears it. */
	$snaps = glob(PFNB_DIR . '/identity-*.json');
	$lr = pfnb_last();
	if ((is_array($snaps) && count($snaps) > 0)
	    || ($lr['TO'] === $TO && in_array($lr['RESULT'], ['failed-pkg', 'failed-acb', 'failed-snapshot', 'failed-crash', 'failed-internal', 'updated-not-connected'], true))) {
		pfnb_log('skipped: previous failure for ' . $TO . ' (Disable and Enable auto-update in pfnetbird to clear it)');
		$mk = PFNB_DIR . '/paused-' . $TO;   /* one notice per version */
		if (!file_exists($mk)) {
			@touch($mk);
			file_notice('pfnetbird', 'pfnetbird auto-update paused for ' . $TO . ' - run Disable and Enable in pfnetbird to clear', 'pfnetbird', '', 1);
		}
		$DONE = true;
		exit(0);
	}

	/* ---- 5. Download, SHA-256, ABI. Nothing is changed yet ---- */
	$paths = [];
	foreach ([$cl, $ui] as $p) {
		$path = $TMP . '/' . $p['name'];
		$rc = pfnb_sh('fetch -q -T 60 -o ' . escapeshellarg($path) . ' ' . escapeshellarg($p['url']), $o);
		if ($rc != 0) { pfnb_tail($o, 2); pfnb_finish('failed-download', 'download of ' . $p['name'] . ' failed (fetch exit ' . $rc . '); nothing was changed', 2); }
		pfnb_sh('sha256 -q ' . escapeshellarg($path), $o);
		if (strtolower(trim((string)($o[0] ?? ''))) !== $p['sha']) {
			@unlink($path);
			pfnb_finish('failed-checksum', 'SHA-256 mismatch for ' . $p['name'] . '; file deleted; nothing was changed', 2);
		}
		pfnb_sh('pkg query -F ' . escapeshellarg($path) . ' %q', $o);
		$pabi = trim((string)($o[0] ?? ''));
		if (!preg_match('/^freebsd:([0-9]+|\*):(.+)$/i', $pabi, $pm)) { pfnb_finish('failed-download', 'unexpected package ABI in ' . $p['name'] . '; nothing was changed', 2); }
		if ($pm[2] !== '*' && $pm[2] !== $box_arch) {
			pfnb_finish('skipped-abi', $p['name'] . ' is for ' . $pabi . ' but the box is ' . $box_abi . ' (architecture); not updated', 1, true);
		}
		if ($pm[1] !== '*' && (int)$pm[1] > $box_major) {
			pfnb_finish('skipped-abi', $p['name'] . ' is for ' . $pabi . ', newer than the box (' . $box_abi . '); not updated', 1, true);
		}
		pfnb_log('package ABI: ' . $p['name'] . ' is ' . $pabi . ', the box is ' . $box_abi);
		$paths[] = $path;
	}

	/* ---- 6. ACB cloud backup like the GUI "Backup Now", confirmed at Netgate by sha256 ---- */
	if (!function_exists('acb_backup_stage_upload')) {
		pfnb_finish('failed-acb-preflight', 'this pfSense has the legacy ACB, which cannot confirm a backup at Netgate; not updated', 2, true);
	}
	if (config_get_path('system/acb/enable') != 'yes') {
		pfnb_finish('failed-acb-preflight', 'update ' . $FROM . ' -> ' . $TO . ' available, but ACB is disabled; not updated', 2, true);
	}
	if (strlen((string)config_get_path('system/acb/encryption_password')) == 0) {
		pfnb_finish('failed-acb-preflight', 'update ' . $FROM . ' -> ' . $TO . ' available, but ACB has no encryption password; not updated', 2, true);
	}
	$staged = glob(g_get('acbbackuppath') . '*.form');
	$pend = is_array($staged) ? count($staged) : 0;
	unset($staged);
	if (!config_read_file(true, false)) { pfnb_finish('failed-acb', 'cannot re-read config.xml before the ACB backup; not updated', 2); }   /* the in-memory config may be stale */
	touch('/tmp/forceacb');
	$w = write_config('pfnetbird: before auto-update to ' . $TO . ' (run ' . $RUN . ')-MaNuAlBaCkUp');
	if (!is_array($w)) { @unlink('/tmp/forceacb'); pfnb_finish('failed-acb', 'write_config for the ACB backup failed; not updated', 2); }
	unset($w);
	pfnb_sh('sha256 -q /cf/conf/config.xml', $o);
	$sha = strtolower(trim((string)($o[0] ?? '')));
	if (!preg_match('/^[0-9a-f]{64}$/', $sha)) { pfnb_finish('failed-acb', 'cannot hash config.xml; not updated', 2); }
	$form = g_get('acbbackuppath') . $sha . '.form';
	if (!file_exists($form)) { pfnb_finish('failed-acb', 'ACB did not stage the backup; not updated', 2); }
	pfnb_log('ACB: backup staged, uploading');
	pfnb_sh('nice -n20 php /usr/local/sbin/acbupload.php', $o);   /* returns at once if the minute cron holds /tmp/acb.lock */
	for ($i = 0; $i < 30 + 30 * $pend && file_exists($form); $i++) { sleep(3); clearstatcache(); }
	if (file_exists($form)) { pfnb_finish('failed-acb', 'the ACB upload did not finish in time; not updated', 2); }
	$k = get_acb_device_key();
	$rtime = '';
	for ($t = 0; $t < 3 && $rtime === '' && $k !== null; $t++) {
		if ($t > 0) { sleep(10); }
		$b = null;
		foreach ((array)acb_backup_list($k) as $e) {
			if (stripos((string)$e['reason'], '(run ' . $RUN . ')') === false) { continue; }
			if ($b === null || strtotime($e['time']) >= strtotime($b['time'])) { $b = $e; }
		}
		if ($b === null) { continue; }
		$q = acb_backup_get($k, $b['time']);
		$p = explode('++++', (string)$q[0], 2);
		if (strtolower(trim($p[0])) === $sha) {
			$rtime = trim((string)$b['localtime']) !== '' ? (string)$b['localtime'] : (string)$b['time'];
		}
	}
	unset($k, $q, $p, $b);
	if ($rtime === '') { pfnb_finish('failed-acb', 'the ACB backup could not be confirmed at Netgate; not updated', 2); }
	pfnb_log('ACB backup confirmed at Netgate: ' . $rtime . ', sha256 ' . substr($sha, 0, 12));

	/* ---- 7. Snapshot identity and package settings, pkg add, restore, restart, verify.
	 *         pkg add of pfSense-pkg-NetBird runs the OLD package's deinstall (deletes config.json and unsets
	 *         installedpackages/netbird), and the new package's post-install starts NetBird with a NEW identity.
	 *         So: stop, compare the identity by key and restore, restore the settings, then restart. ---- */
	$snap = '';
	if (file_exists(PFNB_IDENTITY)) {
		$snap = PFNB_DIR . '/identity-' . $RUN . '.json';
		if (pfnb_sh('cp -p ' . escapeshellarg(PFNB_IDENTITY) . ' ' . escapeshellarg($snap)) != 0) {
			pfnb_finish('failed-snapshot', 'cannot snapshot the NetBird identity; not updated (ACB backup ' . $rtime . ' was taken)', 2);
		}
		@chmod($snap, 0600);
		$SNAP = $snap;
	}
	$pkgcfg = config_get_path('installedpackages/netbird');
	$step = '';
	if (pfnb_sh('timeout 300 pkg add -f ' . escapeshellarg($paths[0]) . ' </dev/null >' . escapeshellarg($TMP . '/pkg.out') . ' 2>&1') != 0) { $step = 'pkg add netbird'; }
	elseif (pfnb_sh('timeout 300 pkg add -f ' . escapeshellarg($paths[1]) . ' </dev/null >' . escapeshellarg($TMP . '/pkg.out') . ' 2>&1') != 0) { $step = 'pkg add pfSense-pkg-NetBird'; }
	if ($step !== '') { pfnb_tail_file($TMP . '/pkg.out', 5); }
	$STOPPED = true;
	$rrc = pfnb_sh('timeout 60 netbird service stop </dev/null >/dev/null 2>&1');
	pfnb_log('netbird service stop: exit ' . $rrc);
	$extra = '';
	if ($snap !== '') {
		$spk = pfnb_pk($snap);
		if (!file_exists(PFNB_IDENTITY) || ($spk !== null && $spk !== pfnb_pk(PFNB_IDENTITY))) {
			@mkdir('/var/db/netbird', 0700, true);
			if (pfnb_sh('cp -p ' . escapeshellarg($snap) . ' ' . escapeshellarg(PFNB_IDENTITY)) != 0) {
				pfnb_finish('failed-snapshot', 'the NetBird identity could not be restored after the update ' . $FROM . ' -> ' . $TO . '. Identity snapshot kept: ' . $snap . '. ACB backup ' . $rtime . '.', 2);
			}
			@chmod(PFNB_IDENTITY, 0600);
			pfnb_log('identity restored');
			$extra .= ' Identity restored from the snapshot (the package install had replaced it).';
		} else {
			pfnb_log('identity unchanged');
		}
		unset($spk);
	}
	if (is_array($pkgcfg) && !empty($pkgcfg)) {
		$cres = 'unchanged';
		if (config_read_file(true, false)) {
			$cur = config_get_path('installedpackages/netbird');
			if (!is_array($cur) || empty($cur) || $cur != $pkgcfg) {
				config_set_path('installedpackages/netbird', $pkgcfg);
				$w = write_config('pfnetbird: restore NetBird package settings-NoReMoTeBaCkUp');
				$cres = is_array($w) ? 'restored' : 'restore-failed';
				unset($w);
			}
			unset($cur);
		} else {
			$cres = 'reread-failed';
		}
		pfnb_log('package settings ' . $cres);
		if ($cres === 'restored') { $extra .= ' NetBird package settings restored.'; }
		elseif ($cres !== 'unchanged') { $extra .= ' NetBird package settings could NOT be restored (' . $cres . '); check VPN > NetBird.'; }
	}
	unset($pkgcfg);
	/* Restart also after a failed pkg add, so the tunnel comes back with whatever is installed. */
	$rrc = pfnb_sh('timeout --foreground 120 netbird service restart </dev/null >/dev/null 2>&1');
	$STOPPED = false;
	pfnb_log('netbird service restart: exit ' . $rrc);
	pfnb_ensure_running();
	pfnb_sh('pkg query %v netbird', $o);
	$now_cl = trim((string)($o[0] ?? ''));
	if ($now_cl === '') { $now_cl = 'missing'; }
	pfnb_sh('pkg query %v pfSense-pkg-NetBird', $o);
	$now_ui = trim((string)($o[0] ?? ''));
	if ($now_ui === '') { $now_ui = 'missing'; }
	if ($step !== '' || pfnb_sh('pkg info -e netbird') != 0 || pfnb_sh('pkg info -e pfSense-pkg-NetBird') != 0) {
		pfnb_finish('failed-pkg', ($step !== '' ? $step . ' failed' : 'package verification failed') . ' during the update ' . $FROM . ' -> ' . $TO
			. '. Installed now: netbird ' . $now_cl . ', pfSense-pkg-NetBird ' . $now_ui . '. ACB backup ' . $rtime . '.' . $extra
			. ($snap !== '' ? ' Identity snapshot: ' . $snap . '.' : '') . ' Repair with pfnetbird > Install/Update.', 2);
	}
	$up = false;
	for ($i = 0; $i < 20 && !$up; $i++) {
		if ($i > 0) { sleep(3); }
		pfnb_sh('timeout 20 netbird status </dev/null', $o);
		$up = preg_match('/management:\s*connected/i', implode("\n", (array)$o)) === 1;
	}
	$o = [];
	if (!$up) {
		pfnb_finish('updated-not-connected', 'NetBird updated ' . $FROM . ' -> ' . $now_cl . ', but "Management: Connected" was not seen within 60 s; check Status > NetBird.'
			. ($snap !== '' ? ' Identity snapshot kept: ' . $snap . '.' : '') . ' ACB backup ' . $rtime . '.' . $extra, 2);
	}
	if ($snap !== '') { @unlink($snap); $SNAP = ''; }
	pfnb_finish('updated', 'NetBird updated ' . $FROM . ' -> ' . $now_cl . ' (release ' . $tag . '), Management: Connected. ACB backup ' . $rtime . '.' . $extra, 0);
} catch (Throwable $e) {
	pfnb_log('error: ' . pfnb_clean(get_class($e) . ': ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine()));
	pfnb_finish('failed-internal', 'unexpected ' . get_class($e) . '; see ' . PFNB_LOG, 2);
}
}
'@).Replace("`r`n", "`n") + "`n"

function Get-KeyValues {
    # Parses KEY=value lines (first occurrence wins) into a hashtable.
    param([string[]]$Lines)
    $h = @{}
    foreach ($l in $Lines) {
        if ($l -cmatch '\A([A-Z0-9_]+)=(.*)\z' -and -not $h.ContainsKey($Matches[1])) { $h[$Matches[1]] = $Matches[2] }
    }
    return $h
}

function Get-UiSeconds {
    # Twin: bash $SECONDS. Whole seconds since the script started (differences of two readings).
    return [long][Math]::Floor($script:SecClock.Elapsed.TotalSeconds)
}

function Get-AcbPreflight {
    # Twin: acb_preflight. Reads the ACB state of the box (read-only). Stores it in $script:Acb and returns it.
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$AcbPrePhp'" 60 } finally { $script:RemoteQuiet = $false }
    $kv = Get-KeyValues $r.Output
    $acb = [pscustomobject]@{ Code = ''; Ok = $false; Txt = ''; Pending = 0 }
    if ($r.ExitCode -ne 0 -or $kv['ACB_CODE'] -notin @('new', 'legacy') -or $kv['ENABLED'] -notin @('0', '1') -or $kv['PASSWORD_SET'] -notin @('0', '1')) {
        $acb.Txt = 'ACB not available: state could not be read'
        Write-Log 'ACB preflight: state could not be read'
    } else {
        $acb.Code = $kv['ACB_CODE']
        $pend = [string]$kv['PENDING']
        if ($pend -cmatch '\A[0-9]+\z') { $acb.Pending = [int]$pend }
        if (-not $pend) { $pend = '?' }
        Write-Log "ACB preflight: code=$($acb.Code) enabled=$($kv['ENABLED']) password_set=$($kv['PASSWORD_SET']) pending=$pend"
        if ($kv['ENABLED'] -ne '1') { $acb.Txt = 'ACB not available: disabled' }
        elseif ($kv['PASSWORD_SET'] -ne '1') { $acb.Txt = 'ACB not available: no encryption password' }
        else { $acb.Ok = $true; $acb.Txt = 'ACB: enabled, encryption password set' }
    }
    $script:Acb = $acb
    return $acb
}

function Invoke-AcbBackup {
    # Twin: acb_backup. The ACB part of the backup, shown as the Backup step. Returns $true when confirmed.
    param([string]$What, $Acb)
    $script:BkKind = 'ok'; $script:BkDetail = ''
    Start-UiStep 'Backup' 'ACB cloud backup'
    $done = Invoke-AcbBackupRun $What $Acb
    if ($done) { Complete-UiStep $script:BkKind $script:BkDetail } else { Complete-UiStep 'fail' '' }
    return $done
}

function Invoke-AcbBackupRun {
    # Twin: acb_backup_run. Triggers an ACB backup like the GUI "Backup Now" and confirms it.
    # $What = install|update|downgrade|uninstall|manual backup. Returns $true when confirmed. On failure the
    # reason is shown (as a note under the failed step) and $false is returned.
    param([string]$What, $Acb)
    $marker = if ($Acb.Code -eq 'new') { '/cf/conf/lastACBentry.txt' } else { '/cf/conf/lastpfSbackup.txt' }
    $mid = $script:UiU['Mid']
    $failMsg = 'ACB upload FAILED - see Status > System Logs > System (Unable to resolve / An error occurred...)'

    $script:RemoteQuiet = $true
    try {
        $code = $AcbWritePhp.Replace('@WHAT@', $What)
        $r = Invoke-Remote "rm -f $marker; touch /tmp/forceacb; php -r '$code'" 120
    } finally { $script:RemoteQuiet = $false }
    $kv = Get-KeyValues $r.Output
    if ($r.ExitCode -ne 0 -or $kv['WRITE'] -ne '1') {
        $null = Invoke-Remote 'rm -f /tmp/forceacb'
        Write-Fail 'ACB backup: write_config on the firewall failed'
        return $false
    }
    $rev = [string]$kv['REV']

    $r = Invoke-Remote "sha256 -q $ConfigXml"
    $sha = if ($r.Output.Count -gt 0) { $r.Output[0].Trim().ToLowerInvariant() } else { '' }
    if ($r.ExitCode -ne 0 -or $sha -cnotmatch '\A[0-9a-f]{64}\z') {
        Write-Fail 'ACB backup: cannot hash config.xml on the firewall'
        return $false
    }

    $form = "/cf/conf/acb/$sha.form"
    if ($Acb.Code -eq 'new') {
        $r = Invoke-Remote "test -e $form"
        if ($r.ExitCode -ne 0) { Write-Fail 'ACB did not stage the backup'; return $false }
    }

    Write-Log 'ACB: uploading the backup to Netgate...'
    $script:RemoteQuiet = $true
    try {
        # Each pending form can take up to about 85 s, so the limit scales with the preflight count.
        $null = Invoke-Remote '/usr/bin/nice -n20 /usr/local/bin/php /usr/local/sbin/acbupload.php' (150 + 90 * $Acb.Pending)
        # The upload may be locked by cron (/tmp/acb.lock): wait up to about 90 s for it to finish.
        if ($Acb.Code -eq 'new') {
            $r = Invoke-Remote "i=0; while [ -e $form ] && [ `$i -lt 30 ]; do sleep 3; i=`$((i+1)); done; [ ! -e $form ]" 120
        } else {
            $r = Invoke-Remote "i=0; while [ ! -e $marker ] && [ `$i -lt 30 ]; do sleep 3; i=`$((i+1)); done; [ -e $marker ]" 120
        }
    } finally { $script:RemoteQuiet = $false }
    if ($r.ExitCode -ne 0) {
        if ($Acb.Code -eq 'new') { Write-Fail 'ACB upload did not finish within 90 s - see Status > System Logs > System' }
        else { Write-Fail $failMsg }
        return $false
    }

    $r = Invoke-Remote "test -e $marker"
    if ($r.ExitCode -ne 0) { Write-Fail $failMsg; return $false }

    if ($Acb.Code -eq 'legacy') {
        Write-Log "OK: ACB upload reported success (legacy, not verified remotely), sha256 $sha"
        $script:BkKind = 'warn'
        $script:BkDetail = "ACB upload reported success $mid not verified remotely (legacy)"
        return $true
    }

    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$($AcbConfirmPhp.Replace('@SHA@', $sha))'" 120 } finally { $script:RemoteQuiet = $false }
    $kv = Get-KeyValues $r.Output
    $rtime = [string]$kv['TIME']
    if ($r.ExitCode -eq 0 -and $kv['REMOTE_MATCH'] -eq '1' -and $rtime) {
        Write-Log "OK: ACB backup confirmed at Netgate: $rtime, sha256 $sha"
        # On screen only the time of day; the full timestamp and the sha256 are in the log.
        $hhmm = $rtime
        $tm = [regex]::Match($rtime, '(^|[^0-9])([01]?[0-9]|2[0-3]):([0-5][0-9])')
        if ($tm.Success) { $hhmm = ('{0:D2}:{1}' -f [int]$tm.Groups[2].Value, $tm.Groups[3].Value) }
        $script:BkKind = 'ok'
        $script:BkDetail = "ACB confirmed at Netgate $hhmm"
        return $true
    }
    # The remote list failed or did not show this backup: fall back to the upload marker.
    $lst = [string]$kv['LISTED']; if (-not $lst) { $lst = '?' }
    $mat = [string]$kv['REMOTE_MATCH']; if (-not $mat) { $mat = '?' }
    Write-Log "ACB confirm: listed=$lst remote_match=$mat"
    $r = Invoke-Remote "cat $marker"
    $mark = if ($r.Output.Count -gt 0) { $r.Output[0].Trim() } else { '' }
    if ($r.ExitCode -eq 0 -and $rev -and $mark -eq $rev) {
        Write-Log "OK: ACB upload reported success (not verified remotely), sha256 $sha"
        $script:BkKind = 'warn'
        $script:BkDetail = "ACB upload reported success $mid not verified remotely"
        return $true
    }
    Write-Fail $failMsg
    return $false
}

function Stop-ExportFail {
    # Twin: export_fail. Shows the error, drops the temp file and fails the open Backup step (a no-op
    # before the step). The caller returns $false; the backup choice then offers another option.
    param([string]$Message, [string]$TmpFile = '')
    Write-Fail $Message
    if ($TmpFile -and (Test-Path -LiteralPath $TmpFile)) { Remove-Item -LiteralPath $TmpFile -Force -ErrorAction SilentlyContinue }
    Complete-UiStep 'fail' ''
}

function Export-Backup {
    # Twin: export_backup. Native export, identical to the GUI Download button (Diagnostics > Backup &
    # Restore) with the GUI defaults. The only question is whether to encrypt. Saves to Downloads under
    # the GUI file name. Returns $true when the file is saved and verified, $false on any failure
    # (error already shown).
    $enc = Read-YesNo 'Encrypt this configuration file? [y/N]'
    $e = if ($enc) { 1 } else { 0 }
    $b64 = ''
    if ($enc) {
        [Console]::Out.Write($script:UiLead + 'Password: ')
        $s1 = Read-Host -AsSecureString
        if ($script:UiFrame) { Write-UiBlank }
        [Console]::Out.Write($script:UiLead + 'Confirm password: ')
        $s2 = Read-Host -AsSecureString
        if ($script:UiFrame) { Write-UiBlank }
        $pw1 = [System.Net.NetworkCredential]::new('', $s1).Password
        $pw2 = [System.Net.NetworkCredential]::new('', $s2).Password
        $same = ($pw1.Length -gt 0 -and $pw1 -ceq $pw2)
        if ($same) { $b64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::new($false).GetBytes($pw1)) }
        $pw1 = $null; $pw2 = $null; $s1 = $null; $s2 = $null
        if (-not $same) { Stop-ExportFail 'Supplied password and confirmation do not match.'; return $false }
    }

    $code = "`$e=$e; $ExportPhp"
    Start-UiStep 'Backup' 'exporting the configuration'
    $script:RemoteQuiet = $true
    try {
        if ($enc) { $r = Invoke-RemoteSecret "php -r '$code'" $b64 120 }
        else { $r = Invoke-Remote "php -r '$code'" 120 }
    } finally { $script:RemoteQuiet = $false }
    $b64 = $null
    if ($r.ExitCode -ne 0) {
        Write-Log "export: failed on the firewall (exit $($r.ExitCode)); output not logged"
        foreach ($l in $r.Output) { if ($l.StartsWith('ERROR=')) { Write-UiSay 'fail' $l.Substring(6) } }   # screen only, never logged
        Stop-ExportFail 'backup: the export on the firewall failed'
        return $false
    }

    $name = $null; $size = $null; $rsha = $null; $renc = $null; $first = -1
    for ($i = 0; $i -lt $r.Output.Count; $i++) {
        $l = $r.Output[$i]
        if ($l.StartsWith('NAME=')) { $name = $l.Substring(5) }
        elseif ($l.StartsWith('SIZE=')) { $size = $l.Substring(5) }
        elseif ($l.StartsWith('SHA256=')) { $rsha = $l.Substring(7).ToLowerInvariant() }
        elseif ($l.StartsWith('ENCRYPTED=')) { $renc = $l.Substring(10); $first = $i + 1; break }
    }
    if ($first -lt 0 -or $name -cnotmatch '\A[A-Za-z0-9._-]+\z' -or $size -cnotmatch '\A[0-9]+\z' -or $rsha -cnotmatch '\A[0-9a-f]{64}\z' -or $renc -cnotmatch '\A[01]\z') {
        Stop-ExportFail 'backup: unexpected export output from the firewall'; return $false
    }
    if ([int]$renc -ne $e) { Stop-ExportFail 'backup: the encryption setting of the export does not match'; return $false }
    if ($first -ge $r.Output.Count) { Stop-ExportFail 'backup: the export from the firewall is empty'; return $false }
    try {
        $bytes = [Convert]::FromBase64String(($r.Output[$first..($r.Output.Count - 1)] -join ''))
    } catch { Stop-ExportFail 'backup: the data received from the firewall is not valid base64'; return $false }

    $actual = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    if ($actual -ne $rsha) { Stop-ExportFail 'backup: SHA-256 of the received export does not match the firewall'; return $false }
    $text = [System.Text.UTF8Encoding]::new($false).GetString($bytes)
    if ($enc) {
        if (-not ($text.Contains('---- BEGIN config.xml ----') -and $text.Contains('---- END config.xml ----'))) {
            Stop-ExportFail 'backup: the export is not a valid encrypted config.xml'; return $false
        }
    } else {
        $valid = $false
        try { $valid = Test-ConfigRoot $text } catch { $valid = $false }
        if (-not $valid) { Stop-ExportFail 'backup: config.xml is not a valid <pfsense> document'; return $false }
    }

    $dir = Get-DownloadsDir
    try {
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    } catch { Stop-ExportFail "backup: cannot create $dir"; return $false }
    $path = Join-Path $dir $name
    $tmp = "$path.tmp"
    try {
        if (-not $IsWindows) {
            # Owner only (sh gets this from mktemp, which creates the file 0600). pwsh 7.3+ (.NET 7): the file is
            # created with FileStreamOptions.UnixCreateMode = UserRead,UserWrite, so it is never readable by
            # group or others, not even for a moment. pwsh 7.1/7.2: no such option, so the EMPTY file is created,
            # chmod 600, and only then filled (the content is never exposed, but the empty file exists for a
            # moment with the default mode). If chmod fails the backup fails instead of being written with the
            # default 0664.
            # The .NET 7+ types (FileStreamOptions.UnixCreateMode, UnixFileMode) are only named inside the first
            # branch: on pwsh 7.1/7.2 they do not exist and must not be evaluated.
            $fsoType = 'System.IO.FileStreamOptions' -as [type]
            if ($fsoType -and $fsoType.GetProperty('UnixCreateMode')) {
                Remove-Item -LiteralPath $tmp -Force -Recurse:$false -Confirm:$false -ErrorAction SilentlyContinue   # the mode applies to a new file only
                $fso = [System.IO.FileStreamOptions]::new()
                $fso.Mode = [System.IO.FileMode]::CreateNew
                $fso.Access = [System.IO.FileAccess]::Write
                $fso.Share = [System.IO.FileShare]::None
                $fso.UnixCreateMode = [System.IO.UnixFileMode]'UserRead, UserWrite'
                $fs = [System.IO.FileStream]::new($tmp, $fso)
                try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            } else {
                [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None).Dispose()
                & chmod 600 $tmp 2>$null
                if ($LASTEXITCODE -ne 0) { throw 'cannot restrict the backup file to the current user' }
                [System.IO.File]::WriteAllBytes($tmp, $bytes)
            }
        } else {
            # Windows has no Unix modes: the file inherits the ACL of the Downloads folder (normally this user,
            # SYSTEM and Administrators only); the script changes nothing there.
            [System.IO.File]::WriteAllBytes($tmp, $bytes)
        }
        Move-Item -LiteralPath $tmp -Destination $path -Force
    } catch {
        Stop-ExportFail "backup: cannot write $path" $tmp
        return $false
    }
    $script:Ctx.Backup = $path
    $script:BackupSize = $bytes.Length
    $script:BackupSha = $actual
    $script:BackupEnc = if ($enc) { 'yes' } else { 'no' }
    Show-BackupSummary
    Complete-UiStep 'ok' $script:BkDetail
    return $true
}

function Show-BackupSummary {
    # Twin: backup_summary. Four log lines; on screen one short step detail (path, size and sha256 are in the log only).
    Write-Log "OK: Backup saved:  $($script:Ctx.Backup)"
    Write-Log "Backup size:   $($script:BackupSize) bytes"
    Write-Log "Encrypted:     $($script:BackupEnc)"
    Write-Log "Backup sha256: $($script:BackupSha)"
    $dl = ConvertTo-UiSafe (Format-UiHome (Get-DownloadsDir))
    $script:BkDetail = "Local saved to $dl, encrypted $($script:BackupEnc)"
}

function Get-BackupTaken {
    # Twin: bk_taken. The end of the stage texts that name the backup: after Skip no backup exists, so none is claimed.
    if ($script:BackupSkipped) { return 'No backup was taken.' }
    return 'A backup was taken first.'
}

function Get-BackupRestore {
    # Twin: bk_restore.
    if ($script:BackupSkipped) { return 'No backup was taken.' }
    return 'Restore from the backup taken above.'
}

function Invoke-TakeBackup {
    # Twin: take_backup. Backup choice, used for "Backup only" and before install, update, uninstall and
    # auto-update Enable/Change schedule/Disable.
    # $What = install|update|downgrade|uninstall|manual backup (the ACB reason). Returns $true when every chosen
    # part succeeded, $false when the user chose Back (the caller then cancels). A failed part, or ACB
    # not available, shows the choice again. End of input counts as Back. With -AllowSkip (before install,
    # update, reinstall, uninstall and auto-update Enable, Change schedule and Disable) the list has 4) Skip (no backup), which returns $true without a backup.
    param([string]$What, [switch]$AllowSkip)
    $back = if ($AllowSkip) { '5' } else { '4' }
    $script:BackupSkipped = $false
    while ($true) {
        # Same list in and out of a frame, like the other submenus (one line per item).
        Write-Info ''
        Write-Info 'Backup'
        Write-Info ' 1) Local only (Downloads)'
        Write-Info ' 2) ACB cloud only'
        Write-Info ' 3) Both'
        if ($AllowSkip) { Write-Info ' 4) Skip (no backup)' }
        Write-Info " $back) Back"
        $opt = Read-UiPrompt 'Enter an option:'
        if ($null -eq $opt) { $opt = $back; Write-Info '' }
        $opt = ([string]$opt).Trim()
        if ($opt) { Write-Log "menu: backup option $opt selected" }
        if ($opt -eq '') { continue }
        if ($opt -eq $back) { return $false }
        if ($AllowSkip -and $opt -eq '4') {
            Write-Log 'WARNING: Backup skipped: no backup was taken'
            Write-UiStepLine 'warn' 'Backup' 'skipped' 0
            $script:BackupSkipped = $true
            return $true
        }
        if ($opt -notin @('1', '2', '3')) { Write-Info 'Invalid option.'; continue }

        $acbOk = $true; $locOk = $true
        # Both: local first (read-only on the box), then ACB (it does write_config).
        if ($opt -eq '1' -or $opt -eq '3') {
            if (-not (Export-Backup)) { $locOk = $false }
        }
        if ($opt -eq '2' -or $opt -eq '3') {
            if (-not $locOk) {
                Write-Info 'ACB backup skipped: the local part failed.'
            } else {
                $acb = Get-AcbPreflight
                if ($acb.Ok) { Write-Log $acb.Txt } else { Write-Info $acb.Txt }   # an ok state is the Backup step
                if (-not $acb.Ok) {
                    if ($opt -eq '2') { continue }
                    $acbOk = $false
                } else {
                    if (-not (Invoke-AcbBackup $What $acb)) { $acbOk = $false }
                }
            }
            if ($opt -eq '3' -and $locOk -and -not $acbOk) {
                Write-Info "The local backup is saved: $($script:Ctx.Backup)"
                Write-Info 'Choose 2) ACB cloud only to retry the ACB part.'
            }
        }

        if ($acbOk -and $locOk) { return $true }
        if (-not $locOk) { Write-Warn 'Backup failed: local export' }
        if (-not $acbOk) { Write-Warn 'Backup failed: ACB cloud backup' }
        Write-Info 'Choose another option, or Back to cancel.'
    }
}

# ---------------------------------------------------------------------------
# Packages on the box
# ---------------------------------------------------------------------------
function Get-RemotePackage {
    # Twin: get_remote_package. Download, verify SHA-256, check ABI. Returns the remote path. The package
    # ABI values go to the log. Adds its times to $script:DlT / $script:VfT for the Download and Verify lines.
    param($Asset, [string]$BoxAbi, [int]$BoxMajor)
    $remote = "$RemoteDir/$($Asset.Name)"
    $script:Downloaded = $true
    $script:UiSN = 'Download'
    $t0 = Get-UiSeconds
    $null = Invoke-Step "download $($Asset.Name)" "mkdir -p $RemoteDir && fetch -q -o $remote '$($Asset.Url)'" 300
    $script:DlT += (Get-UiSeconds) - $t0

    $script:UiSN = 'Verify'
    $t0 = Get-UiSeconds
    $r = Invoke-Step "checksum $($Asset.Name)" "sha256 -q $remote"
    $got = if ($r.Output.Count -gt 0) { $r.Output[0].Trim().ToLowerInvariant() } else { '' }
    if ($got -ne $Asset.Digest.ToLowerInvariant()) {
        $null = Invoke-Remote "rm -f $remote"
        throw "SHA-256 mismatch for $($Asset.Name): expected $($Asset.Digest), got $got. File deleted."
    }

    $r = Invoke-Step "read package ABI $($Asset.Name)" "pkg query -F $remote '%q'"
    $pkgAbi = if ($r.Output.Count -gt 0) { $r.Output[0].Trim() } else { '' }
    if ($pkgAbi -cnotmatch '\A[Ff]ree[Bb][Ss][Dd]:([0-9]+|\*):(.+)\z') { throw "unexpected package ABI '$pkgAbi' in $($Asset.Name)" }
    $pkgMajor = $Matches[1]
    $pkgArch  = $Matches[2]
    $boxArch  = ($BoxAbi -split ':')[2]
    if ($pkgArch -ne '*' -and $pkgArch -ne $boxArch) {
        throw "package $($Asset.Name) is for $pkgAbi but the box is $BoxAbi (architecture mismatch)"
    }
    Write-Log "package ABI: $($Asset.Name) is $pkgAbi, the box is $BoxAbi"
    if ($pkgMajor -ne '*' -and [int]$pkgMajor -gt $BoxMajor) {
        throw "package $($Asset.Name) is for $pkgAbi, newer than the box ($BoxAbi)"
    }
    $script:VfT += (Get-UiSeconds) - $t0
    return [pscustomobject]@{ Path = $remote }
}

function Invoke-PreparePackages {
    # Twin: prepare_packages. Downloads and verifies both packages (the Download and Verify lines) and
    # builds the question. Returns the two packages and the question text.
    param($Box, $Rel, [string]$Intro)
    $script:DlT = 0; $script:VfT = 0
    $dl = "netbird $($Rel.Client.Version) + pfSense-pkg-NetBird $($Rel.Ui.Version)"
    Start-UiStep 'Download' $dl
    $c = Get-RemotePackage $Rel.Client $Box.Abi $Box.AbiMajor
    $u = Get-RemotePackage $Rel.Ui $Box.Abi $Box.AbiMajor
    $q = $Intro
    $script:UiSN = 'Download'
    Complete-UiStep 'ok' $dl $script:DlT
    Write-UiStepLine 'ok' 'Verify' 'SHA-256 match' ([int]$script:VfT)
    $script:UiTotal += [int]$script:VfT
    return [pscustomobject]@{ Client = $c; Ui = $u; Question = $q }
}

function Install-Packages {
    param($ClientPath, $UiPath)
    $null = Invoke-Step 'install netbird' "pkg add -f $ClientPath" 300
    $null = Invoke-Step 'install pfSense-pkg-NetBird' "pkg add -f $UiPath" 300
}

function Assert-Installed {
    # Verifies the packages and the binary. Returns the netbird version line.
    $null = Invoke-Step 'verify netbird package' 'pkg info -e netbird'
    $null = Invoke-Step 'verify pfSense-pkg-NetBird package' 'pkg info -e pfSense-pkg-NetBird'
    $r = Invoke-Step 'verify netbird version' 'netbird version'
    $last = $r.Output | Select-Object -Last 1
    if ($null -eq $last) { return '' }
    return ([string]$last).Trim()
}

function Save-Identity {
    # Twin: save_identity. Returns the snapshot path ('' when there was nothing to snapshot).
    param([string]$Stamp)
    $snap = "/root/pfnetbird-identity-$Stamp.json"
    $script:IdentDetail = 'snapshot saved on the firewall'
    $r = Invoke-Step 'snapshot NetBird identity' "if [ -f $IdentityFile ]; then cp -p $IdentityFile $snap && echo copied; else echo none; fi"
    $last = $r.Output | Select-Object -Last 1
    if ($null -ne $last -and ([string]$last).Trim() -eq 'copied') {
        $script:Ctx.Identity = $snap
        Write-Log "OK: Identity snapshot: $snap (on the firewall)"
        return $snap
    }
    $script:IdentDetail = 'no identity file to snapshot'
    Write-Log 'No NetBird identity file to snapshot.'
    return ''
}

function Restore-IdentityIfMissing {
    # Twin: restore_identity_if_missing. pkg add of pfSense-pkg-NetBird runs the OLD package's deinstall
    # (deletes config.json), and the new package's post-install starts NetBird with a NEW identity. So:
    # stop NetBird, compare the private key of the snapshot with the current file (never printed) and
    # restore it if it is missing or different. The caller restarts NetBird afterwards.
    param([string]$Snapshot)
    $pat = '"PrivateKey": *"[^"]*"'
    Write-Log 'step: stop NetBird before the identity check'
    $script:RemoteQuiet = $true
    try { $null = Invoke-Remote 'timeout 60 netbird service stop </dev/null >/dev/null 2>&1' 90 } finally { $script:RemoteQuiet = $false }
    if (-not $Snapshot) { return }
    $cmd = 'if [ ! -f @ID@ ] || { [ -n "$(grep -o ''@PAT@'' @SNAP@)" ] && [ "$(grep -o ''@PAT@'' @SNAP@)" != "$(grep -o ''@PAT@'' @ID@)" ]; }; then mkdir -p /var/db/netbird && cp -p @SNAP@ @ID@ && chmod 600 @ID@ && echo restored; else echo unchanged; fi'
    $cmd = $cmd.Replace('@PAT@', $pat).Replace('@SNAP@', $Snapshot).Replace('@ID@', $IdentityFile)
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote $cmd } finally { $script:RemoteQuiet = $false }
    $last = $r.Output | Select-Object -Last 1
    $res = if ($null -ne $last) { ([string]$last).Trim() } else { '' }
    if ($r.ExitCode -ne 0) {
        Write-Warn ("NetBird identity could not be restored " + [char]0x2014 + " snapshot kept at $Snapshot (on the firewall)")
    } elseif ($res -eq 'restored') {
        Write-Warn 'The package install had replaced the NetBird identity; restored it from the snapshot.'
    } else {
        Write-Log 'identity unchanged'
    }
}

function Save-PkgConfig {
    # Twin: save_pkgcfg. NetBird package settings (installedpackages/netbird) are unset by the old
    # package's deinstall. Saved to a root-only file before pkg add, restored after, then deleted.
    param([string]$Stamp)
    $script:PkgCfgFile = ''
    $file = "/root/pfnetbird-pkgcfg-$Stamp.ser"
    $code = $PkgCfgSavePhp.Replace('@FILE@', $file)
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$code'" 60 } finally { $script:RemoteQuiet = $false }
    $kv = Get-KeyValues $r.Output
    if ($r.ExitCode -ne 0 -or [string]$kv['SAVED'] -notmatch '^[01]$') { throw 'cannot save the NetBird package settings before the update' }
    if ($kv['SAVED'] -eq '1') { $script:PkgCfgFile = $file; Write-Log 'NetBird package settings saved' }
}

function Restore-PkgConfig {
    # Twin: restore_pkgcfg.
    if (-not $script:PkgCfgFile) { return }
    $file = $script:PkgCfgFile
    $code = $PkgCfgRestorePhp.Replace('@FILE@', $file)
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$code'" 60 } finally { $script:RemoteQuiet = $false }
    $kv = Get-KeyValues $r.Output
    $res = [string]$kv['RESTORE']
    $shown = if ($res) { $res } else { '?' }
    Write-Log "NetBird package settings: $shown"
    switch ($res) {
        'restored' {
            Write-Warn 'The package install had removed the NetBird package settings; restored them.'
            $null = Invoke-Remote "rm -f $file"
        }
        { $_ -in @('unchanged', 'none') } { $null = Invoke-Remote "rm -f $file" }
        default { Write-Warn "The NetBird package settings could not be restored; they are saved in $file (on the firewall). Check VPN > NetBird." }
    }
}

function Wait-NetBirdConnected {
    # Twin: wait_netbird_connected. Quiet poll (the output of `netbird status` is never logged).
    param([int]$TimeoutSec = 30)
    $start = Get-UiSeconds
    while (((Get-UiSeconds) - $start) -lt $TimeoutSec) {
        $script:RemoteQuiet = $true
        try { $r = Invoke-Remote 'netbird status' } finally { $script:RemoteQuiet = $false }
        if (($r.Output -join "`n") -match '[Mm]anagement:\s*[Cc]onnected') { return $true }
        Wait-UiSleep 3
    }
    return $false
}

function Show-NetBirdStatusDetail {
    # Twin: show_netbird_status_detail. Shows `netbird status -d` on screen only. The output (peer names,
    # IPs, public keys) is never logged. A non-zero exit (for example not logged in yet) is information.
    Write-Log ''
    Write-Log 'netbird status -d:'
    Add-UiAfter ''
    Add-UiAfter 'netbird status -d:'
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote 'netbird status -d' 60 } finally { $script:RemoteQuiet = $false }
    foreach ($l in $r.Output) { Add-UiAfter $l }   # after the frame closes, never logged
    if ($r.ExitCode -ne 0) {
        $m = "netbird status -d exited with code $($r.ExitCode) (for example: not logged in yet). Not an error."
        Write-Log $m
        Add-UiAfter $m
    }
}

# ---------------------------------------------------------------------------
# Auto-update (cron on the firewall)
# ---------------------------------------------------------------------------
# A small PHP runner is deployed to /root/pfnetbird and ONE job is added to pfSense's own cron config
# (install_cron_job). Settings live inside the runner file, never in the cron command, so the command
# never changes and install_cron_job always updates instead of duplicating. Twin: the auto_* functions
# of pfnetbird.sh; the remote commands and the runner are byte-identical.
$script:AuWdays = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
$script:AuRunner = $null

function New-AutoState {
    return [pscustomobject]@{
        Read = $false; Jobs = 0; Min = ''; Hour = ''; Mday = ''; Month = ''; Wday = ''; Exact = $false
        RunnerSha = ''; Tz = ''; Snaps = 0; LastTime = ''; LastResult = ''; LastDetail = ''; LastTo = ''
        HasDir = $false; RState = 'missing'
    }
}
$script:Au = New-AutoState

function Get-AutoRunnerBuild {
    # Twin: auto_runner_build. The runner text, its sha256 and its base64. The bytes hashed are exactly the bytes sent.
    if ($null -eq $script:AuRunner) {
        $text = $AutoRunnerPhp.Replace('@VERSION@', $ScriptVersion)
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $script:AuRunner = [pscustomobject]@{
            Text = $text
            Sha  = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            # sha256 of the runner with the placeholder @VERSION@ left in (twin: RUNNER_TPL_SHA). The box hashes
            # its runner with the version string normalised to the same placeholder.
            TplSha = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.UTF8Encoding]::new($false).GetBytes($AutoRunnerPhp))).ToLowerInvariant()
            B64  = [Convert]::ToBase64String($bytes)
        }
    }
    return $script:AuRunner
}

function Update-AutoRunnerState {
    # Twin: auto_runner_state. Compares the runner on the box (hashed with its version string normalised)
    # with this script's runner template. Sets RState: missing | current | other. The version string is not
    # compared; any other byte difference is "other". Such a runner keeps running unchanged; Change
    # schedule redeploys the current one.
    $a = $script:Au
    $a.RState = 'other'
    if (-not $a.RunnerSha) { $a.RState = 'missing'; return }
    if ($a.RunnerSha -ceq (Get-AutoRunnerBuild).TplSha) { $a.RState = 'current' }
}

function Get-AutoSchedText {
    # Twin: auto_sched_text. daily / weekly / monthly / custom, as text.
    param([string]$Min, [string]$Hour, [string]$Mday, [string]$Month, [string]$Wday)
    if ($Min -match '^[0-9]+$' -and $Hour -match '^[0-9]+$' -and $Month -eq '*') {
        $hhmm = '{0:D2}:{1:D2}' -f [int]$Hour, [int]$Min
        if ($Mday -eq '*' -and $Wday -eq '*') { return "daily $hhmm" }
        if ($Mday -eq '*' -and $Wday -match '^[0-9]+$') { return ('weekly {0} {1}' -f $script:AuWdays[[int]$Wday % 7], $hhmm) }
        if ($Wday -eq '*' -and $Mday -match '^[0-9]+$') { return ('monthly day {0} {1}' -f [int]$Mday, $hhmm) }
    }
    return "custom ($Min $Hour $Mday $Month $Wday)"
}

function Get-AutoPresent {
    # Twin: auto_present. True when anything of auto-update is on the firewall: a job, the runner, or the directory.
    $a = $script:Au
    return ($a.Jobs -gt 0 -or [bool]$a.RunnerSha -or $a.HasDir)
}

function Get-AutoWord {
    # Twin: auto_word. Short state word for the menu: off | <schedule> | unknown.
    $a = $script:Au
    if (-not $a.Read) { return 'unknown' }
    if ($a.Jobs -eq 0) { return 'off' }
    return (Get-AutoSchedText $a.Min $a.Hour $a.Mday $a.Month $a.Wday)
}

function Get-AutoWordShort {
    # Twin: auto_word_short. auto_word with the weekday cut to three letters (Wed) and a custom schedule
    # without the brackets.
    $w = Get-AutoWord
    foreach ($d in $script:AuWdays) { $w = $w.Replace($d, $d.Substring(0, 3)) }
    if ($w.StartsWith('custom (', [System.StringComparison]::Ordinal) -and $w.EndsWith(')', [System.StringComparison]::Ordinal)) {
        $w = 'custom ' + $w.Substring(8, $w.Length - 9)
    }
    return $w
}

function Format-AutoLastRun {
    # Twin: fmt_lastrun. `2026-10-17 03:30:05` -> `10-17 03:30`.
    param([string]$Time)
    if ($Time -cmatch '^[0-9]{4}-([0-9]{2}-[0-9]{2})\s+([0-9]{2}:[0-9]{2})') { return "$($Matches[1]) $($Matches[2])" }
    return (Format-UiShorten (ConvertTo-UiSafe $Time) 16)
}

function Format-AutoLastResult {
    # Twin: fmt_lastres. The coloured word for the last auto-update result.
    param([string]$Result)
    switch -Wildcard -CaseSensitive ($Result) {
        'uptodate'              { return (New-UiColor 'ok' 'ok') }
        'updated'               { return (New-UiColor 'ok' 'updated') }
        'updated-not-connected' { return (New-UiColor 'fail' 'not connected') }
        'skipped-*'             { return (New-UiColor 'warn' 'skipped') }
        'failed-*'              { return (New-UiColor 'fail' 'failed') }
        default                 { return (Format-UiShorten (ConvertTo-UiSafe $Result) 12) }
    }
}

function Get-AutoRow {
    # Twin: auto_row. The Auto-update row of the connected screen, with colour markers. One line.
    #   not read                       (warn) unknown                                yellow
    #   no job, nothing left behind    off                                           plain
    #   no job, files left             (warn) off (mid) files left on firewall       yellow
    #   job, runner missing / differs  <schedule> <tz> (mid) (warn) runner missing / differs  yellow part
    #   job, runner current            <schedule> <tz> (mid) last run MM-DD HH:MM <word>
    #   (warn) and (mid) are the warning glyph and the middle dot (ASCII fallback applies)
    $a = $script:Au
    $mid = $script:UiU['Mid']
    $warn = $script:G['Warn']
    if (-not $a.Read) { return (New-UiColor 'warn' "$warn unknown") }
    Update-AutoRunnerState
    if ($a.Jobs -eq 0) {
        if ($a.RState -eq 'missing' -and -not $a.HasDir) { return 'off' }
        return (New-UiColor 'warn' "$warn off $mid files left on firewall")
    }
    $aw = Get-AutoWordShort
    $az = if ($a.Tz) { " $($a.Tz)" } else { '' }
    switch ($a.RState) {
        'missing' { return "$aw$az $mid $(New-UiColor 'warn' "$warn runner missing")" }
        'other'   { return "$aw$az $mid $(New-UiColor 'warn' "$warn runner differs")" }
    }
    $ar = "$aw$az"
    if ($a.LastTime) {
        $lr = if ($a.LastResult) { $a.LastResult } else { '?' }
        $ar += " $mid last run $(Format-AutoLastRun $a.LastTime) $(Format-AutoLastResult $lr)"
    }
    return $ar
}

function Read-AutoState {
    # Twin: auto_read. Reads the auto-update state of the box (read-only) into $script:Au. A failure sets
    # Read = $false and never throws.
    $a = New-AutoState
    $script:Au = $a
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$AutoReadPhp'" 60 } finally { $script:RemoteQuiet = $false }
    $got = $false
    foreach ($l0 in $r.Output) {
        $l = $l0.TrimEnd("`r")
        $eq = $l.IndexOf('=')
        if ($eq -lt 0) { $k = $l; $v = $l } else { $k = $l.Substring(0, $eq); $v = $l.Substring($eq + 1) }
        $v = [regex]::Replace($v, '\p{Cc}', '')
        switch -CaseSensitive ($k) {
            'MIN'         { $a.Min = $v }
            'HOUR'        { $a.Hour = $v }
            'MDAY'        { $a.Mday = $v }
            'MONTH'       { $a.Month = $v }
            'WDAY'        { $a.Wday = $v }
            'DIR'         { if ($v -eq '1') { $a.HasDir = $true } }
            'EXACT'       { if ($v -eq '1') { $a.Exact = $true } }
            'JOBS'        { if ($v -cmatch '\A[0-9]+\z') { $a.Jobs = [int]$v } }
            'RUNNER_SHA'  { if ($v -cmatch '^[0-9a-f]{64}$') { $a.RunnerSha = $v } }
            'TZ'          { if ($v -cmatch '\A[A-Za-z0-9+-]{1,8}\z') { $a.Tz = $v } }
            'SNAPS'       { if ($v -cmatch '\A[0-9]+\z') { $a.Snaps = [int]$v } }
            'LAST_TIME'   { if ($v -cmatch '\A[0-9: \t\r\n\f\v-]+\z') { $a.LastTime = $v } }
            'LAST_RESULT' { if ($v -cmatch '\A[A-Za-z0-9-]+\z') { $a.LastResult = $v } }
            'LAST_DETAIL' { $a.LastDetail = $v }
            'LAST_TO'     { if ($v -cmatch '\A[A-Za-z0-9._+-]+\z') { $a.LastTo = $v } }
            'READ'        { if ($v -eq '1') { $got = $true } }
        }
    }
    foreach ($f in @('Min', 'Hour', 'Mday', 'Month', 'Wday')) {
        if ($a.$f -cnotmatch '\A[0-9*/,-]*\z') { $a.$f = '?' }
    }
    if ($r.ExitCode -eq 0 -and $got) { $a.Read = $true }
    Update-AutoRunnerState
    Write-Log "auto-update read: ok=$([int]$a.Read) jobs=$($a.Jobs) runner=$($a.RState)"
}

function Invoke-AutoGuard {
    # Twin: auto_guard. Stops the change when an auto-update run is in progress on the firewall, then marks
    # this client busy so the runner skips. The marker is removed by the cleanup job and on disconnect.
    # Marker first, then the lock check: a run that starts in between sees the marker and skips.
    $null = Invoke-Step 'mark pfnetbird busy' "touch $AutoBusy"
    $r = Invoke-Remote "lockf -k -s -t 0 $AutoLock /usr/bin/true" 30
    if ($r.ExitCode -ne 0) {
        $null = Invoke-Remote "rm -f $AutoBusy"
        throw 'an auto-update run is in progress on the firewall; try again in a few minutes. Nothing was changed.'
    }
}

function Read-AutoSchedule {
    # Twin: auto_ask_schedule. Schedule input (Daily / Weekly / Monthly, then HH:MM, default 03:30).
    # Returns $null on Back or end of input, else @{ Min; Hour; Mday; Wday; Text }.
    param([string]$Mode)
    $first = ($Mode -eq 'enable')
    $s = @{ Min = ''; Hour = ''; Mday = '*'; Wday = '*'; Text = '' }
    $kind = ''
    while (-not $kind) {
        if ($first) { $first = $false } else { Write-Info '' }   # Enable: the frame already opened with a blank line
        Write-Info "Schedule (firewall time, $(if ($script:Au.Tz) { $script:Au.Tz } else { '?' }))"
        Write-Info ' 1) Daily'
        Write-Info ' 2) Weekly'
        Write-Info ' 3) Monthly'
        Write-Info ' 4) Back'
        $opt = Read-UiPrompt 'Enter an option:'
        if ($null -eq $opt) { $opt = '4'; Write-Info '' }
        $opt = $opt.Trim()
        if ($opt) { Write-Log "menu: schedule option $opt selected" }
        switch ($opt) {
            ''  { }
            '1' { $kind = 'daily' }
            '2' { $kind = 'weekly' }
            '3' { $kind = 'monthly' }
            '4' { return $null }
            default { Write-Info 'Invalid option.' }
        }
    }
    if ($kind -eq 'weekly') {
        while ($true) {
            Write-Info 'Weekday: 1) Mon 2) Tue 3) Wed 4) Thu 5) Fri 6) Sat 7) Sun'
            $ans = Read-UiPrompt 'Enter a weekday [1-7]:'
            if ($null -eq $ans) { Write-Info ''; return $null }
            $ans = $ans.Trim()
            Write-Log "prompt: weekday -> answer: $(if ($ans) { $ans } else { '(empty)' })"
            if ($ans -cmatch '\A[1-7]\z') { $s.Wday = [string]([int]$ans % 7); break }
            Write-Info 'Invalid weekday.'
        }
    } elseif ($kind -eq 'monthly') {
        while ($true) {
            $ans = Read-UiPrompt 'Day of the month [1-28]:'
            if ($null -eq $ans) { Write-Info ''; return $null }
            $ans = $ans.Trim()
            Write-Log "prompt: day of month -> answer: $(if ($ans) { $ans } else { '(empty)' })"
            if ($ans -cmatch '\A([1-9]|1[0-9]|2[0-8])\z') { $s.Mday = $ans; break }
            Write-Info 'Invalid day (1-28, so that every month has it).'
        }
    }
    while ($true) {
        $ans = Read-UiPrompt "Time HH:MM, 24 h, firewall time [${AutoDefaultTime}]:"
        if ($null -eq $ans) { Write-Info ''; return $null }
        $ans = $ans.Trim()
        Write-Log "prompt: time -> answer: $(if ($ans) { $ans } else { '(empty)' })"
        if (-not $ans) { $ans = $AutoDefaultTime }
        if ($ans -cmatch '\A([01]?[0-9]|2[0-3]):([0-5][0-9])\z') {
            $s.Hour = [string][int]$Matches[1]
            $s.Min = [string][int]$Matches[2]
            break
        }
        Write-Info 'Invalid time. Use HH:MM, for example 03:30.'
    }
    $s.Text = Get-AutoSchedText $s.Min $s.Hour $s.Mday '*' $s.Wday
    return $s
}

function Install-AutoRunner {
    # Twin: auto_deploy_runner. Writes the runner to the firewall (checked by sha256 and php -l before it is used).
    $rb = Get-AutoRunnerBuild
    $null = Invoke-Step 'create /root/pfnetbird' "mkdir -p $AutoDir && chmod 700 $AutoDir"
    $script:RemoteQuiet = $true
    try { $r = Invoke-RemotePayload "php -r '$AutoWritePhp'" $rb.B64 60 } finally { $script:RemoteQuiet = $false }
    $w = ''
    foreach ($l in $r.Output) { if ($l.StartsWith('WRITE=', [System.StringComparison]::Ordinal)) { $w = $l.Substring(6) } }
    if ($r.ExitCode -ne 0 -or $w -ne '1') { throw 'auto-update: writing the runner on the firewall failed' }
    $r = Invoke-Remote "sha256 -q $AutoRunner.tmp"
    $got = if ($r.Output.Count -gt 0) { $r.Output[0].Trim().ToLowerInvariant() } else { '' }
    if ($r.ExitCode -ne 0 -or $got -cne $rb.Sha) {
        $null = Invoke-Remote "rm -f $AutoRunner.tmp"
        throw 'auto-update: the runner on the firewall does not match (sha256); removed'
    }
    $null = Invoke-Step 'syntax check runner' "php -l $AutoRunner.tmp >/dev/null"
    $null = Invoke-Step 'install runner' "mv -f $AutoRunner.tmp $AutoRunner"
    Write-Log "OK: Runner written: $AutoRunner (sha256 $($rb.Sha.Substring(0, 12)))"
}

function Remove-AutoCron {
    # Twin: auto_remove_cron. Removes every pfnetbird cron job. Throws when a job that only mentions the runner path is left.
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$AutoRemovePhp'" 60 } finally { $script:RemoteQuiet = $false }
    $left = ''
    foreach ($l in $r.Output) { if ($l.StartsWith('LEFT=', [System.StringComparison]::Ordinal)) { $left = $l.Substring(5) } }
    if ($r.ExitCode -ne 0 -or $left -notmatch '^[0-9]+$') { throw 'auto-update: removing the cron job failed' }
    if ([int]$left -gt 0) {
        throw "a cron job referencing $AutoRunner was not created by pfnetbird; remove it by hand (Cron package or config)"
    }
}

function Set-AutoCron {
    # Twin: auto_apply_cron. Adds or updates the cron job from the schedule. Removes duplicates or a differing command first.
    param($Sched)
    $a = $script:Au
    if ($a.Jobs -gt 1 -or ($a.Jobs -gt 0 -and -not $a.Exact)) { Remove-AutoCron }
    $code = '$m="' + $Sched.Min + '"; $h="' + $Sched.Hour + '"; $d="' + $Sched.Mday + '"; $w="' + $Sched.Wday + '"; ' + $AutoApplyPhp
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$code'" 60 } finally { $script:RemoteQuiet = $false }
    $applied = ''; $crontab = ''
    foreach ($l in $r.Output) {
        if ($l.StartsWith('APPLIED=', [System.StringComparison]::Ordinal)) { $applied = $l.Substring(8) }
        elseif ($l.StartsWith('CRONTAB=', [System.StringComparison]::Ordinal)) { $crontab = $l.Substring(8) }
    }
    if ($r.ExitCode -ne 0 -or $applied -ne '1' -or $crontab -ne '1') {
        throw 'auto-update: the cron job could not be set (not found in the pfSense config or /etc/crontab afterwards)'
    }
}

function Remove-AutoAll {
    # Twin: auto_remove_all. Removes the cron job and /root/pfnetbird, then checks both are gone.
    Remove-AutoCron
    $null = Invoke-Step 'delete /root/pfnetbird' "rm -rf $AutoDir"
    Read-AutoState
    if (-not $script:Au.Read -or (Get-AutoPresent)) {
        throw 'auto-update: the cron job or /root/pfnetbird is still there after the removal'
    }
}

function Invoke-AutoEnable {
    # Twin: auto_enable_run. Enable (first time) or change the schedule. $Mode = enable | change.
    param([string]$Mode)
    if ($Mode -eq 'change') { Start-UiAction 'Change auto-update schedule' } else { Start-UiAction 'Enable auto-update' }
    Read-AutoState
    if (-not $script:Au.Read) { throw 'auto-update: cannot read the auto-update state on the firewall' }
    if (-not $script:St.State.Installed) {
        throw 'Auto-update only updates an installed NetBird. Install it first.'
    }
    $acb = Get-AcbPreflight
    if (-not $acb.Ok) {
        throw "$($acb.Txt). Auto-update needs ACB enabled with an encryption password (Services > AutoConfigBackup)."
    }
    if ($acb.Code -ne 'new') {
        throw 'This pfSense has the legacy ACB, which cannot confirm a backup at Netgate; auto-update is not available.'
    }

    $s = Read-AutoSchedule $Mode
    if ($null -eq $s) { $script:ActNav = $true; return }
    $tz = if ($script:Au.Tz) { $script:Au.Tz } else { '?' }
    $verb = if ($Mode -eq 'change') { 'Change auto-update to' } else { 'Enable auto-update:' }
    $q = "$verb $($s.Text) (firewall time, $tz). [y/N]"
    if (-not (Read-YesNo $q)) {
        Write-Info 'Cancelled. Nothing was changed.'
        return
    }
    $a = $script:Au
    $same = ($a.Jobs -eq 1 -and $a.Exact -and $a.Min -ceq $s.Min -and $a.Hour -ceq $s.Hour -and $a.Mday -ceq $s.Mday `
        -and $a.Month -ceq '*' -and $a.Wday -ceq $s.Wday)

    Invoke-AutoGuard
    $bkOk = Invoke-TakeBackup "auto-update $Mode" -AllowSkip
    if (-not $bkOk) { $script:ActNav = $true; return }

    Write-UiBlank
    Set-UiStage 'Auto-update may be partly set up. Check it with Status.'
    Start-UiStep 'Runner' 'deploying the runner'
    Install-AutoRunner
    $null = Invoke-Step 'clear last result' "rm -f $AutoDir/last-result $AutoDir/paused-*"   # a previous failure no longer blocks the runner
    $rb = Get-AutoRunnerBuild
    Complete-UiStep 'ok' "written, sha256 $($rb.Sha.Substring(0, 8))"
    Start-UiStep 'Cron job' 'setting the schedule'
    Read-AutoState
    Set-AutoCron $s
    Read-AutoState
    $a = $script:Au
    if (-not $a.Read -or $a.Jobs -ne 1 -or -not $a.Exact -or $a.Min -cne $s.Min -or $a.Hour -cne $s.Hour `
            -or $a.Mday -cne $s.Mday -or $a.Month -cne '*' -or $a.Wday -cne $s.Wday -or $a.RState -ne 'current') {
        throw 'auto-update: the cron job or the runner read back from the firewall does not match what was set'
    }
    $tz = if ($a.Tz) { $a.Tz } else { '?' }
    Complete-UiStep 'ok' "$($s.Text) (firewall time, $tz)"
    if ($Mode -eq 'change') {
        Write-Log "OK: Auto-update schedule changed: $($s.Text) (firewall time, $tz)."
        if ($same) { Write-Info 'The schedule was already set; the runner is current.' }
    } else {
        Write-Log "OK: Auto-update enabled: $($s.Text) (firewall time, $tz)."
    }
    Write-Info 'The firewall checks for a new NetBird release then. Results: the notices bell, and /root/pfnetbird/auto.log on the firewall.'
    Write-Info 'Auto-update always follows the latest stable release.'
    if ($Mode -eq 'change') { Close-UiFrame 'ok' "Auto-update schedule changed in $($script:UiTotal)s." }
    else { Close-UiFrame 'ok' "Auto-update enabled in $($script:UiTotal)s." }
}

function Show-AutoEnableDry {
    # Twin: auto_enable_dry. Mode 'enable' or 'change' (Change schedule); both ask for backup with Skip.
    param([string]$Mode = 'enable')
    $bk = 'Local / ACB / Both / Skip / Back'
    $em = [string][char]0x2014
    if ($Mode -eq 'change') { Write-UiPlan 'Dry run: change auto-update schedule' } else { Write-UiPlan 'Dry run: enable auto-update' }
    Read-AutoState
    $acb = Get-AcbPreflight
    $tz = if ($script:Au.Tz) { $script:Au.Tz } else { '?' }
    Write-Info "DRY RUN $em would do:"
    Write-Info "  1. Check: NetBird installed ($(if ($script:St.State.Installed) { 'yes' } else { 'no' })), $($acb.Txt)."
    Write-Info '     Run is refused when NetBird is not installed, or ACB is disabled, has no encryption password, or is the legacy ACB.'
    Write-Info "  2. Ask the schedule: 1) Daily 2) Weekly (weekday) 3) Monthly (day 1-28), then HH:MM (firewall time, $tz)."
    Write-Info '  3. Ask for confirmation (y/N).'
    Write-Info "  4. Check that no auto-update run is in progress (lockf on $AutoLock) and mark this client busy."
    Write-Info "  5. Ask for backup: $bk."
    Write-Info "  6. Write $AutoRunner (mode 0600; sha256 and php -l checked before it is used) and clear last-result."
    Write-Info "  7. Add or update the pfSense cron job (install_cron_job): $AutoCmd"
    Write-Info '     pfSense writes the config as "Installed cron job for ..." or "Updated cron job for ...".'
    Write-Info '  8. Read the cron job back and check /etc/crontab.'
    Write-Info '  At each scheduled run the firewall would: look up the latest stable release on GitHub; stop if netbird is up to date; skip if an earlier attempt for the same release failed; download both packages, check SHA-256; take an ACB backup and confirm it at Netgate (stop without changes if that fails); snapshot the NetBird identity and package settings; pkg add -f both; stop NetBird, restore the identity and settings if the package install replaced them; netbird service restart; wait 60 s for "Management: Connected"; report in the notices bell and /root/pfnetbird/auto.log.'
    Write-DryJobEnd
}

function Show-AutoStatus {
    # Twin: auto_status_show. Read-only. Shows the cron job, the runner, the last result and the tail of the run log.
    Start-UiAction 'Auto-update status'
    Read-AutoState
    $a = $script:Au
    if (-not $a.Read) { throw 'auto-update: cannot read the auto-update state on the firewall' }
    $tz = if ($a.Tz) { $a.Tz } else { '?' }
    if ($a.Jobs -eq 0) { $cron = 'none' }
    elseif ($a.Jobs -gt 1) { $cron = "$($a.Jobs) jobs found (Change schedule repairs this)" }
    elseif (-not $a.Exact) { $cron = "$(Get-AutoWord), but the command differs (Change schedule repairs this)" }
    else { $cron = "$(Get-AutoWord) (firewall time, $tz)" }
    switch ($a.RState) {
        'missing' { $runner = 'missing (Change schedule redeploys it)' }
        'current' { $runner = 'current' }
        default   { $runner = 'other version (Change schedule redeploys it)' }
    }
    $script:LogMute = $true   # the box output is shown, not logged; one summary line below
    try {
        Write-Info "  Cron job:     $cron"
        Write-Info "  Runner:       $runner"
        Write-Info "  Last run:     $(if ($a.LastTime) { $a.LastTime } else { 'never' })"
        if ($a.LastResult) {
            $last = $a.LastResult
            if ($a.LastDetail) { $last += " - $($a.LastDetail)" }
            Write-Info "  Last result:  $last"
        }
        if ($a.Snaps -gt 0) { Write-Info "  Identity snapshots on the firewall: $($a.Snaps)" }
        if ($a.Snaps -gt 0) {
            Write-Info '  Next runs:    paused while an identity snapshot exists (cleared by Disable and Enable, a successful manual Update, or a later run that finds NetBird connected and up to date; Change schedule does not remove it)'
        } else {
            if ($a.LastResult -cin @('failed-pkg', 'failed-acb', 'failed-snapshot', 'failed-crash', 'failed-internal', 'updated-not-connected')) {
                $to = if ($a.LastTo) { $a.LastTo } else { '?' }
                Write-Info "  Next runs:    paused for release $to (cleared by Change schedule, Disable and Enable, or a successful manual Update)"
            }
        }
        Write-Info "  Log on the firewall: $AutoDir/auto.log (last 10 lines):"
        $r = Invoke-Remote "if [ -f $AutoDir/auto.log ]; then tail -n 10 $AutoDir/auto.log; else echo '(no log yet)'; fi" 30
        foreach ($l in $r.Output) { Write-Info "  $l" }
    } finally { $script:LogMute = $false }
    Write-Log "auto-update status shown: jobs=$($a.Jobs) runner=$($a.RState) last=$(if ($a.LastResult) { $a.LastResult } else { 'none' })"
}

function Invoke-AutoDisable {
    # Twin: auto_disable_run.
    Start-UiAction 'Disable auto-update'
    Read-AutoState
    if (-not $script:Au.Read) { throw 'auto-update: cannot read the auto-update state on the firewall' }
    $extra = ''
    if ($script:Au.Snaps -gt 0) { $extra = ", $($script:Au.Snaps) identity snapshot(s)" }
    if (-not (Read-YesNo "Disable auto-update? The cron job and $AutoDir (runner, log, last result$extra) are removed. [y/N]")) {
        Write-Info 'Cancelled. Nothing was changed.'
        return
    }
    Invoke-AutoGuard
    if (-not (Invoke-TakeBackup 'auto-update disable' -AllowSkip)) { $script:ActNav = $true; return }
    Write-UiBlank
    Set-UiStage 'Auto-update may be partly removed. Check it with Status.'
    Start-UiStep 'Remove' 'removing the cron job and the runner'
    Remove-AutoAll
    Write-Log "OK: Auto-update disabled. The cron job and $AutoDir are removed."
    Complete-UiStep 'ok' 'cron job and runner directory removed'
    Close-UiFrame 'ok' "Auto-update disabled in $($script:UiTotal)s."
}

function Show-AutoDisableDry {
    # Twin: auto_disable_dry.
    $em = [string][char]0x2014
    Write-UiPlan 'Dry run: disable auto-update'
    Read-AutoState
    $snaps = ''
    if ($script:Au.Snaps -gt 0) { $snaps = ", $($script:Au.Snaps) identity snapshot(s)" }
    Write-Info "DRY RUN $em would do:"
    Write-Info '  1. Ask for confirmation (y/N).'
    Write-Info "  2. Check that no auto-update run is in progress (lockf on $AutoLock) and mark this client busy."
    Write-Info '  3. Ask for backup: Local / ACB / Both / Skip / Back.'
    Write-Info "  4. Remove the pfSense cron job (install_cron_job, inactive): pfSense writes `"Removed cron job for $AutoCmd`"."
    Write-Info "  5. Delete $AutoDir (runner, auto.log, last-result$snaps)."
    Write-Info '  6. Check that no cron job is left and the directory is gone.'
    Write-DryJobEnd
}

function Invoke-AutoJob {
    # Twin: auto_job. Menu entry "Auto-update". Off: straight to Enable. On (job or runner found): maintenance menu.
    Read-AutoState
    if (-not $script:Au.Read) { throw 'auto-update: cannot read the auto-update state on the firewall' }
    if (-not (Get-AutoPresent)) {
        switch (Show-ChangeMenu 'Enable auto-update (cron on the firewall)' -Note 'Requires ACB (Services > AutoConfigBackup) with an encryption password.') {
            'run' { Invoke-AutoEnable 'enable' }
            'dry' { Show-AutoEnableDry 'enable' }
            default { $script:ActNav = $true }
        }
        return
    }
    Open-UiFrame 'Auto-update'
    while ($true) {
        Write-Info ''
        Write-Info "Auto-update (cron on the firewall): $(Get-AutoWord)"
        Write-Info ' 1) Status'
        Write-Info ' 2) Change schedule'
        Write-Info ' 3) Disable'
        Write-Info ' 4) Back'
        $opt = Read-UiPrompt 'Enter an option:'
        if ($null -eq $opt) { $opt = '4'; Write-Info '' }
        $opt = $opt.Trim()
        if ($opt) { Write-Log "menu: auto-update option $opt selected" }
        switch ($opt) {
            ''  { }
            '1' { Show-AutoStatus; return }
            '2' {
                switch (Show-ChangeMenu "Change auto-update schedule (now: $(Get-AutoWord))") {
                    'run' { Invoke-AutoEnable 'change' }
                    'dry' { Show-AutoEnableDry 'change' }
                    default { $script:ActNav = $true }
                }
                return
            }
            '3' {
                switch (Show-ChangeMenu 'Disable auto-update') {
                    'run' { Invoke-AutoDisable }
                    'dry' { Show-AutoDisableDry }
                    default { $script:ActNav = $true }
                }
                return
            }
            '4' { $script:ActNav = $true; return }
            default { Write-Info 'Invalid option.' }
        }
    }
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
function Test-UninstallReady {
    # Twin: uninstall_check. Read-only: is wt0 assigned as a pfSense interface, and do rules reference it?
    # The detail (interface name, description) goes to the screen only; the log gets booleans.
    $u = [pscustomobject]@{ Assigned = $false; If = ''; Desc = ''; Fw = 0; Nat = 0; Onat = 0 }
    $script:RemoteQuiet = $true
    try { $r = Invoke-Remote "php -r '$UnCheckPhp'" 60 } finally { $script:RemoteQuiet = $false }
    if ($r.ExitCode -ne 0) { throw 'cannot check whether wt0 is assigned as a pfSense interface (php check failed)' }
    $seen = $false
    foreach ($l0 in $r.Output) {
        $l = $l0.TrimEnd("`r")
        $eq = $l.IndexOf('=')
        if ($eq -lt 0) { $k = $l; $v = $l } else { $k = $l.Substring(0, $eq); $v = $l.Substring($eq + 1) }
        switch ($k) {
            'ASSIGNED' { if ($v -eq '0' -or $v -eq '1') { $u.Assigned = ($v -eq '1'); $seen = $true } }
            'IFNAME'   { $u.If = $v }
            'DESCR'    { $u.Desc = $v }
            'FW'       { if ($v -cmatch '\A[0-9]+\z') { $u.Fw = [int]$v } }
            'NAT'      { if ($v -cmatch '\A[0-9]+\z') { $u.Nat = [int]$v } }
            'ONAT'     { if ($v -cmatch '\A[0-9]+\z') { $u.Onat = [int]$v } }
        }
    }
    if (-not $seen) { throw 'cannot check whether wt0 is assigned as a pfSense interface (no ASSIGNED line)' }
    $u.If = ConvertTo-UiSafe $u.If; $u.Desc = ConvertTo-UiSafe $u.Desc   # remote strings, display only
    Write-Log ("uninstall check: wt0 assigned={0}; firewall rules={1}; nat rules={2}; outbound nat={3}" -f [int]$u.Assigned, [int]($u.Fw -gt 0), [int]($u.Nat -gt 0), [int]($u.Onat -gt 0))
    return $u
}

function Invoke-Uninstall {
    # Twin: do_uninstall. Returns the exit code (0 done or cancelled, 2 blocked or failed).
    param($State)
    $ver = [string]$State.Client
    $gt = $script:UiU['Gt']
    Start-UiAction "Uninstall NetBird $ver"
    Set-UiStage 'NetBird was not changed.'
    Start-UiStep 'Check' 'wt0 interface assignment'
    $un = Test-UninstallReady
    if ($un.Assigned) {
        $ifn = ''; if ($un.If) { $ifn = " ($($un.If.ToUpperInvariant()))" }
        $tab = if ($un.Desc) { $un.Desc } else { $un.If.ToUpperInvariant() }
        Complete-UiStep 'fail' "wt0 is assigned as a pfSense interface$ifn"
        $script:LogMute = $true
        try {
            Write-UiBlank
            Write-Info 'Removing the package now would leave a missing interface, and pfSense can stop at boot with an interface mismatch.'
            Write-Info 'Remove these in the pfSense web UI first, then try again:'
            if ($tab) { Write-Info "  1. Firewall $gt Rules $gt ${tab}: the rules on the NetBird interface" }
            else { Write-Info "  1. Firewall $gt Rules: the rules on the NetBird interface" }
            Write-Info "  2. Interfaces $gt Assignments: the wt0 assignment"
            if ($un.Nat -gt 0) { Write-Info "  (also found: $($un.Nat) NAT rule(s) on that interface, Firewall $gt NAT)" }
            if ($un.Onat -gt 0) { Write-Info "  (also found: $($un.Onat) outbound NAT rule(s) on that interface, Firewall $gt NAT $gt Outbound)" }
            Write-UiBlank
        } finally { $script:LogMute = $false }
        Write-Log 'uninstall stopped: wt0 assigned'
        Close-UiFrame '' 'NetBird was not changed.'
        return 2
    }
    Complete-UiStep 'ok' 'wt0 is not assigned as a pfSense interface'

    # Auto-update is removed together with NetBird (one confirmation, one backup).
    $autoOn = $false; $extra = ''
    Read-AutoState
    if (-not $script:Au.Read) {
        Write-Warn 'cannot read the auto-update state, so it is not known whether auto-update is on.'
        if (-not (Read-YesNo 'Continue the uninstall anyway? A left-over auto-update would only report "NetBird is not installed". [y/N]')) {
            Write-Info 'Cancelled. Nothing was changed.'
            Set-UiStage ''
            return 0
        }
    } elseif (Get-AutoPresent) {
        $autoOn = $true
        Write-Info "Auto-update is on ($(Get-AutoWord)); it is removed too."
        $extra = " The auto-update cron job and $AutoDir are removed too."
    }

    Write-Info 'The NetBird identity on this box is removed; a reinstall needs a new setup key.'
    if (-not (Read-YesNo "Uninstall NetBird ${ver}?$extra [y/N]")) {
        Write-Info 'Cancelled. Nothing was changed.'
        Set-UiStage ''
        return 0
    }

    Invoke-AutoGuard
    if (-not (Invoke-TakeBackup 'uninstall' -AllowSkip)) {
        Write-Info ('Cancelled ' + [char]0x2014 + ' NetBird was not changed')
        Set-UiStage ''
        return 0
    }
    Write-UiBlank

    if ($autoOn) {
        Start-UiStep 'Auto-update' 'removing the cron job and the runner'
        Remove-AutoAll
        Write-Log 'OK: Auto-update removed (cron job and runner directory).'
        Complete-UiStep 'ok' 'cron job and runner directory removed'
        Set-UiStage 'Auto-update was removed; NetBird is still installed.'
    }

    Set-UiStage "NetBird may be stopped or partly removed. $(Get-BackupTaken)"
    Start-UiStep 'Stop' 'netbird service stop'
    Write-Log 'step: stop NetBird'
    $r = Invoke-Remote 'netbird service stop >/dev/null 2>&1' 120
    if ($r.ExitCode -ne 0) {
        Write-Warn "netbird service stop exited with code $($r.ExitCode); continuing (the service may already be stopped)."
    }
    Complete-UiStep 'ok' 'netbird service stop'

    # One call with both names, as NetBird's guide says. pfSense-pkg-NetBird depends on netbird, so pkg
    # removes the GUI package first; its pre-deinstall hook runs while the client still exists.
    Set-UiStage "NetBird may be stopped or partly removed. $(Get-BackupTaken)"
    Start-UiStep 'Remove' 'pkg delete'
    Write-Log 'step: pkg delete'
    $r = Invoke-Remote 'pkg delete -y pfSense-pkg-NetBird netbird' 300
    if ($r.ExitCode -ne 0) {
        Write-Warn "pkg delete exited with code $($r.ExitCode); checking what is left."
    }
    Complete-UiStep 'ok' 'pkg delete pfSense-pkg-NetBird netbird'

    Start-UiStep 'Verify' 'pkg info'
    $left = ''
    $r = Invoke-Remote 'pkg info -e netbird'
    if ($r.ExitCode -eq 0) { $left += ' netbird' }
    $r = Invoke-Remote 'pkg info -e pfSense-pkg-NetBird'
    if ($r.ExitCode -eq 0) { $left += ' pfSense-pkg-NetBird' }
    if ($left) {
        Write-Fail "Uninstall failed. Still installed:$left"
        Complete-UiStep 'fail' ''
        Set-UiStage 'Uninstall failed; NetBird is still partly installed.'
        return 2
    }
    Complete-UiStep 'ok' 'both packages are gone'
    Write-Log 'OK: NetBird uninstalled'
    Write-Info 'The package removes its own pfSense settings (installedpackages/netbird), /var/db/netbird/config.json and its interface-mismatch patch.'
    Write-Info 'You can check in the pfSense UI that no NetBird config is left. This script deletes no config.'
    Write-Info 'The peer is still listed in the NetBird dashboard; remove it there if you want.'
    Close-UiFrame 'ok' "NetBird uninstalled in $($script:UiTotal)s."
    return 0
}

# ---------------------------------------------------------------------------
# Branches
# ---------------------------------------------------------------------------
function Write-StepAfter {
    # Twin: pns_after. One guide line printed after the frame has closed (logged as is, wrapped on screen,
    # hanging under the list marker).
    param([string]$Text)
    Write-Log $Text
    foreach ($l in (Format-UiWrap (ConvertTo-UiGlyph $Text) 'auto' '' '')) { Add-UiAfter $l }
}

function Write-NetBirdSteps {
    param([switch]$After)   # After: print after the frame closes (Show-PostInstallSteps); else inside the frame (dry run)
    $say = { param($t) if ($After) { Write-StepAfter $t } else { Write-Info $t } }
    # Twin: print_netbird_steps. The configuration steps after an install, following NetBird's pfSense guide.
    & $say '  1. VPN > NetBird: enter the Management URL and the setup key, then Save.'
    & $say '       Management URL: https://app.netbird.io:443 (default) or your self-hosted server.'
    & $say '  2. Status > NetBird: verify the connection status (peers and control services).'
    & $say '  3. Interfaces > Assignments (wt0 appears after step 1): under "Available network ports" select wt0, then Add.'
    & $say '  4. Interfaces > OPT<n> (the new interface): check Enable Interface, set Description to NetBird, then Save and Apply Changes.'
    & $say '  5. Firewall > Rules > NetBird tab: Add a rule, Action Pass, Interface NetBird, Protocol Any, Source Any, Destination Any, Description "Allow all on NetBird (managed by NetBird)". Save and Apply Changes.'
    & $say '       NetBird access policies (ACLs) then control what traffic is allowed.'
    & $say '  6. Static port for direct (non-relayed) connections. The guide lists this under "Config for Troubleshooting Relayed Connections"; do it if peers connect through a relay:'
    & $say '       a. Firewall > NAT > Outbound: choose Hybrid Outbound NAT rule generation, then Save.'
    & $say '       b. Add a rule at the top: Interface WAN, Address Family IPv4, Protocol UDP, Source Network = this firewall''s NetBird IP, Destination Any, check Static Port, Description "NetBird Static Port". Save and Apply Changes.'
    & $say '       c. Diagnostics > States: filter by the NetBird IP, then click Kill.'
    & $say '       d. Run `netbird service restart`, then `netbird status -d`.'
    & $say '          Already done by this script after the install; repeat after configuring.'
    & $say 'Guide: https://docs.netbird.io/get-started/install/pfsense'
}

function Show-PostInstallSteps {
    # Twin: show_post_install_steps. Last thing an install prints: after the frame has closed and after
    # `netbird status -d`, just before "Press Enter".
    Write-Log ''
    Write-Log 'NetBird is installed. Remaining steps in the pfSense web UI:'
    Add-UiAfter ''
    Add-UiAfter 'Next in the pfSense web UI:'
    Write-NetBirdSteps -After
}

function Invoke-Install {
    # Twin: do_install. Returns the exit code.
    param($Box, $Rel)
    $mid = $script:UiU['Mid']
    Start-UiAction "Install NetBird $($Rel.Client.Version)"
    Set-UiStage 'NetBird was not changed.'
    $p = Invoke-PreparePackages $Box $Rel "Install NetBird $($Rel.Client.Version)?"
    Write-UiBlank
    if (-not (Read-YesNo "$($p.Question) [y/N]")) { Write-Info 'Cancelled. Nothing was changed.'; Set-UiStage ''; return 0 }

    if (-not (Invoke-TakeBackup 'install' -AllowSkip)) {
        Write-Info ('Cancelled ' + [char]0x2014 + ' NetBird was not changed')
        Set-UiStage ''
        return 0
    }
    Write-UiBlank
    Set-UiStage "NetBird may be partly installed. $(Get-BackupTaken)"
    Start-UiStep 'Install' 'pkg add'
    Install-Packages $p.Client.Path $p.Ui.Path
    $ver = Assert-Installed
    Write-Log "OK: Installed: $ver"
    Complete-UiStep 'ok' "pkg add $mid netbird $ver"
    Set-UiStage 'NetBird is installed, but the restart step failed. Check the firewall.'
    Start-UiStep 'Restart' 'netbird service restart'
    Write-Log 'step: restart NetBird'
    $r = Invoke-Remote 'netbird service restart >/dev/null 2>&1' 120
    if ($r.ExitCode -ne 0) {
        Write-Warn "netbird service restart exited with code $($r.ExitCode); continuing (not configured yet?)."
    }
    Complete-UiStep 'ok' 'netbird service restart'
    Show-NetBirdStatusDetail
    Show-PostInstallSteps
    Close-UiFrame 'ok' "Installed NetBird $($Rel.Client.Version) in $($script:UiTotal)s."
    return 0
}

function Get-UpdateTitle {
    # Twin: update_title. "Reinstall NetBird X" when the installed client already is that version.
    param([string]$Installed, [string]$Target)
    if ((Compare-PkgVersion $Installed $Target) -gt 0) { return 'Downgrade NetBird' }
    if ((Compare-PkgVersion $Installed $Target) -eq 0) { return "Reinstall NetBird $Target" }
    return "Update NetBird $Installed $($script:UiU['Arr']) $Target"
}

function Invoke-Update {
    # Twin: do_update. Returns the exit code (0 done or cancelled, 2 not connected).
    param($Box, $State, $Rel)
    $mid = $script:UiU['Mid']
    $rv = [string]$Rel.Client.Version
    Start-UiAction (Get-UpdateTitle $State.Client $rv)
    Set-UiStage 'NetBird was not changed.'
    $same = ((Compare-PkgVersion ([string]$State.Client) $rv) -eq 0)
    $verb = if (Test-Downgrade $State $Rel) { 'Downgraded' } else { 'Updated' }
    $p = Invoke-PreparePackages $Box $Rel "Update from $($State.Client) to ${rv}?"
    if ($same) { $p.Question = "Reinstall NetBird ${rv}?" }
    # An older release than the installed one: the one confirm question warns about the downgrade.
    if (Test-Downgrade $State $Rel) { $p.Question = "Downgrade NetBird from $($State.Client) to ${rv}?" }
    Write-UiBlank
    if (-not (Read-YesNo "$($p.Question) [y/N]")) { Write-Info 'Cancelled. Nothing was changed.'; Set-UiStage ''; return 0 }

    Invoke-AutoGuard
    # The ACB reason names a downgrade too ("pfnetbird: before downgrade"), by the same compare as the title.
    $bkWhat = if (Test-Downgrade $State $Rel) { 'downgrade' } else { 'update' }
    if (-not (Invoke-TakeBackup $bkWhat -AllowSkip)) {
        Write-Info ('Cancelled ' + [char]0x2014 + ' NetBird was not changed')
        Set-UiStage ''
        return 0
    }
    # Read-only, before anything changes: NeedsLogin means there is no setup key yet, so there is nothing to wait for.
    $script:RemoteQuiet = $true
    try { $pre = Invoke-Remote 'netbird status' } finally { $script:RemoteQuiet = $false }
    $needsLogin = (($pre.Output -join "`n") -cmatch 'NeedsLogin')
    Write-UiBlank
    $stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    Start-UiStep 'Identity' 'snapshot of the NetBird identity and settings'
    $snap = Save-Identity $stamp
    Save-PkgConfig $stamp
    Complete-UiStep 'ok' $script:IdentDetail
    Set-UiStage "NetBird may be partly changed. $(Get-BackupRestore)"
    Start-UiStep 'Install' 'pkg add'
    Install-Packages $p.Client.Path $p.Ui.Path
    Restore-IdentityIfMissing $snap
    Restore-PkgConfig
    Complete-UiStep 'ok' "pkg add $mid identity and settings kept"
    Set-UiStage "$verb, but the restart step failed. Check NetBird on the firewall."
    Start-UiStep 'Restart' 'netbird service restart'
    $null = Invoke-Step 'restart NetBird' 'netbird service restart >/dev/null 2>&1' 120
    $ver = Assert-Installed
    Complete-UiStep 'ok' 'netbird service restart'
    if ($needsLogin) {
        Show-NetBirdStatusDetail
        $word = if ($same) { "Reinstalled NetBird $rv." } else { "$verb to $rv." }
        Write-Log "OK: $word NetBird is not logged in yet (no setup key)."
        if ($snap) {
            Write-Info "$snap (on the firewall) holds the NetBird private identity. Delete it from the firewall once NetBird is verified."
        }
        Close-UiFrame 'ok' "$word NetBird is not logged in yet (no setup key)."
        return 0
    }
    Write-Log "Installed: $ver. Waiting up to 30 s for the management connection..."
    Set-UiStage "$verb, but the connection check did not finish."
    Start-UiStep 'Connect' 'waiting for Management: Connected'
    $up = Wait-NetBirdConnected 30
    if ($up) { Complete-UiStep 'ok' 'Management: Connected' }
    else { Complete-UiStep 'warn' 'Management: Connected was not seen within 30 s' }
    Show-NetBirdStatusDetail
    if ($up) {
        if ($same) { Write-Log "OK: Reinstalled NetBird $rv." }
        else { Write-Log "OK: $verb to $rv. Management: Connected." }
        # A successful manual update clears a failed auto-update attempt (it would otherwise block the runner).
        $null = Invoke-Remote "rm -f $AutoDir/last-result $AutoDir/paused-* $AutoDir/identity-*.json"
        if ($snap) {
            Write-Info "$snap (on the firewall) holds the NetBird private identity. Delete it from the firewall once NetBird is verified."
        }
        if ($same) { Close-UiFrame 'ok' "Reinstalled NetBird $rv in $($script:UiTotal)s." }
        else { Close-UiFrame 'ok' "$verb to $rv in $($script:UiTotal)s. Management: Connected." }
        return 0
    }
    Write-Log "WARNING: $verb, but `"Management: Connected`" was not seen within 30 s. Check ``netbird status`` on the firewall."
    Close-UiFrame 'fail' "$verb to $rv, but not connected."
    return 2
}

# --- Dry run ---------------------------------------------------------------------------------
function Write-DryPackage {
    # Twin: dry_pkg.
    param([string]$Label, $Pkg)
    Write-Info "     $Label"
    Write-Info "       asset:        $($Pkg.Name)"
    Write-Info '       download URL:'
    Write-Info "         $($Pkg.Url)"
    Write-Info '       sha256:'
    Write-Info "         $($Pkg.Digest)"
    Write-Info "       target path:  $RemoteDir/$($Pkg.Name)"
}

function Write-DryBackupLine {
    # Twin: dry_backup_line. Read-only ACB preflight line plus the backup line of every plan.
    $acb = Get-AcbPreflight
    Write-Info $acb.Txt
    Write-Info "DRY RUN $([string][char]0x2014) backup: would ask for backup: Local / ACB / Both / Skip / Back"
    Write-Info ''
}

function Show-DryInstallPlan {
    # Twin: dry_install_plan. Plan for install or update (no uninstall section), nothing is written.
    # When NetBird is already up to date the plan is the reinstall (what the menu Run does).
    param($State, $Rel)
    $em = [string][char]0x2014
    $c = $Rel.Client; $u = $Rel.Ui
    $n = 0
    $stamp = '<yyyyMMdd-HHmmss>'
    Write-Info "DRY RUN $em would do:"
    $n++; Write-Info "  $n. Create $RemoteDir on the firewall and download both packages with fetch:"
    Write-DryPackage 'netbird client' $c
    Write-DryPackage 'pfSense-pkg-NetBird' $u
    $n++; Write-Info "  $n. Verify each downloaded file against the sha256 above; delete it and stop on a mismatch."
    if (Test-Downgrade $State $Rel) {
        $n++; Write-Info "  $n. Downgrade from $($State.Client) to $($Rel.Client.Version): ask for confirmation (y/N), then would ask for backup: Local / ACB / Both / Skip / Back."
    } else {
        $n++; Write-Info "  $n. Ask for confirmation (y/N), then would ask for backup: Local / ACB / Both / Skip / Back."
    }
    if ($State.Installed) {
        $n++; Write-Info "  $n. Snapshot the NetBird identity if present: cp -p $IdentityFile /root/pfnetbird-identity-$stamp.json"
    }
    $n++; Write-Info "  $n. pkg add -f $RemoteDir/$($c.Name)"
    $n++; Write-Info "  $n. pkg add -f $RemoteDir/$($u.Name)"
    if ($State.Installed) {
        $n++; Write-Info "  $n. Restore $IdentityFile from the snapshot if it is missing after the update."
        $n++; Write-Info "  $n. netbird service restart"
    }
    $n++; Write-Info "  $n. Verify: pkg info -e netbird, pkg info -e pfSense-pkg-NetBird, netbird version."
    if (-not $State.Installed) {
        $n++; Write-Info "  $n. netbird service restart (a failed restart is only a warning)."
    }
    if ($State.Installed) {
        $script:RemoteQuiet = $true
        try { $pre = Invoke-Remote 'netbird status' } finally { $script:RemoteQuiet = $false }
        if (($pre.Output -join "`n") -cmatch 'NeedsLogin') {
            $n++; Write-Info "  $n. NetBird is not logged in yet (no setup key): no wait for `"Management: Connected`"."
        } else {
            $n++; Write-Info "  $n. Wait up to 30 s for `"Management: Connected`" in netbird status."
        }
    }
    $n++; Write-Info "  $n. Show netbird status -d on screen only (not logged; a non-zero exit is shown, not treated as failure)."
    $n++; Write-Info "  $n. Remove $RemoteDir from the firewall and close the session."
    if (-not $State.Installed) {
        Write-Info ''
        Write-Info 'After a real install, the remaining steps in the pfSense web UI would be:'
        Write-NetBirdSteps
    }
}

function Show-DryUninstall {
    # Twin: dry_uninstall.
    Write-Info ''
    Write-Info "DRY RUN $([string][char]0x2014) uninstall plan (NetBird is installed):"
    Write-Info '  1. Check whether wt0 is assigned as a pfSense interface (read-only, result below).'
    $un = Test-UninstallReady
    $script:LogMute = $true
    try {
        if ($un.Assigned) {
            $d = if ($un.Desc) { $un.Desc } else { 'none' }
            Write-Info "  wt0 is assigned as pfSense interface '$($un.If)' (description: $d)"
            Write-Info "  firewall rules on it: $($un.Fw), NAT rules: $($un.Nat), outbound NAT rules: $($un.Onat)"
        } else {
            Write-Info '  wt0 is not assigned as a pfSense interface.'
        }
    } finally { $script:LogMute = $false }
    if ($un.Assigned) {
        Write-Info '  The uninstall would STOP here: remove the rules and the wt0 assignment in the pfSense UI first.'
        return
    }
    Write-Info '  2. Ask for confirmation (y/N).'
    Write-Info '  3. would ask for backup: Local / ACB / Both / Skip / Back'
    Read-AutoState
    if (-not $script:Au.Read) {
        Write-Info '  3a. auto-update state unreadable (cannot tell whether it is on)'
    } elseif (Get-AutoPresent) {
        Write-Info "  3a. would remove auto-update: the cron job (Removed cron job for $AutoCmd) and $AutoDir"
    }
    Write-Info '  4. would stop: netbird service stop (a non-zero exit is only a warning)'
    Write-Info '  5. would pkg delete: pkg delete -y pfSense-pkg-NetBird netbird'
    Write-Info '  6. would verify: pkg info -e netbird and pkg info -e pfSense-pkg-NetBird must both report not installed'
}

# ---------------------------------------------------------------------------
# State and flow shared by the menu actions
# ---------------------------------------------------------------------------
function Show-CtxPaths {
    if ($script:Ctx.Backup)   { Write-Info "Config backup (local): $($script:Ctx.Backup)" }
    if ($script:Ctx.Identity) { Write-Info "Identity snapshot (on the firewall): $($script:Ctx.Identity)" }
}

function Write-RateLimitFail {
    Write-FailW 'GitHub rate limit reached for your IP (60 requests per hour). Wait up to an hour, or set GITHUB_TOKEN.'
}

function Read-FirewallState {
    # Reads box, NetBird and release. Each stage is stored as soon as it is known, so a
    # later failure (for example GitHub being down) still leaves the earlier stages.
    $script:St = [pscustomobject]@{ Stage = 0; Box = $null; State = $null; Rel = $null }
    $script:Au = New-AutoState
    $script:St.Box = Get-BoxInfo
    $script:St.Stage = 1
    $script:St.State = Get-NetBirdState
    Read-AutoState
    $script:St.Stage = 2
    $script:RelLimited = $false
    try {
        $script:St.Rel = Get-LatestRelease $script:St.Box.Arch
        $script:St.Stage = 3
    } catch {
        if (-not $_.Exception.Data['pfnbRateLimit']) { throw }
        # Rate limit: one wrapped line, then the connected screen with Latest unknown.
        $script:RelLimited = $true
        Write-RateLimitFail
    }
}

function Connect-Flow {
    # Asks for the firewall and the user (or takes them from -Host, once), validates, warns about the
    # NetBird range, logs in. Returns $true when connected, $false when the user cancelled. Errors throw.
    $hostName = ''
    $userName = ''
    if ($script:HostArg) {
        $hostName = $script:HostArg
        $userName = $script:HostUser
        $script:HostArg = ''; $script:HostUser = ''     # used once
    }
    while (-not $hostName) {
        # One question, [user@]host, checked by the same Test-HostArg as -Host; invalid input shows the
        # same error and asks again. End of input is an error (exit 2), as before.
        $ans = Read-UiPrompt 'Firewall (user@host):'
        if ($null -eq $ans) { throw 'invalid firewall IP or host name' }
        $script:HostArg = ([string]$ans).Trim(); $script:HostUser = ''
        try { Test-HostArg } catch { Write-Fail $_.Exception.Message; $script:HostArg = ''; $script:HostUser = ''; continue }
        $hostName = $script:HostArg
        $userName = $script:HostUser
        $script:HostArg = ''; $script:HostUser = ''
    }
    if (-not (Test-HostName $hostName)) { throw 'invalid firewall IP or host name' }
    while (-not $userName) {
        # Same as the Firewall prompt: invalid or empty input shows the error and asks again; end of
        # input is an error (exit 2), so the loop can never run forever.
        $ans = Read-UiPrompt 'Username:'
        if ($null -eq $ans) { throw 'invalid user name' }
        $ans = ([string]$ans).Trim()
        if (-not (Test-UserName $ans)) { Write-Fail 'invalid user name'; continue }
        $userName = $ans
    }
    if (-not (Test-UserName $userName)) { throw 'invalid user name' }

    if (Test-NetBirdRange $hostName) {
        Write-WarnW "$hostName is in the NetBird range (100.64.0.0/10). An update or uninstall stops NetBird and could cut this session. Use the LAN address if you can."
        if (-not (Read-YesNo 'Continue over the NetBird address? [y/N]')) { Write-Info 'Cancelled.'; return $false }
    }

    if ($script:KeyGiven) {
        Write-Info "Logging in with key $($script:KeyName) (no password fallback). The script never sees a passphrase."
    } else {
        Write-InfoW 'Logging in like ssh: a key from your SSH agent (e.g. 1Password) or ~/.ssh is used if the firewall accepts it; approve it if 1Password asks. Otherwise ssh asks for the password below. The script never sees either.'
    }
    Connect-Remote $hostName $userName
    $script:LogDay = [DateTime]::Now.ToString('yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture)
    Open-Log $hostName
    Write-Log "login OK: $userName@$hostName"
    if ($script:KeyGiven) { Write-Log "auth=key key=$($script:KeyName)" } else { Write-Log 'auth=ssh' }
    $script:ConnHost = $hostName
    $script:ConnUser = $userName
    return $true
}

# ---------------------------------------------------------------------------
# Menu mode
# ---------------------------------------------------------------------------
function Show-StartScreen {
    # Twin: start_screen.
    $dl = Format-UiHome (Get-DownloadsDir)
    $dl = ConvertTo-UiSafe $dl
    $dl = Format-UiShorten $dl ($script:UiW - $script:UiPfx.Length - $script:UiKvw)
    Open-UiFrame "pfnetbird $ScriptVersion $($script:UiU['H'])$($script:UiU['H'])$($script:UiU['H']) maintain NetBird on pfSense, the community way"
    Write-UiBlank
    Write-UiKv 'Connection' 'not connected'
    if ($script:KeyGiven) { Write-UiKv 'Auth' "key $($script:KeyName) only" } else { Write-UiKv 'Auth' $script:UiAuthRow }
    Write-UiKv 'Backups' $dl
    Write-UiKv 'Logging' (Get-LogStateWord)
    Write-UiSection 'Menu'
    Write-UiMenu2 @('1) Connect to firewall', "2) Logging: $(Get-LogStateWord) (toggle)", '0) Exit')
    Close-UiFrame
}

function Show-SessionScreen {
    # Twin: session_screen.
    $st = $script:St
    $box = $st.Box
    $ed = if ($box -and $box.Edition -ne 'unknown') { "pfSense $($box.Edition)" } else { 'pfSense' }
    $arrow = $script:UiU['Arr']
    $mid = $script:UiU['Mid']

    # The old text forms are kept: the one logged summary line below is built from them.
    $nbtxt = 'unknown'
    if ($st.Stage -ge 2) {
        if ($st.State.Installed) {
            $pk = if ($st.State.Package) { $st.State.Package } else { 'not installed' }
            $nbtxt = "$($st.State.Client) (pfSense-pkg-NetBird $pk)"
        } else { $nbtxt = 'not installed' }
    }
    if ($st.Stage -ge 3) {
        $rel = $st.Rel
        $reltxt = "$($rel.Tag) (netbird $($rel.Client.Version), pfSense-pkg-NetBird $($rel.Ui.Version))"
        if (-not $st.State.Installed) {
            $status = 'not installed'; $item1 = "Install NetBird $($rel.Client.Version)"
        } else {
            if ((Compare-PkgVersion ([string]$st.State.Client) ([string]$rel.Client.Version)) -ge 0) { $status = 'up to date' }
            else { $status = "update available ($($st.State.Client) -> $($rel.Client.Version))" }
            if ((Compare-PkgVersion ([string]$st.State.Client) ([string]$rel.Client.Version)) -eq 0) { $item1 = "Reinstall NetBird $($rel.Client.Version)" }
            else { $item1 = "Update NetBird $arrow $($rel.Client.Version)" }
        }
    } else {
        $reltxt = 'unknown (lookup failed)'; $status = 'unknown'; $item1 = 'Install or update NetBird'
    }

    # --- display forms ---
    # Title right part: user@host (fqdn); the (fqdn) is dropped when it does not fit.
    $uh = ConvertTo-UiSafe "$($script:ConnUser)@$($script:ConnHost)"
    $titleR = $uh
    $fqdn = if ($box) { [string]$box.Fqdn } else { '' }
    if ($fqdn -and $fqdn -cne $script:ConnHost) {
        if ($ScriptVersion.Length + 11 + $uh.Length + $fqdn.Length + 3 -le $script:UiW - 8) {
            $titleR = "$uh ($(ConvertTo-UiSafe $fqdn))"
        }
    }
    # Subtitle: edition and version (-RELEASE dropped), FreeBSD major, package ABI, auth.
    $ver = if ($box) { ConvertTo-UiSafe ([string]$box.Version).Replace('-RELEASE', '') } else { '' }
    $sub = $ed
    if ($ver) { $sub += " $ver" }
    if ($box) { $sub += " $mid FreeBSD $($box.AbiMajor)" }
    if ($box -and $box.Abi) { $sub += " $mid $(ConvertTo-UiSafe ([string]$box.Abi))" }
    $sub = ConvertTo-UiGlyph $sub
    if ($script:KeyGiven) {
        # The key name gives way first, so the box facts stay whole.
        $kn = Format-UiShorten $script:KeyName ($script:UiW - $script:UiPfx.Length - $sub.Length - 3 - 9)
        $authSub = ConvertTo-UiGlyph " $mid auth key $kn"
    } else {
        $authSub = ConvertTo-UiGlyph " $mid $($script:UiAuthSub)"
    }
    if ($sub.Length + $authSub.Length -le $script:UiW - $script:UiPfx.Length) { $sub += $authSub }   # else drop auth before cutting
    $sub = Format-UiShorten $sub ($script:UiW - $script:UiPfx.Length)

    # NetBird section.
    if ($st.Stage -ge 2) {
        if ($st.State.Installed) {
            $nbv = (ConvertTo-UiSafe ([string]$st.State.Client)) + '   pfSense-pkg-NetBird ' + (ConvertTo-UiSafe $(if ($st.State.Package) { [string]$st.State.Package } else { 'not installed' }))
        } else { $nbv = [string]$script:UiU['Em'] }
    } else { $nbv = 'unknown' }
    if ($st.Stage -ge 3) {
        $relv = ConvertTo-UiSafe ([string]$rel.Client.Version)
        $relp = ConvertTo-UiSafe ([string]$rel.Ui.Version)
        $relt = ConvertTo-UiSafe ([string]$rel.Tag)
        $latestv = "$relv   pfSense-pkg-NetBird $relp   release $relt"
        $dot = $script:G['Dot']
        switch ($status) {
            'not installed' { $statv = New-UiColor 'warn' "$dot not installed" }
            'up to date'    { $statv = New-UiColor 'ok' "$dot up to date" }
            default         { $statv = New-UiColor 'warn' "$dot update available" }
        }
    } else {
        $latestv = if ($script:RelLimited) { 'unknown' } else { [string]$script:UiU['Em'] }
        if ($st.Stage -ge 2) { $statv = New-UiColor 'warn' "$($script:G['Warn']) lookup failed" }
        else { $statv = New-UiColor 'warn' "$($script:G['Warn']) unknown" }
    }

    # Menu: 1 Check; 2 Backup only; 3 Install / Update / Reinstall; then Uninstall only when NetBird is
    # installed; Auto-update when NetBird is installed or a job or runner is left over; Logging is the last
    # item before 0 Disconnect.
    $items = @('1) Check (refresh status)', '2) Backup only', "3) $item1")
    $n = 4
    $script:MenuUn = 'none'; $script:MenuAu = 'none'
    if ($st.Stage -ge 2 -and $st.State.Installed) {
        $script:MenuUn = [string]$n; $items += "$n) Uninstall NetBird"; $n++
    }
    if ($st.Stage -ge 2 -and ($st.State.Installed -or (Get-AutoPresent))) {
        $script:MenuAu = [string]$n; $items += "$n) Auto-update: $(Get-AutoWordShort)"; $n++
    }
    $script:MenuLog = $n
    $items += "$n) Logging: $(Get-LogMenuWord)"

    # The screen itself is not copied to the log line by line; one summary line is.
    $script:LogMute = $true
    try {
        Open-UiFrame "pfnetbird $ScriptVersion" $titleR
        Write-UiBlank
        Write-UiLine ($script:UiPfx + $sub)
        Write-UiSection 'NetBird'
        Write-UiKv 'Installed' $nbv
        Write-UiKv 'Latest' $latestv
        Write-UiKv 'Status' $statv
        Write-UiSection 'Safety'
        Write-UiKv 'Auto-update' (Get-AutoRow)
        Write-UiSection 'Menu'
        Write-UiMenu1 ($items + '0) Disconnect SSH')
        Close-UiFrame
    } finally {
        $script:LogMute = $false
    }
    Write-Log "screen: NetBird=$nbtxt; latest=$reltxt; status=$status; auto=$(Get-AutoWord)"
}

function Invoke-Action {
    # Runs one menu action (twin: run_action + run_job). Returns 'ok', 'nav' (the action ended with
    # Back: no "Press Enter"), 'error' (still connected) or 'lost' (session torn down).
    param([scriptblock]$Body)
    $script:Ctx.Backup = $null
    $script:Ctx.Identity = $null
    # Clean UI state, as sh's action subshell starts with.
    $script:UiFrame = $false; $script:UiStep = $false; $script:UiLead = ''; $script:UiFailT = ''; $script:UiTotal = 0
    $script:UiAfter.Clear(); $script:UiNoteK.Clear(); $script:UiNoteT.Clear()
    $script:ActNav = $false
    $lost = $false
    $failed = $false
    try {
        $null = & $Body
    } catch {
        $ex = $_.Exception
        $failed = $true
        Stop-UiStep
        Write-Fail (Get-ErrorMessage $ex)
        Show-CtxPaths
        Exit-UiFrame
        if (Test-SessionLost $ex -IncludeTimeout) { $lost = $true }
    }
    Exit-UiFrame
    if (-not $lost -and $null -ne $script:Session -and $script:Session.Proc.HasExited) {
        Write-Fail 'the ssh session has ended'
        $failed = $true
        $lost = $true
    }
    if ($lost) {
        Disconnect-Remote 'Connection lost.'
        return 'lost'
    }
    if ($failed) { return 'error' }
    if ($script:ActNav) { return 'nav' }
    return 'ok'
}

function Read-Option {
    $o = Read-UiPrompt 'Enter an option:'
    if ($null -eq $o) { Write-Info ''; return $null }
    return $o.Trim()
}

function Invoke-SessionLoop {
    # Connected screen (twin: session_loop). Returns the exit code: 0 when disconnected, 2 when the
    # session was lost.
    $needRefresh = $true
    $first = $true
    while ($true) {
        if ($needRefresh) {
            $needRefresh = $false
            $res = Invoke-Action { Read-FirewallState }
            if ($res -eq 'lost') { return 2 }
            if ($res -ne 'ok' -or $script:RelLimited) { Wait-UiEnter }
        }
        # The first screen of a session is not cleared, so "Login OK" stays visible above it.
        if ($first) { $first = $false } else { Clear-UiScreen }
        Show-SessionScreen
        $redraw = $false
        while (-not $redraw) {
            $opt = Read-Option
            if ($null -eq $opt) { $opt = '0' }
            if ($opt -eq '') { continue }
            Write-Log "menu: option $opt selected"
            if ($opt -eq '0') {
                Disconnect-Remote 'Disconnected.'
                return 0
            } elseif ($opt -eq [string]$script:MenuLog) {
                if ($script:LogOn -and $script:LogFile) {
                    Write-Log 'logging disabled'
                    $script:LogOn = $false
                    Write-UiSay 'ok' 'Logging is off.'
                    Write-Log 'Logging is off.'
                } else {
                    # Off, or on without a log file (cannot write): switch on and try to open the log again.
                    $script:LogOn = $true
                    if (-not $script:LogFile) { Open-Log $script:ConnHost -Retry }
                    if ($script:LogFile) {
                        Write-Log 'logging enabled'
                        Write-UiSay 'ok' 'Logging is on.'
                        Write-Log 'Logging is on.'
                    } else {
                        Write-UiSay 'fail' "Logging could not start ($($script:LogWhy))"   # no log is open, so nothing is logged
                    }
                }
                Wait-UiEnter
                $redraw = $true
            } elseif ($opt -eq '1') {
                Write-Info 'Reading the firewall and the latest NetBird release...'
                $needRefresh = $true; $redraw = $true
            } elseif ($opt -eq '2') {
                $res = Invoke-Action { Invoke-BackupJob }
                if ($res -eq 'lost') { return 2 }
                if ($res -ne 'nav') { Wait-UiEnter }
                Write-Info ''
                $needRefresh = $true; $redraw = $true
            } elseif ($opt -eq '3') {
                if ($script:St.Stage -lt 3) {
                    Write-Fail 'the release information is not available; use option 1 to try again'
                    continue
                }
                $script:Downloaded = $true
                $res = Invoke-Action { Invoke-InstallJob }
                if ($res -eq 'lost') { return 2 }
                if ((Invoke-Action { $null = Invoke-Remote "rm -rf $RemoteDir; rm -f $AutoBusy" }) -eq 'lost') { return 2 }
                $script:Downloaded = $false
                if ($res -ne 'nav') { Wait-UiEnter }
                Write-Info ''
                $needRefresh = $true; $redraw = $true
            } elseif ($opt -eq $script:MenuUn) {
                if ($script:MenuUn -eq 'none') { Write-Info 'Invalid option.'; continue }
                $res = Invoke-Action { Invoke-UninstallJob }
                if ($res -eq 'lost') { return 2 }
                if ((Invoke-Action { $null = Invoke-Remote "rm -rf $RemoteDir; rm -f $AutoBusy" }) -eq 'lost') { return 2 }
                if ($res -ne 'nav') { Wait-UiEnter }
                Write-Info ''
                $needRefresh = $true; $redraw = $true
            } elseif ($opt -eq $script:MenuAu) {
                if ($script:MenuAu -eq 'none') { Write-Info 'Invalid option.'; continue }
                $res = Invoke-Action { Invoke-AutoJob }
                if ($res -eq 'lost') { return 2 }
                if ((Invoke-Action { $null = Invoke-Remote "rm -rf $RemoteDir; rm -f $AutoBusy" }) -eq 'lost') { return 2 }
                if ($res -ne 'nav') { Wait-UiEnter }
                Write-Info ''
                $needRefresh = $true; $redraw = $true
            } else {
                Write-Info 'Invalid option.'
            }
        }
    }
}

function Show-ChangeMenu {
    # Twin: change_menu. Run / Dry run / Back, or with -Older Run / Dry run / Older release / Back.
    # Returns 'run', 'dry', 'older' or 'back' (end of input = back). -Note: a line printed right after the header.
    param([string]$Header, [switch]$Older, [string]$Note)
    $back = if ($Older) { '4' } else { '3' }
    while ($true) {
        Write-Info ''
        Write-Info $Header
        if ($Note) { Write-Info " $Note" }
        Write-Info ' 1) Run'
        Write-Info ' 2) Dry run (plan only)'
        if ($Older) { Write-Info ' 3) Older release' }
        Write-Info " $back) Back"
        $opt = Read-UiPrompt 'Enter an option:'
        if ($null -eq $opt) { $opt = $back; Write-Info '' }
        $opt = $opt.Trim()
        if ($opt) { Write-Log "menu: change option $opt selected" }
        switch ($opt) {
            ''  { }
            '1' { return 'run' }
            '2' { return 'dry' }
            '3' { if ($Older) { return 'older' }; return 'back' }
            '4' { if ($Older) { return 'back' }; Write-Info 'Invalid option.' }
            default { Write-Info 'Invalid option.' }
        }
    }
}

function Invoke-BackupJob {
    # Twin: backup_job. Menu item 2.
    Open-UiFrame 'Backup'
    if (-not (Invoke-TakeBackup 'manual backup')) { $script:ActNav = $true; return }
    Close-UiFrame 'ok' "Backup done in $($script:UiTotal)s."
}

function Write-DryJobEnd {
    Close-UiFrame '' 'Dry run: nothing was changed.'
}

function Invoke-InstallRelease {
    # Header, Run / Dry run / Back for one release (the latest, or an older one). -Older adds the
    # Older release item. Returns 'older' or 'back' when the user chose those, otherwise 'done'.
    param($Rel, [switch]$Older)
    $st = $script:St
    if ($st.State.Installed) { $hdr = Get-UpdateTitle ([string]$st.State.Client) ([string]$Rel.Client.Version) }
    else { $hdr = "Install NetBird $($Rel.Client.Version)" }
    $choice = if ($Older) { Show-ChangeMenu $hdr -Older } else { Show-ChangeMenu $hdr }
    switch ($choice) {
        'run' {
            if ($st.State.Installed) { $null = Invoke-Update $st.Box $st.State $Rel }
            else { $null = Invoke-Install $st.Box $Rel }
            return 'done'
        }
        'dry' {
            # Twin: dry_install_job.
            if ($st.State.Installed -and (Test-Downgrade $st.State $Rel)) { Write-UiPlan 'Dry run: downgrade NetBird' }
            else { Write-UiPlan "$hdr (dry run)" }
            Write-DryBackupLine
            Show-DryInstallPlan $st.State $Rel
            Write-DryJobEnd
            return 'done'
        }
        default { return $choice }
    }
}

function Invoke-InstallJob {
    # Twin: install_job. Menu item 3: header, Run / Dry run / Older release / Back, then the flows.
    $choice = Invoke-InstallRelease $script:St.Rel -Older
    if ($choice -eq 'older') { Invoke-OlderJob }
    elseif ($choice -eq 'back') { $script:ActNav = $true }
}

function Invoke-OlderJob {
    # Lists the 5 newest stable releases before the latest (netbird version and release
    # tag, 0 = Back), then Run / Dry run / Back for the chosen one. pkg add -f allows the downgrade; the
    # identity and settings snapshot/restore is the one of Invoke-Update. The connected screen still
    # follows the latest release, so it shows the update afterwards. A rate limit on the list gives the
    # fail line and back to the menu.
    $st = $script:St
    Write-Info ''
    Write-Info 'Reading the release list from GitHub...'
    try {
        $rels = @(Get-OlderRelease ([string]$st.Box.Arch) ([string]$st.Rel.Tag))
    } catch {
        if (-not $_.Exception.Data['pfnbRateLimit']) { throw }
        Write-RateLimitFail
        $script:ActNav = $true
        return
    }
    if ($rels.Count -eq 0) { throw 'no older stable release found on GitHub' }
    while ($true) {
        Write-Info ''
        Write-Info 'Older release (newest first)'
        for ($i = 0; $i -lt $rels.Count; $i++) { Write-Info " $($i + 1)) netbird $($rels[$i].Client.Version)   release $($rels[$i].Tag)" }
        Write-Info ' 0) Back'
        $opt = Read-UiPrompt 'Enter an option:'
        if ($null -eq $opt) { $opt = '0'; Write-Info '' }
        $opt = $opt.Trim()
        if ($opt) { Write-Log "menu: older release option $opt selected" }
        if ($opt -eq '') { continue }
        if ($opt -eq '0') { $script:ActNav = $true; return }
        if ($opt -cnotmatch '\A[1-9]\z' -or [int]$opt -gt $rels.Count) { Write-Info 'Invalid option.'; continue }
        $pick = $rels[[int]$opt - 1]
        Write-Log "menu: older release $($pick.Tag) selected"
        # Run / Dry run / Back for it; Back returns to the list.
        if ((Invoke-InstallRelease $pick) -eq 'done') { return }
    }
}

function Invoke-UninstallJob {
    # Twin: uninstall_job. Menu item "Uninstall NetBird".
    $st = $script:St
    $hdr = "Uninstall NetBird $($st.State.Client)"
    $choice = Show-ChangeMenu $hdr
    switch ($choice) {
        'run' { $null = Invoke-Uninstall $st.State }
        'dry' {
            Write-UiPlan "$hdr (dry run)"
            Show-DryUninstall
            Write-DryJobEnd
        }
        default { $script:ActNav = $true }
    }
}

function Test-KeyFile {
    # Twin: check_key_file. -Key: the key file must exist and be readable on the client. Only the name is
    # ever shown. Opened and closed at once; its content is never read.
    $f = $script:KeyFile
    if ($f.StartsWith('~/') -or $f.StartsWith('~\')) { $f = Join-Path $HOME $f.Substring(2) }
    if (-not $f) { throw '-Key needs the path of a private key file' }
    $script:KeyFile = $f
    $script:KeyName = ConvertTo-UiSafe ([System.IO.Path]::GetFileName($f))
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "key file '$($script:KeyName)' does not exist or is not a file" }
    try { [System.IO.File]::Open($f, 'Open', 'Read', 'ReadWrite').Dispose() }
    catch { throw "key file '$($script:KeyName)' is not readable" }
}

function Test-HostArg {
    # Twin: check_host_arg. -Host [user@]host: split and validate before anything else happens (before the login).
    $h = $script:HostArg
    $hasAt = $h.Contains('@')
    if ($hasAt) {
        $i = $h.LastIndexOf('@')
        $script:HostUser = $h.Substring(0, $i)
        $script:HostArg = $h.Substring($i + 1)
    }
    if (-not (Test-HostName $script:HostArg)) { throw 'invalid firewall IP or host name' }
    if ($hasAt -and -not (Test-UserName $script:HostUser)) { throw 'invalid user name' }
}

function Invoke-StartLoop {
    # Start screen (twin: start loop). With -Host there is no start screen: connect at once and end after
    # the session (Invoke-Run). Otherwise Connect, Logging and Exit; after Disconnect, a lost session, a
    # cancelled or a failed login the start screen comes back. Exit or end of input: exit code 0.
    if ($script:HostArg) { return (Invoke-Run) }
    while ($true) {
        Clear-UiScreen
        Show-StartScreen
        $go = $false
        $toggle = $false
        while (-not $go -and -not $toggle) {
            $opt = Read-Option
            if ($null -eq $opt) { return 0 }
            if ($opt -eq '') { continue }
            if ($opt -eq '0') { return 0 }
            elseif ($opt -eq '1') { $go = $true }
            elseif ($opt -eq '2') { $toggle = $true }
            else { Write-Info 'Invalid option.' }
        }
        if ($toggle) { $script:LogOn = -not $script:LogOn; continue }
        $connected = $false
        try {
            $connected = Connect-Flow
        } catch {
            Write-FailW (Get-ErrorMessage $_.Exception)
        }
        if ($connected) {
            Write-Info 'Reading the firewall and the latest NetBird release...'
            $null = Invoke-SessionLoop
        } else {
            Disconnect-Remote
        }
        # Failed connect, cancelled connect, "Disconnected." or "Connection lost.": read it first.
        Wait-UiEnter
    }
}

function Invoke-Run {
    # Twin: main (after the checks). With -Host: connects, runs the session, returns the exit code.
    $connected = $false
    try {
        $connected = Connect-Flow
    } catch {
        Write-FailW (Get-ErrorMessage $_.Exception)
        Disconnect-Remote
        return 2
    }
    if (-not $connected) { return 0 }
    Write-Info 'Reading the firewall and the latest NetBird release...'
    return (Invoke-SessionLoop)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Main {
    if ($Version) {
        [Console]::Out.Write("pfnetbird $ScriptVersion`n")
        return 0
    }
    try {
        Initialize-Ui
        Assert-Interactive
        if ($script:KeyGiven) { Test-KeyFile }
        if ($script:HostGiven) { Test-HostArg }
        return (Invoke-StartLoop)
    } catch {
        # In sh's die order: close the open step, the message, the paths, then the frame.
        $ex = $_.Exception
        try {
            Stop-UiStep
            Write-Fail (Get-ErrorMessage $ex)
            Show-CtxPaths
            Exit-UiFrame
        } catch { }
        return 2
    } finally {
        try {
            try { Exit-UiFrame } catch { }
            Disconnect-Remote
        } finally {
            Restore-UiEncoding
        }
    }
}

exit (Invoke-Main)
