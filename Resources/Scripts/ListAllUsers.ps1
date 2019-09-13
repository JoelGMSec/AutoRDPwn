<#
.SYNOPSIS
This script will list all users' RDP Connections History.
First use "reg load" to load hive.
Then read the RDP Connections History from HKEY_USERS.
Last you need to use "reg unload" to unload hive. 
The script automatically implements the above operation,there is no need for a GUI. :)
Author: 3gstudent@3gstudent
License: BSD 3-Clause
#>

function ListAllUsers { $ErrorActionPreference = "SilentlyContinue"
$nouser='DefaultAccount','Guest','defaultuser0','Invitado','WDAGUtilityAccount','HomeGroupUser$'
$AllUser = Get-WmiObject -Class Win32_UserAccount | where{$_.Name -notin $nouser} 
foreach($User in $AllUser)
{
	$RegPath = "Registry::HKEY_USERS\"+$User.SID+"\Software\Microsoft\Terminal Server Client\Servers\"
	Write-Output "User:"$User.Name
	Write-Output "SID:"$User.SID
	Write-Output "Status:"$User.Status
	$QueryPath = dir $RegPath -Name -ErrorAction SilentlyContinue
	If(!$?)
	{
		Write-Output "[!]Not logged in"
		Write-Output "[*]Try to load Hive"
		$File = "C:\Documents and Settings\"+$User.Name+"\NTUSER.DAT"
		$Path = "HKEY_USERS\"+$User.SID
		Reg load $Path $File
		If(!$?)
		{
			Write-Output "[!]Fail to load Hive"
			Write-Output "[!]No RDP Connections History"
		}
		Else
		{
			$QueryPath = dir $RegPath -Name -ErrorAction SilentlyContinue
			If(!$?)
			{
				Write-Output "[!]No RDP Connections History"
			}
			Else
			{
				foreach($Name in $QueryPath)
				{   
					$User = (Get-ItemProperty -Path $RegPath$Name -ErrorAction Stop).UsernameHint
					Write-Output "Server:"$Name
					Write-Output "User:"$User
				}
			}
			Write-Output "[*]Try to unload Hive"
			Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "Reg unload $Path"		
		}
	}
	foreach($Name in $QueryPath)
	{   
		Try  
		{  
			$User = (Get-ItemProperty -Path $RegPath$Name -ErrorAction Stop).UsernameHint
			Write-Output "Server:"$Name
			Write-Output "User:"$User
		}
		Catch  
		{
			Write-Output "[!]No RDP Connections History"
		}
	}
	Write-Output "----------------------------------"	}}
