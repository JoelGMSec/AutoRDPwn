$Global:ExploitTable = $null
# Build References
# 
# [3790:    2003, 2003 R2 & XP]
# 6000:    Vista
# 6001:    2008
# 6002:    2008 SP2 & Vista SP2
# 7600:    2008 R2 & 7
# 9200:    2012 & 8
# 9600:    2012 R2 & 8.1
# 10240:   10 1507
# 10586:   10 1511
# 14393:   2016 & 10 1607
# 15063:   10 1703
# 16299:   10 1709
# 17134:   10 1803
#     ?:   10 1809
# Version Number: 	Operating System:
# 5.0 	Windows 2000
# 5.1 	Windows XP
# 5.2 	Windows XP 64bit
# 5.2 	Windows Server 2003 / R2
# 6.0 	Windows Vista / Windows Server 2008
# 6.1 	Windows 7 / Windows Server 2008 R2
# 6.2 	Windows 8 / Windows Server 2012
# 6.3 	Windows 8.1 / Windows Server 2012 R2
# 10.0 	Windows 10 (Preview)

 



function Get-FileVersionInfo ($FilePath) {

    $VersionInfo = (Get-Item $FilePath).VersionInfo
    $FileVersion = ( "{0}.{1}.{2}.{3}" -f $VersionInfo.FileMajorPart, $VersionInfo.FileMinorPart, $VersionInfo.FileBuildPart, $VersionInfo.FilePrivatePart )
        
    return $FileVersion

}

#function Get-InstalledSoftware($SoftwareName) {
#
#    $SoftwareVersion = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $SoftwareName } | Select-Object Version
#    $SoftwareVersion = $SoftwareVersion.Version  # I have no idea what I'm doing
    
#    return $SoftwareVersion

#}

function Get-Architecture {

    # This is the CPU architecture.  Returns "64-bit" or "32-bit".
     
    if ((Test-Path "c:\Program Files (x86)") -eq $true) {$CPUArchitecture = "64-bits" } else {$CPUArchitecture = "32 bits"}
    #$CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    # This is the process architecture, e.g. are we an x86 process running on a 64-bit system.  Retuns "AMD64" or "x86".
    $ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE

    return $CPUArchitecture, $ProcessArchitecture

}

function Get-CPUCoreCount {

    $CoreCount = ((Get-ItemProperty "registry::HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\*").Identifier).count
    
    return $CoreCount

}

function New-ExploitTable {

    # Create the table
    $Global:ExploitTable = New-Object System.Data.DataTable

    # Create the columns
    $Global:ExploitTable.Columns.Add("Title")
    $Global:ExploitTable.Columns.Add("MSBulletin")
    $Global:ExploitTable.Columns.Add("CVEID")
    $Global:ExploitTable.Columns.Add("Link")
    $Global:ExploitTable.Columns.Add("VulnStatus")

    # Add the exploits we are interested in.

    # MS10
    $Global:ExploitTable.Rows.Add("User Mode to Ring (KiTrap0D)","MS10-015","2010-0232","https://www.exploit-db.com/exploits/11199/")
    $Global:ExploitTable.Rows.Add("Task Scheduler .XML","MS10-092","2010-3338, 2010-3888","https://www.exploit-db.com/exploits/19930/")
    # MS11
    $Global:ExploitTable.Rows.Add("The Ancillary Function Driver (AFD) in afd.sys does not properly validate user-mode input, which allows local users to elevate privileges.","MS11-046","N/A","https://www.exploit-db.com/exploits/40564/")
    $Global:ExploitTable.Rows.Add("An EoP exists due to a flaw in the AfdJoinLeaf function of the afd.sys. WinXP/2K3","MS11-080","N/A","https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms11_080_afdjoinleaf.rb")
    # MS12
    $Global:ExploitTable.Rows.Add("An EoP exists due to the way the Windows User Mode Scheduler handles system requests, which can be exploited to execute arbitrary code in kernel mode.","MS12-042","N/A","https://www.exploit-db.com/exploits/20861/")
    # MS13
    $Global:ExploitTable.Rows.Add("HWND_BROADCAST Low to Medium Integrity Privilege Escalation","MS13-005","N/A","https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms13_005_hwnd_broadcast.rb")
    $Global:ExploitTable.Rows.Add("NTUserMessageCall Win32k Kernel Pool Overflow","MS13-053","2013-1300","https://www.exploit-db.com/exploits/33213/")
    $Global:ExploitTable.Rows.Add("TrackPopupMenuEx Win32k NULL Page","MS13-081","2013-3881","https://www.exploit-db.com/exploits/31576/")
    # MS14
    $Global:ExploitTable.Rows.Add("TrackPopupMenu Win32k Null Pointer Dereference","MS14-058","2014-4113","https://www.exploit-db.com/exploits/35101/")
    # MS15
    $Global:ExploitTable.Rows.Add("ClientCopyImage Win32k","MS15-051","2015-1701, 2015-2433","https://www.exploit-db.com/exploits/37367/")
    $Global:ExploitTable.Rows.Add("DCOM DCE/RPC Local NTLM Reflection Privilege Escalation","MS15-076","N/A","https://www.exploit-db.com/exploits/37367/")
    $Global:ExploitTable.Rows.Add("Font Driver Buffer Overflow","MS15-078","2015-2426, 2015-2433","https://www.exploit-db.com/exploits/38222/")
    # MS16
    $Global:ExploitTable.Rows.Add("Kerberos Security Feature Bypass","MS16-014","N/A","https://www.exploit-db.com/exploits/40085/")
    $Global:ExploitTable.Rows.Add("'mrxdav.sys' WebDAV","MS16-016","2016-0051","https://www.exploit-db.com/exploits/40085/")
    $Global:ExploitTable.Rows.Add("Secondary Logon Handle","MS16-032","2016-0099","https://www.exploit-db.com/exploits/39719/")
    $Global:ExploitTable.Rows.Add("Windows Kernel-Mode Drivers EoP","MS16-034","2016-0093/94/95/96","https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?")
    $Global:ExploitTable.Rows.Add("Windows 7 x86/x64 Group Policy Privilege Escalation","MS16-072","N/A","https://www.exploit-db.com/exploits/40219/")
    $Global:ExploitTable.Rows.Add("Win32k Elevation of Privilege","MS16-135","2016-7255","https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135")
    # Miscs that aren't MS
    $Global:ExploitTable.Rows.Add("Nessus Agent 6.6.2 - 6.10.3","N/A","2017-7199","https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html")
    $Global:ExploitTable.Rows.Add("COM Session Moniker Privilege Escalation","MS17-012","CVE-2017-0007","https://www.exploit-db.com/exploits/41607/")
    $Global:ExploitTable.Rows.Add("GDI Palette Objects Local Privilege Escalation","MS17-017","CVE-2017-0050","https://www.exploit-db.com/exploits/42432/")
    $Global:ExploitTable.Rows.Add("An EoP exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory.","N/A","2017-0263","https://www.exploit-db.com/exploits/44478/")
    $Global:ExploitTable.Rows.Add("An EoP exists when the Windows kernel fails to properly handle objects in memory.","N/A","2018-8897","https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/mov_ss.rb")
    $Global:ExploitTable.Rows.Add("An EoP exists when Diagnostics Hub Standard Collector allows file creation in arbitrary locations.","N/A","2018-0952","https://www.exploit-db.com/exploits/45244/")
    $Global:ExploitTable.Rows.Add("An EoP exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).","N/A","2018-8440","https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/alpc_taskscheduler.rb")


}

function Set-ExploitTable ($MSBulletin, $VulnStatus) {

    if ( $MSBulletin -like "MS*" ) {

        $Global:ExploitTable | Where-Object { $_.MSBulletin -eq $MSBulletin

        } | ForEach-Object {

            $_.VulnStatus = $VulnStatus

        }

    } else {


    $Global:ExploitTable | Where-Object { $_.CVEID -eq $MSBulletin

        } | ForEach-Object {

            $_.VulnStatus = $VulnStatus

        }

    }

}

function Get-Results {

    $Global:ExploitTable

}

function Find-AllVulns {

    if ( !$Global:ExploitTable ) {

        $null = New-ExploitTable
    
    }

        Find-MS10015
        Find-MS10092
        Find-MS11046
        Find-MS11080
        Find-MS12042
        Find-MS13005
        Find-MS13053
        Find-MS13081
        Find-MS14058
        Find-MS15051
        Find-Ms15076
        Find-MS15078
        Find-MS16014
        Find-MS16016
        Find-MS16032
        Find-MS16034
        Find-MS16135
        Find-Ms16072
        Find-CVE20170263
        Find-CVE20177199
        Find-MS17012
        Find-MS17017
        Find-CVE20180952
        Find-CVE20188440
        Find-CVE20188897
        Get-Results

}

function Find-MS10015 {

    $MSBulletin = "MS10-015"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\ntoskrnl.exe"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20591" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS10092 {

    $MSBulletin = "MS10-092"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\schedsvc.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\schedsvc.dll"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20830" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS11046 {

    $MSBulletin  = "MS11-046"
    $Path = $env:windir + "\system32\drivers\afd.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        6001 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18639 ] }
        6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18457 ] }
        7006 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 16802 ] }
        default { $VulnStatus = "Not Vulnerable" }

 }   
    Set-ExploitTable $MSBulletin  $VulnStatus
 



}

function Find-MS11080 {

    $MSBulletin  = "MS11-080"
    $Path = $env:windir + "\system32\drivers\afd.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    if ([int](Get-ItemProperty "registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion.split(".")[0] -lt 6 ) {Set-ExploitTable $MSBulletin  $VulnStatus} else {
    switch ( $Build ) {

        default { $VulnStatus = "Not Vulnerable" }

 }   }
    Set-ExploitTable $MSBulletin  $VulnStatus
 



}

function Find-MS12042 {

    $MSBulletin  = "MS12-042"
    if ([int](Get-ItemProperty "registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion.split(".")[0] -lt 6 ) {Set-ExploitTable $MSBulletin  $VulnStatus} else {
    switch ( $Build ) {

        default { $VulnStatus = "Not Vulnerable" }

 }   }
    Set-ExploitTable $MSBulletin  $VulnStatus
 


}

function Find-MS13005 {

    $MSBulletin  = "MS13-005"
    $Path = $env:windir + "\system32\drivers\afd.sys"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    if ([int](Get-ItemProperty "registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion.split(".")[0] -lt 6 ) {Set-ExploitTable $MSBulletin  $VulnStatus} else {
    switch ( $Build ) {

        default { $VulnStatus = "Not Vulnerable" }

 }   }
    Set-ExploitTable $MSBulletin  $VulnStatus
 


}


function Find-MS13053 {

    $MSBulletin = "MS13-053"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "17000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22348" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20732" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS13081 {

    $MSBulletin = "MS13-081"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22435" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "20807" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS14058 {

        $MSBulletin = "MS14-058"
        $Architecture = Get-Architecture
        $Path = $env:windir + "\system32\win32k.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")
        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -ge "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS15051 {

    $MSBulletin = "MS15-051"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "22823" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21247" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "17353" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS15076 {
    
    $Architecture = Get-Architecture
    $MSBulletin  = "MS15-076"
          if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\rpcrt4.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\syswow64\rpcrt4.dll"

    }
    
  
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19431 ] }
        9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17422 ] }
        9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17919 ] }
        default { $VulnStatus = "Not Vulnerable" }
        }
    
    Set-ExploitTable $MSBulletin  $VulnStatus
 }  

function Find-MS15078 {

    $MSBulletin = "MS15-078"
    $Path = $env:windir + "\system32\atmfd.dll"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(" ")

    $Revision = $VersionInfo[2]

    switch ( $Revision ) {

        243 { $VulnStatus = "Appears Vulnerable" }
        default { $VulnStatus = "Not Vulnerable" }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16014 {

    $MSBulletin = "MS16-014"
    
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32kfull.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\syswow64\win32kfull.sys"

    } 

    $VersionInfo = Get-FileVersionInfo($Path)

    $VersionInfo = $VersionInfo.Split(".")

    $Build = [int]$VersionInfo[2]
    $Revision = [int]$VersionInfo[3].Split(" ")[0]

    switch ( $Build ) {

        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 16683] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 103 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    
    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16016 {

    $MSBulletin = "MS16-016"
    $Architecture = Get-Architecture

    if ( $Architecture[0] -eq "64-bit" ) {

        $VulnStatus = "Not supported on 64-bit systems"

    } Else {

        $Path = $env:windir + "\system32\drivers\mrxdav.sys"
        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")

        $Build = $VersionInfo[2]
        $Revision = $VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16000" ] }
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "23317" ] }
            9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "21738" ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "18189" ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "16683" ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le "103" ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16032 {

    $MSBulletin = "MS16-032"
    
    $CPUCount = Get-CPUCoreCount

    if ( $CPUCount -eq "1" ) {

        $VulnStatus = "Not Supported on single-core systems"
    
    } Else {
    
        $Architecture = Get-Architecture

        if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

            $Path = $env:windir + "\system32\seclogon.dll"

        } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

            $Path = $env:windir + "\sysnative\seclogon.dll"

        } 

            $VersionInfo = Get-FileVersionInfo($Path)

            $VersionInfo = $VersionInfo.Split(".")

            $Build = [int]$VersionInfo[2]
            $Revision = [int]$VersionInfo[3].Split(" ")[0]

            switch ( $Build ) {

                6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19598 -Or ( $Revision -ge 23000 -And $Revision -le 23909 ) ] }
                7600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19148 ] }
                7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19148 -Or ( $Revision -ge 23000 -And $Revision -le 23347 ) ] }
                9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17649 -Or ( $Revision -ge 21000 -And $Revision -le 21767 ) ] }
                9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18230 ] }
                10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 16724 ] }
                10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 161 ] }
                default { $VulnStatus = "Not Vulnerable" }

            }
    }
    
    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16034 {

    $MSBulletin = "MS16-034"
    
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    } 

    $VersionInfo = Get-FileVersionInfo($Path)

    $VersionInfo = $VersionInfo.Split(".")

    $Build = [int]$VersionInfo[2]
    $Revision = [int]$VersionInfo[3].Split(" ")[0]

    switch ( $Build ) {

        6002 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 19597 -Or $Revision -lt 23908 ] }
        7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 19145 -Or $Revision -lt 23346 ] }
        9200 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17647 -Or $Revision -lt 21766 ] }
        9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 18228 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    
    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS16072 {
    

    $MSBulletin  = "MS16-072"
    $Architecture = Get-Architecture
                if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\gpprefcl.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\SysWOW64\gpprefcl.dll"

    }
    
    $Architecture = Get-Architecture
  
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 16942 ] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 420 ] }
        default { $VulnStatus = "Not Vulnerable" }
        }
    
    Set-ExploitTable $MSBulletin  $VulnStatus
 }  

function Find-CVE20177199 {

    $CVEID = "2017-7199"
    $SoftwareVersion = Get-InstalledSoftware "Nessus Agent"
    
    if ( !$SoftwareVersion ) {

        $VulnStatus = "Not Vulnerable"

    } else {

        $SoftwareVersion = $SoftwareVersion.Split(".")

        $Major = [int]$SoftwareVersion[0]
        $Minor = [int]$SoftwareVersion[1]
        $Build = [int]$SoftwareVersion[2]

        switch( $Major ) {

        6 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Minor -eq 10 -and $Build -le 3 -Or ( $Minor -eq 6 -and $Build -le 2 ) -Or ( $Minor -le 9 -and $Minor -ge 7 ) ] } # 6.6.2 - 6.10.3
        default { $VulnStatus = "Not Vulnerable" }

        }

    }

    Set-ExploitTable $CVEID $VulnStatus

}

function Find-MS16135 {

    $MSBulletin = "MS16-135"
    $Architecture = Get-Architecture

    if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\win32k.sys"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\sysnative\win32k.sys"

    }

        $VersionInfo = Get-FileVersionInfo($Path)
        $VersionInfo = $VersionInfo.Split(".")
        
        $Build = [int]$VersionInfo[2]
        $Revision = [int]$VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23584 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18524 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16384 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

function Find-MS17012 {
    
    $MSBulletin  = "MS17-012"
    $Path = $env:windir + "\system32\gdi32.dll"
    $Architecture = Get-Architecture
    if ($Architecture[0] -like "*64*") {
     $VulnStatus = "Not Vulnerable"
     Set-ExploitTable $MSBulletin  $VulnStatus
    } else {
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17319 ] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 839 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    Set-ExploitTable $MSBulletin  $VulnStatus
    }
}

function Find-MS17017 {
    

    $MSBulletin  = "MS17-017"
    $Path = $env:windir + "\system32\gdi32.dll"
    $Architecture = Get-Architecture
    if ($Architecture[0] -like "*64*") {
     $VulnStatus = "Not Vulnerable"
     Set-ExploitTable $MSBulletin  $VulnStatus
    } else {
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17319 ] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 839 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    Set-ExploitTable $MSBulletin  $VulnStatus
 }   
}

function Find-CVE20170263 {

    $CVEID = "2017-0263"
    $Path = $env:windir + "\system32\gdi32.dll"
    $Architecture = Get-Architecture
    if ($Architecture[0] -like "*64*") {
     $VulnStatus = "Not Vulnerable"
     Set-ExploitTable $CVEID  $VulnStatus
    } else {
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {

        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17394 ] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 916 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    Set-ExploitTable $CVEID  $VulnStatus
    }
}

function Find-MS17017 {
    

    $MSBulletin  = "MS17-017"
    $Path = $env:windir + "\system32\gdi32.dll"
    $Architecture = Get-Architecture
    if ($Architecture[0] -like "*64*") {
     $VulnStatus = "Not Vulnerable"
     Set-ExploitTable $MSBulletin  $VulnStatus
    } else {
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17319 ] }
        10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 839 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    Set-ExploitTable $MSBulletin  $VulnStatus
 }   
}

function Find-CVE20180952 {
    

    $CVEID  = "2018-0952"
    $Path = $env:windir + "\system32\ntoskrnl.exe"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        9200  { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17946 ] }
        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17946 ] }
        14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 2430 ] }
        15063 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 1266 ] }
        16299 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 611 ] }
        17134 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 228 ] }
        default { $VulnStatus = "Not Vulnerable" }
        }
    
    Set-ExploitTable $CVEID  $VulnStatus
 }  

function Find-CVE20188440 {
    

    $CVEID  = "2018-8440"
    $Architecture = Get-Architecture
    $Path = $env:windir + "\system32\ntoskrnl.exe"
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {

        9200  { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17976 ]}
        10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 17976 ] }
        14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 2485 ] }
        15063 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 1324 ] }
        16299 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 665 ] }
        17134 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 285 ] }
        default { $VulnStatus = "Not Vulnerable" }
        }
    
    Set-ExploitTable $CVEID  $VulnStatus
 } 

function Find-CVE20188897 {

    $CVEID = "2018-8897"
    $Architecture = Get-Architecture
    
    $MSBulletin  = "MS16-072"
                if ( $Architecture[1] -eq "AMD64" -or $Architecture[0] -eq "32-bit" ) {

        $Path = $env:windir + "\system32\coremessaging.dll"

    } ElseIf ( $Architecture[0] -eq "64-bit" -and $Architecture[1] -eq "x86" ) {

        $Path = $env:windir + "\SysWOW64\coremessaging.dll"

    }
    $VersionInfo = Get-FileVersionInfo($Path)
    $VersionInfo = $VersionInfo.Split(".")
    $Build = $VersionInfo[2]
    $Revision = $VersionInfo[3].Split(" ")[0]
    switch ( $Build ) {


        15063 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revison -lt 1088 ] }
        default { $VulnStatus = "Not Vulnerable" }

    }
    Set-ExploitTable $CVEID  $VulnStatus
    
}

