Function Get-MD4Hash
{
<#
.SYNOPSIS
    This cmdlet returns the MD4 hash of the data that is input.
    WARNING: MD4 is not secure, so it should NEVER be used to 
    protect sensitive data. This cmdlet is for research purposes only!

.DESCRIPTION
    This cmdlet returns the MD4 hash of the data that is input.
    WARNING: MD4 is not secure, so it should NEVER be used to 
    protect sensitive data. This cmdlet is for research purposes only!
    This cmdlet uses Microsoft's implementation of MD4, exported 
    from bcrypt.dll. The implementation is fully compliant with
    RFC 1320. This cmdlet takes a byte array as input, not a string.
    So if you wanted to hash a string (such as a password,) you 
    need to convert it to a byte array first.

.EXAMPLE
    Get-MD4Hash -DataToHash $([Text.Encoding]::Unicode.GetBytes("YourPassword1!"))

.PARAMETER DataToHash
    A byte array that represents the data that you want to hash.

.INPUTS
    A byte array containing the data you wish to hash.

.OUTPUTS
    A 128-bit hexadecimal string - the MD4 hash of your data.

.NOTES
    Author: Ryan Ries, 2014, ryan@myotherpcisacloud.com

.LINK
    https://myotherpcisacloud.com
#>
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True, ValueFromPipeline=$False)]           
           [Byte[]]$DataToHash)
    END
    {        
        Set-StrictMode -Version Latest
        Add-Type -TypeDefinition @'
        using System;
        using System.Text;
        using System.Runtime.InteropServices;
        public class BCrypt
        {
            [DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
            public static extern NTStatus BCryptOpenAlgorithmProvider(
                [Out] out IntPtr phAlgorithm,
                [In] string pszAlgId,
                [In, Optional] string pszImplementation,
                [In] UInt32 dwFlags);

            [DllImport("bcrypt.dll")]
            public static extern NTStatus BCryptCloseAlgorithmProvider(
                [In, Out] IntPtr hAlgorithm,
                [In] UInt32 dwFlags);

            [DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
            public static extern NTStatus BCryptCreateHash(
                [In, Out] IntPtr hAlgorithm,
                [Out] out IntPtr phHash,
                [Out] IntPtr pbHashObject,
                [In, Optional] UInt32 cbHashObject,
                [In, Optional] IntPtr pbSecret,
                [In] UInt32 cbSecret,
                [In] UInt32 dwFlags);

            [DllImport("bcrypt.dll")]
            public static extern NTStatus BCryptDestroyHash(
                [In, Out] IntPtr hHash);

            [DllImport("bcrypt.dll")]
            public static extern NTStatus BCryptHashData(
                [In, Out] IntPtr hHash,
                [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                [In] int cbInput,
                [In] UInt32 dwFlags);

            [DllImport("bcrypt.dll")]
            public static extern NTStatus BCryptFinishHash(
                [In, Out] IntPtr hHash,
                [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                [In] int cbInput,
                [In] UInt32 dwFlags);

            [Flags]
            public enum AlgOpsFlags : uint
            {            
                BCRYPT_PROV_DISPATCH = 0x00000001,
                BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008,
                BCRYPT_HASH_REUSABLE_FLAG = 0x00000020
            }

            // This is a gigantic enum and I don't want to copy all of it into this Powershell script.
            // Basically anything other than zero means something went wrong.
            public enum NTStatus : uint
            {
                STATUS_SUCCESS = 0x00000000
            }
        }
'@

        [Byte[]]$HashBytes   = New-Object Byte[] 16
        [IntPtr]$PHAlgorithm = [IntPtr]::Zero
        [IntPtr]$PHHash      = [IntPtr]::Zero
        $NTStatus = [BCrypt]::BCryptOpenAlgorithmProvider([Ref] $PHAlgorithm, 'MD4', $Null, 0)
        If ($NTStatus -NE 0)
        {
            Write-Error "BCryptOpenAlgorithmProvider failed with NTSTATUS $NTStatus"
            If ($PHAlgorithm -NE [IntPtr]::Zero)
            {
                $NTStatus = [BCrypt]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
            }
            Return
        }
        $NTStatus = [BCrypt]::BCryptCreateHash($PHAlgorithm, [Ref] $PHHash, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, 0)
        If ($NTStatus -NE 0)
        {
            Write-Error "BCryptCreateHash failed with NTSTATUS $NTStatus"
            If ($PHHash -NE [IntPtr]::Zero)
            {
                $NTStatus = [BCrypt]::BCryptDestroyHash($PHHash)                
            }
            If ($PHAlgorithm -NE [IntPtr]::Zero)
            {
                $NTStatus = [BCrypt]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
            }
            Return
        }

        $NTStatus = [BCrypt]::BCryptHashData($PHHash, $DataToHash, $DataToHash.Length, 0)
        $NTStatus = [BCrypt]::BCryptFinishHash($PHHash, $HashBytes, $HashBytes.Length, 0)

        If ($PHHash -NE [IntPtr]::Zero)
        {
            $NTStatus = [BCrypt]::BCryptDestroyHash($PHHash)
        }
        If ($PHAlgorithm -NE [IntPtr]::Zero)
        {
            $NTStatus = [BCrypt]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
        }

        $HashString = New-Object System.Text.StringBuilder
        Foreach ($Byte In $HashBytes)
        {
            [Void]$HashString.Append($Byte.ToString("X2"))
        }
        Return $HashString.ToString()
    }
}

function Get-NTLM {

    Get-MD4Hash -DataToHash $([Text.Encoding]::Unicode.GetBytes($args[0]))

    }
