############################################################################## 
## 
## Script: Set-ConsoleIcon.ps1 
## By: Aaron Lerch 
## Website: www.aaronlerch.com/blog  
## 
## Set the icon of the current console window to the specified icon 
## 
## Usage:  Set-ConsoleIcon [string] 
## 
## ie: 
## 
## PS:1 > Set-ConsoleIcon "C:\Icons\special_powershell_icon.ico"  
## 
############################################################################## 

param( 
    [string] $iconFile 
) 
 
$WM_SETICON = 0x80 
$ICON_SMALL = 0 
 
function Main 
{ 
    [System.Reflection.Assembly ]::LoadWithPartialName("System.Drawing") | out-null 
 
    # Verify the file exists 
    if ([System.IO.File]::Exists($iconFile) -eq $TRUE) 
    { 
        $icon = new-object System.Drawing.Icon($iconFile)  
 
        if ($icon -ne $null) 
        { 
            $consoleHandle = GetConsoleWindow 
            SendMessage $consoleHandle $WM_SETICON $ICON_SMALL $icon.Handle | out-null 
        } 
    } 
    else  
    { 
        $null 
    } 
} 
 
 
## Invoke a Win32 P/Invoke call. 
## From: Lee Holmes 
## http://www.leeholmes.com/blog/GetTheOwnerOfAProcessInPowerShellPInvokeAndRefOutParameters.aspx 
function Invoke-Win32([string] $dllName, [Type] $returnType,  
   [string] $methodName, [Type[]] $parameterTypes, [Object[]] $parameters)  
{ 
   ## Begin to build the dynamic assembly 
   $domain = [AppDomain]::CurrentDomain 
   $name = New-Object Reflection.AssemblyName 'PInvokeAssembly' 
   $assembly = $domain.DefineDynamicAssembly($name, 'Run')  
   $module = $assembly.DefineDynamicModule('PInvokeModule') 
   $type = $module.DefineType('PInvokeType', "Public,BeforeFieldInit") 
 
   ## Go through all of the parameters passed to us.  As we do this,  
   ## we clone the user's inputs into another array that we will use for 
   ## the P/Invoke call.   
   $inputParameters = @() 
   $refParameters = @() 
   
   for($counter = 1; $counter -le $parameterTypes.Length; $counter++)  
   { 
      ## If an item is a PSReference, then the user  
      ## wants an [out] parameter. 
      if($parameterTypes[$counter - 1] -eq [Ref]) 
      { 
         ## Remember which parameters are used for [Out] parameters  
         $refParameters += $counter 
 
         ## On the cloned array, we replace the PSReference type with the  
         ## .Net reference type that represents the value of the PSReference,  
         ## and the value with the value held by the PSReference.  
         $parameterTypes[$counter - 1] =  
            $parameters[$counter - 1].Value.GetType().MakeByRefType() 
         $inputParameters += $parameters[$counter - 1].Value 
      } 
      else 
      { 
         ## Otherwise, just add their actual parameter to the 
         ## input array. 
         $inputParameters += $parameters[$counter - 1] 
      } 
   } 
 
   ## Define the actual P/Invoke method, adding the [Out]  
   ## attribute for any parameters that were originally [Ref]  
   ## parameters. 
   $method = $type.DefineMethod($methodName, 'Public,HideBySig,Static,PinvokeImpl',  
      $returnType, $parameterTypes)  
   foreach($refParameter in $refParameters) 
   { 
      $method.DefineParameter($refParameter, "Out", $null) 
   } 
 
   ## Apply the P/Invoke constructor 
   $ctor = [Runtime.InteropServices.DllImportAttribute ].GetConstructor([string]) 
   $attr = New-Object Reflection.Emit.CustomAttributeBuilder $ctor, $dllName 
   $method.SetCustomAttribute($attr) 
 
   ## Create the temporary type, and invoke the method. 
   $realType = $type.CreateType()  
   $realType.InvokeMember($methodName, 'Public,Static,InvokeMethod', $null, $null,  
      $inputParameters) 
 
   ## Finally, go through all of the reference parameters, and update the 
   ## values of the PSReference objects that the user passed in.  
   foreach($refParameter in $refParameters) 
   { 
      $parameters[$refParameter - 1].Value = $inputParameters[$refParameter - 1] 
   } 
} 
 
function SendMessage([IntPtr] $hWnd, [Int32] $message, [Int32] $wParam, [Int32] $lParam)  
{ 
    $parameterTypes = [IntPtr], [Int32], [Int32], [Int32] 
    $parameters = $hWnd, $message, $wParam, $lParam 
 
    Invoke-Win32 "user32.dll" ([Int32]) "SendMessage" $parameterTypes $parameters  
} 
 
function GetConsoleWindow() 
{ 
    Invoke-Win32 "kernel32" ([IntPtr]) "GetConsoleWindow" 
} 
 
. Main
