$ErrorActionPreference = "SilentlyContinue" ; Set-StrictMode -Off

REG DELETE "HKCU\Console"/f 2>&1> $null
REG ADD "HKCU\Console" /v ForceV2 /t REG_DWORD /d 1 /f 2>&1> $null
REG ADD "HKCU\Console" /v ExtendedEditKey /t REG_DWORD /d 1 /f 2>&1> $null
REG ADD "HKCU\Console" /v FilterOnPaste /t REG_DWORD /d 1 /f 2>&1> $null
REG ADD "HKCU\Console" /v InsertMode /t REG_DWORD /d 1 /f 2>&1> $null
REG ADD "HKCU\Console" /v QuickEdit /t REG_DWORD /d 1 /f 2>&1> $null
REG ADD "HKCU\Console" /v FaceName /t REG_SZ /d Consolas /f 2>&1> $null
REG ADD "HKCU\Console" /v FontFamily /t REG_DWORD /d 54 /f 2>&1> $null
REG ADD "HKCU\Console" /v FontWeight /t REG_DWORD /d 700 /f 2>&1> $null
REG ADD "HKCU\Console" /v ScreenBufferSize /t REG_DWORD /d 196608100 /f 2>&1> $null
REG ADD "HKCU\Console" /v FontSize /t REG_DWORD /d 1048576 /f 2>&1> $null
REG ADD "HKCU\Console" /v WindowSize /t REG_DWORD /d 1966180 /f 2>&1> $null
REG ADD "HKCU\Console" /v WindowAlpha /t REG_DWORD /d 252 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable00 /t REG_DWORD /d 1315860 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable01 /t REG_DWORD /d 14300928 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable02 /t REG_DWORD /d 958739 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable03 /t REG_DWORD /d 14521914 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable04 /t REG_DWORD /d 2035653 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable05 /t REG_DWORD /d 9967496 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable06 /t REG_DWORD /d 40129 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable07 /t REG_DWORD /d 13421772 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable08 /t REG_DWORD /d 7763574 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable09 /t REG_DWORD /d 16742459 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable10 /t REG_DWORD /d 7915030 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable11 /t REG_DWORD /d 14079585 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable12 /t REG_DWORD /d 5901010 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable13 /t REG_DWORD /d 10354868 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable14 /t REG_DWORD /d 10875385 /f 2>&1> $null
REG ADD "HKCU\Console" /v ColorTable15 /t REG_DWORD /d 15921906 /f 2>&1> $null

