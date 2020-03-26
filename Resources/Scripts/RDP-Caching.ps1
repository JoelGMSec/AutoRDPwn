Add-Type -Assembly System.Drawing
$workingDir = "$env:Temp\Recovered_RDP_Session"
md $workingDir -force
$file=(dir Env:\LOCALAPPDATA).Value+"\Microsoft\Terminal Server Client\Cache\Cache0001.bin"
 
$tileSize = 64
$tilesPerGraphW=8
$tilesPerGraphH=8
$bpp = 4
$bufSize = $bpp * $tileSize * $tileSize * $tilesPerGraphW * $tilesPerGraphH
$bytesRead=$bufSize
$imgNo=0
$imgNamePrefix=(get-date).Ticks
$tileSize2 = $tileSize * $tileSize
 
$buf = new-object byte[] $bufSize
$fs = new-object IO.FileStream($file, [IO.FileMode]::Open)
$reader = new-object IO.BinaryReader($fs)
$bmBM = New-Object System.Drawing.Bitmap (($tileSize * $tilesPerGraphW),($tileSize * $tilesPerGraphH))
 
 
while ($bytesRead -eq $bufSize)
    {
    $offset = $imgNo*$bufSize
    $imgNo++
   
    $dum=$reader.BaseStream.Seek($offset,"Begin")
    $bytesRead=$reader.Read($buf, 0, $bufSize)
   
    for ($it=0; $it -lt $tilesPerGraphH; $it++)
        {
        Write-Progress -Activity "Analyzing cache file" -Status "Row $it of $tilesPerGraphH" -PercentComplete (($it/$tilesPerGraphH)*100) -id 0
        for ($jt=0; $jt -lt $tilesPerGraphW; $jt++)
            {
            for ($is=0; $is -lt $tileSize; $is++)
                {
                for ($js=0; $js -lt $tileSize; $js++)
                    {
                    $bufPos = $bpp * (($it*$tilesPerGraphW+$jt)*$tileSize2+$is*$tileSize+$js)
                    $red = $buf[$bufPos]
                    $green = $buf[$bufPos + 1]
                    $blue = $buf[$bufPos + 2]
                    $bmBM.SetPixel($jt*$tileSize+$js,$it*$tileSize+$is,[System.Drawing.Color]::FromArgb($red, $green, $blue))
                    }
                }
            }
        }
        $imgNoText=($imgNo).ToString("0000")
        $bmBM.Save("$workingDir\$imgNamePrefix.$imgNoText.png")
        Write-Progress -Activity "Analyzing cache file" -Status "Row $it of $tilesPerGraphH" -id 0 -Completed
    }
