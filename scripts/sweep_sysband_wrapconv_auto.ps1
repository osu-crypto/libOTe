param(
    [string]$Exe = ".\out\build\x64-Release\frontend\frontend_libOTe.exe",
    [string]$Csv = "",
    [int]$Threads = 20,
    [int[]]$Sigmas = @(8, 12, 16, 20),
    [int]$StartK = 24,
    [int]$StepK = 8,
    [int]$MaxPoints = 0
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Csv)) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Csv = "sysband_wrapconv_batches_$stamp.csv"
}

"k,n,sigma,ms,attempts,cap,zeroH,cumH,zero_rel,zero_val" | Set-Content $Csv

$pointCount = 0
$k = $StartK
while ($true) {
    foreach ($sigma in $Sigmas) {
        $n = 2 * $k + $sigma
        $out = & $Exe `
            -minimumdistance `
            -subcode sysBand wrapConv `
            -k $k `
            -stageN $n $n `
            -stageSigma $sigma $sigma `
            -numeric float `
            -threads $Threads `
            -noPlot `
            -autoHMax 2>&1

        $timeLine = ($out | Select-String ' time: ').Line
        $autoLine = ($out | Select-String '^autoHMax:').Line
        $mdLine = ($out | Select-String '^MD:').Line
        if (-not $timeLine -or -not $autoLine -or -not $mdLine) {
            throw "parse failure for k=$k sigma=$sigma`n$out"
        }

        $ms = [int]([regex]::Match($timeLine, 'time: (\d+)ms').Groups[1].Value)
        $attempts = [int]([regex]::Match($autoLine, 'attempts=(\d+)').Groups[1].Value)
        $cap = [int]([regex]::Match($autoLine, 'cap=(\d+)').Groups[1].Value)
        $zeroH = [int]([regex]::Match($autoLine, 'zeroH=(\d+)').Groups[1].Value)
        $cumH = [int]([regex]::Match($autoLine, 'cumH=(\d+)').Groups[1].Value)
        $zeroRel = [regex]::Match($mdLine, 'zero: ([0-9eE+\.-]+)').Groups[1].Value
        $zeroVal = [regex]::Match($mdLine, 'zeroVal: ([0-9eE+\.-]+)').Groups[1].Value

        "$k,$n,$sigma,$ms,$attempts,$cap,$zeroH,$cumH,$zeroRel,$zeroVal" | Add-Content $Csv
        Write-Host "k=$k sigma=$sigma n=$n ms=$ms attempts=$attempts cap=$cap zeroH=$zeroH cumH=$cumH zero=$zeroRel"

        ++$pointCount
        if ($MaxPoints -gt 0 -and $pointCount -ge $MaxPoints) {
            return
        }
    }

    $k += $StepK
}
