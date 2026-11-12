param([string]$Scanner)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $here)

dotnet build "$here\Target" -c Release -nologo -v q | Out-Null
dotnet build "$root\src" -c Release -nologo -v q | Out-Null

$target = "$here\Target\bin\Release\net8.0\win-x64\PageScanTarget.exe"
$scanner = if ($Scanner) { (Resolve-Path $Scanner).Path } else { "$root\src\bin\Release\net8.0\win-x64\PageScan.exe" }
$out = "$here\out"
New-Item -ItemType Directory -Force $out | Out-Null
$log = "$out\target.log"
Remove-Item $log -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $target -ArgumentList 120 -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
try {
    $ready = $false
    foreach ($i in 1..100) {
        Start-Sleep -Milliseconds 200
        if ((Test-Path $log) -and (Select-String -Path $log -Pattern '^READY' -Quiet)) { $ready = $true; break }
    }
    if (-not $ready) { throw 'цель не вышла на готовность' }

    Get-Content $log -Encoding UTF8
    ''
    $ErrorActionPreference = 'Continue'
    & $scanner --pid $p.Id --out $out @args 2>$null
    $code = $LASTEXITCODE
}
finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}

$html = Get-ChildItem $out -Filter 'pagescan-*.html' | Sort-Object LastWriteTime | Select-Object -Last 1
$text = [IO.File]::ReadAllText($html.FullName, [Text.Encoding]::UTF8)
$json = [regex]::Match($text, '(?s)<script id="mcdata" type="application/json">(.*?)</script>').Groups[1].Value
$data = $json | ConvertFrom-Json

$expect = @(
    @{ Name = 'снятый перехват в kernel32';        Sev = 4; Cat = 'КОД';       Like = 'kernel32.dll:*вернули байты как было — страниц: 1' },
    @{ Name = 'снятый перехват, страница вытеснена'; Sev = 3; Cat = 'КОД';     Like = 'version.dll:*вернули байты как было — страниц: 1' },
    @{ Name = 'перехват в начале функции';         Sev = 4; Cat = 'КОД';       Like = 'dbghelp.dll:*точечная правка*мест: 2*в начале функции: 1*вне образов: 1*' },
    @{ Name = 'замещение кода';                    Sev = 3; Cat = 'КОД';       Like = 'msxml6.dll:*замещён*страниц: 8*' },
    @{ Name = 'много правок на странице';          Sev = 2; Cat = 'КОД';       Like = 'msxml6.dll:*изменён во многих местах*' },
    @{ Name = 'подмена адреса в данных';           Sev = 3; Cat = 'ДАННЫЕ';    Like = 'msxml6.dll:*вне образов*' },
    @{ Name = 'стёртый заголовок';                 Sev = 3; Cat = 'ЗАГОЛОВОК'; Like = 'msftedit.dll:*стёрт*' },
    @{ Name = 'заголовок: писали и вернули';       Sev = 2; Cat = 'ЗАГОЛОВОК'; Like = 'riched20.dll:*вернули*' }
)

''
$failed = 0
foreach ($e in $expect) {
    $hit = $data.findings | Where-Object { $_.sev -eq $e.Sev -and $_.cat -eq $e.Cat -and $_.title -like $e.Like } | Select-Object -First 1
    if ($hit) { "  [ok] $($e.Name)" } else { "  [!!] $($e.Name) — находки нет"; $failed++ }
}

$strong = @($data.findings | Where-Object { $_.sev -ge 2 })
$extra = @($strong | Where-Object { $t = $_.title; -not ($expect | Where-Object { $t -like $_.Like }) })
foreach ($x in $extra) { "  [!!] лишняя находка: [$($x.cat)] $($x.title)"; $failed++ }

''
"Отчёт: $($html.FullName)"
"Код возврата сканера: $code"
if ($failed -eq 0) { 'ТЕСТ ПРОЙДЕН'; exit 0 } else { "ТЕСТ НЕ ПРОЙДЕН: расхождений $failed"; exit 1 }
