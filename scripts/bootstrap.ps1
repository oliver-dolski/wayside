# scripts/bootstrap.ps1
#
# Jedno polecenie po klonie: instaluje uv (jesli brak) i synchronizuje srodowisko.
# Pisany pod Windows PowerShell 5.1 (powershell.exe), nie pod PowerShell 7 (pwsh.exe) -
# bez konstrukcji niedostepnych w 5.1 (np. ForEach-Object -Parallel, operator ternarny).
#
# Ten skrypt NIE zmienia globalnej Execution Policy i NIE uruchamia samoczynnie
# lancucha pobierz-i-wykonaj (irm | iex). Jesli winget nie jest dostepny, skrypt
# wypisuje gotowe do recznego skopiowania polecenie zapasowe i konczy sie.

$ErrorActionPreference = 'Stop'

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "== Wayside bootstrap =="

if (-not (Test-CommandExists 'uv')) {
    Write-Host "uv nie znalezione na PATH."

    if (Test-CommandExists 'winget') {
        Write-Host "Instaluje uv przez winget..."
        winget install --id astral-sh.uv -e
        if ($LASTEXITCODE -ne 0) {
            throw "Instalacja uv przez winget zakonczyla sie kodem $LASTEXITCODE"
        }
    }
    else {
        Write-Host "winget niedostepny na tej maszynie. Zainstaluj uv recznie, np.:"
        Write-Host '  powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        Write-Host "Powyzsze polecenie uzywa zakresowego bypassu polityki wykonywania"
        Write-Host "tylko dla tego jednego wywolania - nie zmienia globalnej polityki."
        Write-Host "Po instalacji uruchom ten skrypt ponownie."
        exit 1
    }

    if (-not (Test-CommandExists 'uv')) {
        throw "uv nadal niedostepne na PATH po instalacji przez winget. Otworz nowa sesje powloki i sprobuj ponownie."
    }
}
else {
    Write-Host "uv jest juz dostepne na PATH."
}

Write-Host "Synchronizuje srodowisko (uv sync)..."
uv sync
if ($LASTEXITCODE -ne 0) {
    throw "uv sync zakonczylo sie kodem $LASTEXITCODE"
}

Write-Host ""
Write-Host "== Bootstrap zakonczony =="
Write-Host "Uruchomienie CLI:  uv run wayside inspect <plik.pcap>"
Write-Host "Uruchomienie testow: uv run pytest"
