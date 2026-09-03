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

function Update-PathFromRegistry {
    # Odswieza PATH biezacego procesu z rejestru, zakres Machine plus User.
    # To jest dokladnie ta zawartosc, ktora dostaje nowo otwarta powloka, wiec
    # po tym wywolaniu proces widzi to samo co swieza sesja - bez restartu.
    $maszyna = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $uzytkownik = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($maszyna, $uzytkownik) | Where-Object { $_ }) -join ';'
}

Write-Host "== Wayside bootstrap =="

$uvZainstalowaneWTejSesji = $false

if (-not (Test-CommandExists 'uv')) {
    Write-Host "uv nie znalezione na PATH."
    $uvZainstalowaneWTejSesji = $true

    if (Test-CommandExists 'winget') {
        Write-Host "Instaluje uv przez winget..."
        winget install --id astral-sh.uv -e
        if ($LASTEXITCODE -ne 0) {
            throw "Instalacja uv przez winget zakonczyla sie kodem $LASTEXITCODE"
        }

        # Winget dopisuje katalog z aliasami uv do PATH UZYTKOWNIKA w rejestrze
        # i sam o tym mowi: "Path environment variable modified; restart your
        # shell to use the new value". Proces PowerShella dostal jednak wlasna
        # kopie PATH przy starcie i nie odswiezy jej sam, wiec `Test-CommandExists
        # 'uv'` ponizej zwracalo falsz na maszynie, na ktorej instalacja WLASNIE
        # SIE POWIODLA. Skrypt konczyl sie wtedy bledem i kazal otworzyc nowa
        # powloke, czyli obietnica FOUND-01 "jedno polecenie po klonie" byla
        # nieprawdziwa: potrzebne byly dwa uruchomienia.
        #
        # Zmierzone 2026-09-03 na czystym Windows 11 (Hyper-V, brak uv, brak
        # Npcap) przy UAT fazy 1, test 2. Na maszynie autora ten warunek nigdy
        # nie zaszedl, bo uv bylo tam na PATH od poczatku.
        Update-PathFromRegistry
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
        throw "uv nadal niedostepne na PATH mimo instalacji przez winget i odswiezenia PATH z rejestru. Otworz nowa sesje powloki i sprobuj ponownie."
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

# Git swiadomie NIE kopiuje .git/hooks/* przy klonowaniu (hak w cudzym
# repozytorium moglby wykonac dowolny kod przy pierwszym commicie), wiec ten
# krok jest tu, a nie czyms, co "juz dziala" po samym `uv sync`. Bez niego
# bramka poufnosci (scripts/confidentiality_guard.py) istnieje jako kod, ale
# nigdy nie zostaje uruchomiona przy commicie.
#
# Dewelopera z wlasnym, scentralizowanym `core.hooksPath` (typowa praktyka
# bezpieczenstwa/zespolowa, nie tylko jedna maszyna) `pre-commit install`
# odmawia obslugiwac wprost - narzedzie nie wie, czy hak pod tamta sciezka
# jest bezpieczny do nadpisania, i celowo sie zatrzymuje. Nadpisanie jest tu
# wylacznie na czas TEGO JEDNEGO polecenia: `GIT_CONFIG_GLOBAL` przestawia
# gita na pusty plik configu zamiast prawdziwego globalnego, wiec `pre-commit
# install` nie widzi zadnego `core.hooksPath`. Nic nie jest zapisywane do
# prawdziwego globalnego configu dewelopera - podmieniany jest tylko plik, na
# ktory ta jedna komenda patrzy. (Pusty string w `GIT_CONFIG_VALUE_0` NIE
# dziala jako obejscie na Windows - PowerShell traktuje `$env:X = ""` jako
# usuniecie zmiennej, a git wtedy zglasza `missing config value`.)
# Wartosc `core.hooksPath` moze siedziec w DWOCH zakresach naraz i kazdy
# wymaga innego obejscia. Zakres globalny zdejmuje `GIT_CONFIG_GLOBAL`
# opisane wyzej. Zakres LOKALNY tego nie zdejmie w ogole, bo `.git/config`
# nie jest plikiem globalnym - a wlasnie tam ten skrypt sam przypina
# `.git/hooks` na koncu swojego pierwszego przebiegu.
#
# Skutek byl taki, ze bootstrap NIE BYL IDEMPOTENTNY: pierwsze uruchomienie
# przechodzilo (lokalnej wartosci jeszcze nie bylo), a kazde nastepne
# odbijalo sie o `Cowardly refusing to install hooks with core.hooksPath
# set`, bo skrypt widzial wlasne przypiecie i stosowal do niego obejscie
# przeznaczone dla ustawienia globalnego. Wykryte 2026-09-03 przy zmianie
# nazwy katalogu projektu, ktora wymusila drugi przebieg - ale wywrocilby
# sie kazdy drugi przebieg, z dowolnego powodu.
#
# Lokalna wartosc jest zdejmowana na czas instalacji i przywracana zaraz
# po niej, nizej w tym pliku. Bez `core.hooksPath` `pre-commit install`
# pisze hak do `.git/hooks/pre-commit`, czyli dokladnie tam, gdzie ma byc.
$existingHooksPath = git config --get core.hooksPath 2>$null
if ($LASTEXITCODE -ne 0) { $existingHooksPath = $null }

$localHooksPath = git config --local --get core.hooksPath 2>$null
if ($LASTEXITCODE -ne 0) { $localHooksPath = $null }

if ($existingHooksPath) {
    Write-Host "core.hooksPath jest ustawione na '$existingHooksPath'."
    Write-Host "Instaluje z tymczasowym nadpisaniem tego ustawienia (tylko na czas tego polecenia)."
    $emptyGlobalConfig = Join-Path ([System.IO.Path]::GetTempPath()) "wayside-empty-gitconfig-$PID.ini"
    New-Item -ItemType File -Path $emptyGlobalConfig -Force | Out-Null
    $env:GIT_CONFIG_GLOBAL = $emptyGlobalConfig
}

if ($localHooksPath) {
    Write-Host "core.hooksPath jest przypiete lokalnie do '$localHooksPath' - zdejmuje na czas instalacji."
    git config --local --unset-all core.hooksPath
}

Write-Host "Instaluje hak pre-commit (uv run pre-commit install)..."
uv run pre-commit install
$preCommitInstallExitCode = $LASTEXITCODE

if ($env:GIT_CONFIG_GLOBAL) {
    Remove-Item $env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue
    Remove-Item Env:\GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue
}

# Przywrocenie idzie PRZED sprawdzeniem kodu wyjscia, bo skrypt nie moze
# zostawic repozytorium bez przypiecia takze wtedy, gdy instalacja padla:
# bez `core.hooksPath` git wrocilby do globalnej sciezki dewelopera i hak
# poufnosci nie wywolalby sie przy nastepnym commicie.
if ($localHooksPath) {
    git config --local core.hooksPath $localHooksPath
}

if ($preCommitInstallExitCode -ne 0) {
    throw "uv run pre-commit install zakonczylo sie kodem $preCommitInstallExitCode"
}

if ($existingHooksPath) {
    # Hak jest juz zapisany w .git/hooks, ale bez tego kroku git nadal
    # szukalby go pod poprzednim core.hooksPath przy prawdziwym `git commit`
    # i haka poufnosci nigdy by nie wywolal. Przypiecie jest LOKALNE (tylko
    # to jedno repozytorium, w .git/config, nigdy scommitowane) i wskazuje
    # dokladnie na standardowa, domyslna lokalizacje gita - inne repozytoria
    # tego dewelopera i jego globalne ustawienie zostaja bez zmian.
    git config --local core.hooksPath ".git/hooks"
    Write-Host "core.hooksPath przypiete lokalnie do .git/hooks dla tego repozytorium (ustawienie globalne bez zmian)."
}

$hookPath = Join-Path (Join-Path (Get-Location) ".git") "hooks\pre-commit"
if (-not (Test-Path $hookPath)) {
    Write-Host "Plik $hookPath nie powstal po instalacji haka." -ForegroundColor Red
    exit 1
}
Write-Host "Hak pre-commit zainstalowany: $hookPath"

Write-Host ""
Write-Host "== Bootstrap zakonczony =="
Write-Host "Uruchomienie CLI:  uv run wayside inspect <plik.pcap>"
Write-Host "Uruchomienie testow: uv run pytest"

# Jesli uv zostalo zainstalowane wlasnie teraz, ta podpowiedz nie zadziala
# w powloce, ktora wywolala ten skrypt: proces potomny nie moze zmienic
# srodowiska procesu rodzica. Odswiezenie PATH wyzej dziala wewnatrz TEGO
# procesu, dzieki czemu `uv sync` powyzej sie wykonalo, ale okno, z ktorego
# skrypt zostal uruchomiony, dalej ma swoja stara kopie PATH. Kodem tego
# naprawic nie da sie w ogole, wiec mowimy o tym wprost.
# Zmierzone 2026-09-03 na czystym Windows 11 przy UAT fazy 1, test 2.
if ($uvZainstalowaneWTejSesji) {
    Write-Host ""
    Write-Host "UWAGA: uv zostalo zainstalowane podczas tego uruchomienia."
    Write-Host "Zamknij to okno i otworz nowe, zanim wywolasz powyzsze polecenia -"
    Write-Host "biezace okno ma jeszcze PATH sprzed instalacji."
}
