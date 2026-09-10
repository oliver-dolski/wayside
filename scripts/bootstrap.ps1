# scripts/bootstrap.ps1
#
# One command after cloning: installs uv (if absent) and syncs the environment.
# Written for Windows PowerShell 5.1 (powershell.exe), not for PowerShell 7
# (pwsh.exe) - with no construct unavailable in 5.1 (e.g. ForEach-Object
# -Parallel, the ternary operator).
#
# This script does NOT change the global Execution Policy and does NOT run a
# download-and-execute chain (irm | iex) on its own. If winget is unavailable,
# the script prints a fallback command ready to copy by hand and stops.

$ErrorActionPreference = 'Stop'

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Update-PathFromRegistry {
    # Refreshes the PATH of the current process from the registry, Machine plus
    # User scope. That is exactly the content a newly opened shell receives, so
    # after this call the process sees the same as a fresh session - with no
    # restart.
    $machine = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

Write-Host "== Wayside bootstrap =="

$uvInstalledInThisSession = $false

if (-not (Test-CommandExists 'uv')) {
    Write-Host "uv not found on PATH."
    $uvInstalledInThisSession = $true

    if (Test-CommandExists 'winget') {
        Write-Host "Installing uv through winget..."
        winget install --id astral-sh.uv -e
        if ($LASTEXITCODE -ne 0) {
            throw "Installing uv through winget exited with code $LASTEXITCODE"
        }

        # Winget appends the directory with the uv aliases to the USER PATH in
        # the registry and says so itself: "Path environment variable modified;
        # restart your shell to use the new value". The PowerShell process,
        # however, received its own copy of PATH at start and will not refresh
        # it on its own, so `Test-CommandExists 'uv'` below returned false on a
        # machine where the installation had JUST SUCCEEDED. The script then
        # ended with an error telling the user to open a new shell, which made
        # the FOUND-01 promise of "one command after cloning" untrue: two runs
        # were needed.
        #
        # Measured on 2026-09-03 on a clean Windows 11 (Hyper-V, no uv, no
        # Npcap) during the phase 1 UAT, test 2. On the author's machine this
        # condition never occurred, because uv was on PATH there from the
        # start.
        Update-PathFromRegistry
    }
    else {
        Write-Host "winget is unavailable on this machine. Install uv by hand, e.g.:"
        Write-Host '  powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        Write-Host "The command above uses a scoped execution policy bypass for"
        Write-Host "that single call only - it does not change the global policy."
        Write-Host "After installing, run this script again."
        exit 1
    }

    if (-not (Test-CommandExists 'uv')) {
        throw "uv is still unavailable on PATH despite the winget install and the PATH refresh from the registry. Open a new shell session and try again."
    }
}
else {
    Write-Host "uv is already available on PATH."
}

Write-Host "Syncing the environment (uv sync)..."
uv sync
if ($LASTEXITCODE -ne 0) {
    throw "uv sync exited with code $LASTEXITCODE"
}

# Git deliberately does NOT copy .git/hooks/* on clone (a hook in someone
# else's repository could execute arbitrary code on the first commit), so this
# step is here rather than being something that "already works" after `uv sync`
# alone. Without it the confidentiality gate
# (scripts/confidentiality_guard.py) exists as code but never runs at commit
# time.
#
# For a developer with their own centralised `core.hooksPath` (a common
# security/team practice, not one machine's quirk) `pre-commit install` refuses
# to proceed outright - the tool does not know whether the hook under that path
# is safe to overwrite, and stops deliberately. The override here lasts for
# THIS ONE COMMAND only: `GIT_CONFIG_GLOBAL` points git at an empty config file
# instead of the real global one, so `pre-commit install` sees no
# `core.hooksPath`. Nothing is written to the developer's real global config -
# only the file that this one command looks at is swapped. (An empty string in
# `GIT_CONFIG_VALUE_0` does NOT work as a workaround on Windows - PowerShell
# treats `$env:X = ""` as deleting the variable, and git then reports `missing
# config value`.)
# The `core.hooksPath` value can sit in TWO scopes at once, and each needs a
# different workaround. The global scope is lifted by the `GIT_CONFIG_GLOBAL`
# described above. The LOCAL scope is not lifted by it at all, because
# `.git/config` is not a global file - and that is exactly where this script
# pins `.git/hooks` at the end of its first run.
#
# The effect was that bootstrap WAS NOT IDEMPOTENT: the first run passed (the
# local value did not exist yet), and every following one bounced off `Cowardly
# refusing to install hooks with core.hooksPath set`, because the script saw
# its own pin and applied to it the workaround meant for the global setting.
# Found on 2026-09-03 during a rename of the project directory, which forced a
# second run - but any second run would have fallen over, for any reason.
#
# The local value is unset for the duration of the installation and restored
# right after it, further down this file. Without `core.hooksPath`,
# `pre-commit install` writes the hook to `.git/hooks/pre-commit`, which is
# exactly where it belongs.
$existingHooksPath = git config --get core.hooksPath 2>$null
if ($LASTEXITCODE -ne 0) { $existingHooksPath = $null }

$localHooksPath = git config --local --get core.hooksPath 2>$null
if ($LASTEXITCODE -ne 0) { $localHooksPath = $null }

if ($existingHooksPath) {
    Write-Host "core.hooksPath is set to '$existingHooksPath'."
    Write-Host "Installing with a temporary override of that setting (for this command only)."
    $emptyGlobalConfig = Join-Path ([System.IO.Path]::GetTempPath()) "wayside-empty-gitconfig-$PID.ini"
    New-Item -ItemType File -Path $emptyGlobalConfig -Force | Out-Null
    $env:GIT_CONFIG_GLOBAL = $emptyGlobalConfig
}

if ($localHooksPath) {
    Write-Host "core.hooksPath is pinned locally to '$localHooksPath' - unsetting it for the installation."
    git config --local --unset-all core.hooksPath
}

Write-Host "Installing the pre-commit hook (uv run pre-commit install)..."
uv run pre-commit install
$preCommitInstallExitCode = $LASTEXITCODE

if ($env:GIT_CONFIG_GLOBAL) {
    Remove-Item $env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue
    Remove-Item Env:\GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue
}

# The restore comes BEFORE checking the exit code, because the script must not
# leave the repository without a pin even when the installation failed: without
# `core.hooksPath` git would fall back to the developer's global path and the
# confidentiality hook would not fire on the next commit.
if ($localHooksPath) {
    git config --local core.hooksPath $localHooksPath
}

if ($preCommitInstallExitCode -ne 0) {
    throw "uv run pre-commit install exited with code $preCommitInstallExitCode"
}

if ($existingHooksPath) {
    # The hook is already written into .git/hooks, but without this step git
    # would still look for it under the previous core.hooksPath on a real `git
    # commit` and would never fire the confidentiality hook. The pin is LOCAL
    # (this one repository only, in .git/config, never committed) and points at
    # git's standard, default location - the developer's other repositories and
    # their global setting stay unchanged.
    git config --local core.hooksPath ".git/hooks"
    Write-Host "core.hooksPath pinned locally to .git/hooks for this repository (the global setting is unchanged)."
}

$hookPath = Join-Path (Join-Path (Get-Location) ".git") "hooks\pre-commit"
if (-not (Test-Path $hookPath)) {
    Write-Host "The file $hookPath was not created by the hook installation." -ForegroundColor Red
    exit 1
}
Write-Host "Pre-commit hook installed: $hookPath"

Write-Host ""
Write-Host "== Bootstrap finished =="
Write-Host "Run the CLI:    uv run wayside inspect <file.pcap>"
Write-Host "Run the tests:  uv run pytest"

# If uv was installed just now, this hint will not work in the shell that
# invoked this script: a child process cannot change the environment of its
# parent. The PATH refresh above works inside THIS process, which is why `uv
# sync` above ran, but the window the script was started from still has its old
# copy of PATH. That cannot be fixed in code at all, so we say it outright.
# Measured on 2026-09-03 on a clean Windows 11 during the phase 1 UAT, test 2.
if ($uvInstalledInThisSession) {
    Write-Host ""
    Write-Host "NOTE: uv was installed during this run."
    Write-Host "Close this window and open a new one before running the commands above -"
    Write-Host "the current window still has the PATH from before the installation."
}
