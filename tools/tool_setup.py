"""
Tool installation and binary setup helpers for discovery tooling.
"""
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from utils.ansi import CYAN, GREEN, YELLOW, RESET, RED


def _find_feroxbuster_binary() -> Optional[str]:
    """Find feroxbuster binary in common install locations."""
    candidates = [
        shutil.which('feroxbuster'),
        os.path.expanduser('~/.cargo/bin/feroxbuster'),
        os.path.expanduser('~/.local/bin/feroxbuster'),
        '/usr/local/bin/feroxbuster',
        '/opt/homebrew/bin/feroxbuster',
    ]

    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _find_katana_binary() -> Optional[str]:
    """Find katana binary in common install locations."""
    candidates = [
        shutil.which('katana'),
        os.path.expanduser('~/go/bin/katana'),
        '/usr/local/bin/katana',
    ]

    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _find_dirb_binary() -> Optional[str]:
    """Find dirb binary in common install locations."""
    candidates = [
        shutil.which('dirb'),
        '/usr/bin/dirb',
        '/usr/local/bin/dirb',
    ]

    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run_login_shell(command: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run command in login shell so Rust/Go env is loaded from shell profile."""
    return subprocess.run(
        f'bash -l -c "{command}"',
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def _install_katana() -> Optional[str]:
    """Install katana using Go toolchain as fallback endpoint discovery tool."""
    print(f"{YELLOW}[*] Attempting fallback installer: katana{RESET}")

    if not shutil.which('go'):
        print(f"{RED}[!] Go is not installed; cannot install katana automatically{RESET}")
        print(f"{YELLOW}[*] Install Go and run:{RESET}")
        print(f"{YELLOW}    CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest{RESET}\n")
        return None

    print(f"{CYAN}[*] Running: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest{RESET}")
    result = _run_login_shell(
        'CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest',
        timeout=420
    )

    if result.returncode != 0:
        stderr_tail = (result.stderr or '')[-500:]
        print(f"{RED}[!] katana installation failed{RESET}")
        if stderr_tail:
            print(f"{RED}Error: {stderr_tail}{RESET}\n")
        return None

    katana_path = _find_katana_binary()
    if katana_path:
        print(f"{GREEN}[+] katana installed successfully at {katana_path}{RESET}\n")
        return katana_path

    print(f"{YELLOW}[!] katana installation finished but binary not found in PATH{RESET}\n")
    return None


def _install_dirb() -> Optional[str]:
    """Install dirb as the final fallback endpoint discovery tool."""
    print(f"{YELLOW}[*] Attempting last-resort installer: dirb{RESET}")

    system = platform.system()
    try:
        if system == 'Darwin' and shutil.which('brew'):
            print(f"{CYAN}[*] Running: brew install dirb{RESET}")
            result = subprocess.run(['brew', 'install', 'dirb'], capture_output=True, text=True, timeout=240)
            if result.returncode == 0:
                return _find_dirb_binary()

        if system == 'Linux':
            if shutil.which('apt-get'):
                print(f"{CYAN}[*] Running: sudo apt-get install -y dirb{RESET}")
                result = subprocess.run(['sudo', 'apt-get', 'install', '-y', 'dirb'], capture_output=True, text=True, timeout=240)
                if result.returncode == 0:
                    return _find_dirb_binary()

            if shutil.which('dnf'):
                print(f"{CYAN}[*] Running: sudo dnf install -y dirb{RESET}")
                result = subprocess.run(['sudo', 'dnf', 'install', '-y', 'dirb'], capture_output=True, text=True, timeout=240)
                if result.returncode == 0:
                    return _find_dirb_binary()
    except Exception as error:
        print(f"{YELLOW}[!] dirb installation failed: {str(error)}{RESET}\n")

    return None


def _ensure_seclists_git_clone() -> Optional[str]:
    """Ensure SecLists is available via git clone and return best dirb wordlist path."""
    clone_dir = '/tmp/SecLists'
    candidate_wordlists = [
        os.path.join(clone_dir, 'Discovery', 'Web-Content', 'raft-medium-directories.txt'),
        os.path.join(clone_dir, 'Discovery', 'Web-Content', 'common.txt'),
    ]

    for candidate in candidate_wordlists:
        if os.path.exists(candidate):
            return candidate

    if not shutil.which('git'):
        print(f"{YELLOW}[!] git not available; cannot clone SecLists repository{RESET}")
        return None

    try:
        if not os.path.exists(clone_dir):
            print(f"{CYAN}[*] Cloning SecLists via git...{RESET}")
            print(f"{CYAN}[*] Running: git clone https://github.com/danielmiessler/SecLists.git {clone_dir}{RESET}")
            result = subprocess.run(
                ['git', 'clone', 'https://github.com/danielmiessler/SecLists.git', clone_dir],
                capture_output=True,
                text=True,
                timeout=240
            )
            if result.returncode != 0:
                print(f"{YELLOW}[!] SecLists clone failed{RESET}")
                return None
        else:
            subprocess.run(
                ['git', '-C', clone_dir, 'pull', '--ff-only'],
                capture_output=True,
                text=True,
                timeout=90
            )

        for candidate in candidate_wordlists:
            if os.path.exists(candidate):
                print(f"{GREEN}[+] Using SecLists wordlist: {candidate}{RESET}")
                return candidate
    except Exception as error:
        print(f"{YELLOW}[!] Unable to prepare SecLists clone: {str(error)}{RESET}")

    return None


def setup_wordlist() -> Optional[str]:
    """
    Ensure a wordlist is available for endpoint discovery.
    Returns path to wordlist or None if not found.
    Attempts to auto-install SecLists if not available.
    """
    wordlist_paths = [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/opt/seclists/Discovery/Web-Content/common.txt',
        '/opt/wordlists/directory-list-2.3-medium.txt',
    ]

    for path in wordlist_paths:
        if os.path.exists(path):
            print(f"{CYAN}[*] Found wordlist: {path}{RESET}")
            return path

    print(f"{YELLOW}[*] No wordlist found. Attempting to install SecLists...{RESET}")

    system = platform.system()
    try:
        if system == 'Darwin' and shutil.which('brew'):
            print(f"{CYAN}[*] Installing SecLists via Homebrew...{RESET}")
            result = subprocess.run(['brew', 'install', 'seclists'], capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                print(f"{GREEN}[+] SecLists installed!{RESET}")
                for path in wordlist_paths:
                    if os.path.exists(path):
                        return path

        elif system == 'Linux' and shutil.which('apt'):
            print(f"{CYAN}[*] Installing SecLists via apt...{RESET}")
            result = subprocess.run(['sudo', 'apt', 'install', '-y', 'seclists'], capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                print(f"{GREEN}[+] SecLists installed!{RESET}")
                for path in wordlist_paths:
                    if os.path.exists(path):
                        return path
    except Exception as error:
        print(f"{YELLOW}[*] SecLists auto-install failed: {str(error)}{RESET}")

    try:
        result = subprocess.run(['feroxbuster', '--help'], capture_output=True, text=True, timeout=5)
        if 'default' in result.stdout.lower():
            print(f"{CYAN}[*] Using feroxbuster default wordlist{RESET}")
            return None
    except Exception:
        pass

    print(f"{YELLOW}[!] No wordlist found. Using feroxbuster default (less accurate){RESET}")
    print(f"{YELLOW}[*] For better results, install SecLists:{RESET}")
    print(f"{YELLOW}    macOS: brew install seclists{RESET}")
    print(f"{YELLOW}    Linux: apt install seclists{RESET}\n")
    return None


def _ensure_fallback_wordlist() -> str:
    """Create a minimal local wordlist so scanners never depend on missing system defaults."""
    fallback_path = '/tmp/yaap_ferox_wordlist.txt'
    if os.path.exists(fallback_path):
        return fallback_path

    default_entries = [
        'admin',
        'login',
        'logout',
        'search',
        'api',
        'assets',
        'static',
        'js',
        'css',
        'images',
        'uploads',
        'dashboard',
        'user',
        'users',
        'profile',
        'account',
        'config',
        'health',
        'status',
        'robots.txt',
        'sitemap.xml',
    ]

    with open(fallback_path, 'w') as handle:
        handle.write('\n'.join(default_entries) + '\n')

    return fallback_path


def _repair_rust_toolchain() -> bool:
    """Attempt full rustup recovery for broken/partial stable toolchain installs."""
    print(f"{YELLOW}[*] Attempting deep Rust toolchain repair...{RESET}")

    commands = [
        'rustup self update || true',
        'rustup toolchain uninstall stable-x86_64-unknown-linux-gnu || true',
        'rustup toolchain install stable-x86_64-unknown-linux-gnu --profile minimal',
        'rustup default stable-x86_64-unknown-linux-gnu',
        'rustup show'
    ]

    for command in commands:
        print(f"{CYAN}[*] Running: {command}{RESET}")
        result = _run_login_shell(command, timeout=300)
        if result.returncode != 0 and '|| true' not in command:
            stderr_tail = (result.stderr or '')[-400:]
            print(f"{RED}[!] Rust repair step failed: {stderr_tail}{RESET}")
            return False

    print(f"{GREEN}[+] Rust toolchain repair completed{RESET}\n")
    return True


def _install_feroxbuster_prebuilt_binary() -> Optional[str]:
    """Install feroxbuster from latest GitHub prebuilt release binary (Rust-independent fallback)."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system != 'linux':
        return None

    arch_tokens = {
        'x86_64': ['x86_64', 'amd64'],
        'amd64': ['x86_64', 'amd64'],
        'aarch64': ['aarch64', 'arm64'],
        'arm64': ['aarch64', 'arm64'],
    }
    selected_arch_tokens = arch_tokens.get(machine, [machine])

    print(f"{CYAN}[*] Attempting prebuilt feroxbuster binary install from GitHub releases...{RESET}")
    print(f"{CYAN}[*] Detected platform: {system}/{machine}{RESET}")

    try:
        api_url = 'https://api.github.com/repos/epi052/feroxbuster/releases/latest'
        request = Request(api_url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'yaap-installer'})
        with urlopen(request, timeout=30) as response:
            release_data = json.loads(response.read().decode('utf-8'))

        assets = release_data.get('assets', [])
        selected_asset = None

        for asset in assets:
            name = asset.get('name', '').lower()
            if not name:
                continue
            if any(bad in name for bad in ['.deb', '.rpm', '.sha256', 'checksums', 'sbom']):
                continue
            if not (name.endswith('.tar.gz') or name.endswith('.tgz') or name.endswith('.zip')):
                continue
            if 'linux' not in name and 'unknown-linux' not in name:
                continue
            if not any(token in name for token in selected_arch_tokens):
                continue

            selected_asset = asset
            break

        if not selected_asset:
            print(f"{YELLOW}[!] No matching prebuilt asset found for {system}/{machine}{RESET}\n")
            return None

        download_url = selected_asset.get('browser_download_url')
        asset_name = selected_asset.get('name')
        print(f"{CYAN}[*] Downloading asset: {asset_name}{RESET}")

        with tempfile.TemporaryDirectory(prefix='ferox-prebuilt-') as temp_dir:
            archive_path = os.path.join(temp_dir, asset_name)
            with urlopen(download_url, timeout=60) as response, open(archive_path, 'wb') as out_file:
                out_file.write(response.read())

            extract_dir = os.path.join(temp_dir, 'extract')
            os.makedirs(extract_dir, exist_ok=True)

            if asset_name.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(extract_dir)
            elif asset_name.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    zf.extractall(extract_dir)
            else:
                return None

            ferox_source = None
            for root, _, files in os.walk(extract_dir):
                for file_name in files:
                    if file_name == 'feroxbuster':
                        candidate = os.path.join(root, file_name)
                        if os.path.isfile(candidate):
                            ferox_source = candidate
                            break
                if ferox_source:
                    break

            if not ferox_source:
                print(f"{YELLOW}[!] Prebuilt archive did not contain feroxbuster binary{RESET}\n")
                return None

            final_path = '/tmp/feroxbuster-prebuilt'
            shutil.copy2(ferox_source, final_path)
            os.chmod(final_path, os.stat(final_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            print(f"{GREEN}[+] Installed prebuilt feroxbuster binary at {final_path}{RESET}")
            return final_path

    except URLError as error:
        print(f"{YELLOW}[!] Failed to fetch GitHub release data: {str(error)}{RESET}\n")
        return None
    except Exception as error:
        print(f"{YELLOW}[!] Prebuilt binary install failed: {str(error)}{RESET}\n")
        return None


def auto_install_feroxbuster() -> Optional[str]:
    """
    Automatically install feroxbuster if not already installed.
    Detects OS and uses git clone + cargo build (preferred method).
    Fallback to package managers if git/cargo not available.
    Returns the path to feroxbuster if successful, None otherwise.
    """
    ferox_path = _find_feroxbuster_binary()
    if ferox_path:
        print(f"{GREEN}[+] feroxbuster is already installed at {ferox_path}{RESET}")
        return ferox_path

    print(f"{YELLOW}[*] feroxbuster not found in PATH{RESET}")
    print(f"{YELLOW}[*] Detecting operating system...{RESET}\n")

    system = platform.system()
    print(f"{CYAN}[*] Operating System: {system}{RESET}\n")

    try:
        has_git = shutil.which('git') is not None
        has_cargo = shutil.which('cargo') is not None or os.path.exists(os.path.expanduser('~/.cargo/bin/cargo'))

        print(f"{CYAN}[*] Checking dependencies:{RESET}")
        print(f"    git: {'[OK]' if has_git else '[MISSING]'}")
        print(f"    cargo: {'[OK]' if has_cargo else '[MISSING]'}")
        print()

        if has_git and has_cargo:
            print(f"{CYAN}[*] PRIMARY METHOD: Git clone + Cargo build{RESET}\n")
            result = _install_feroxbuster_from_git(system)
            if result:
                return result
            print(f"{YELLOW}[*] Git clone method failed, trying fallback...{RESET}\n")

        if not has_cargo:
            print(f"{YELLOW}[*] Installing Rust/Cargo (required for compilation)...{RESET}")
            print(f"{CYAN}[*] Running: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh{RESET}\n")
            result = subprocess.run(
                'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                print(f"{GREEN}[+] Rust installed successfully!{RESET}\n")
                cargo_path = os.path.expanduser('~/.cargo/bin')
                os.environ['PATH'] = f"{cargo_path}:{os.environ.get('PATH', '')}"
                time.sleep(2)

                print(f"{CYAN}[*] Initializing Rust toolchain...{RESET}")
                result = _run_login_shell('rustup default stable && rustup show', timeout=120)

                if result.returncode == 0:
                    print(f"{GREEN}[+] Rust toolchain initialized{RESET}")
                    print(f"    Info: {result.stdout.split(chr(10))[0] if result.stdout else 'OK'}\n")
                else:
                    print(f"{YELLOW}[!] Toolchain init had issues but continuing: {result.stderr[:200]}{RESET}\n")

                if shutil.which('git'):
                    print(f"{CYAN}[*] Retrying git clone + Cargo build...{RESET}\n")
                    result = _install_feroxbuster_from_git(system)
                    if result:
                        return result

                prebuilt = _install_feroxbuster_prebuilt_binary()
                if prebuilt:
                    return prebuilt
            else:
                print(f"{RED}[!] Rust installation failed{RESET}\n")
                prebuilt = _install_feroxbuster_prebuilt_binary()
                if prebuilt:
                    return prebuilt

        if system == 'Darwin':
            return _install_feroxbuster_macos()
        elif system == 'Linux':
            return _install_feroxbuster_linux()
        elif system == 'Windows':
            return _install_feroxbuster_windows()
        else:
            print(f"{RED}[!] Unsupported OS: {system}{RESET}")
            print(f"{YELLOW}[*] Install manually from: https://github.com/epi052/feroxbuster{RESET}\n")
            return None

    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Installation timed out - process took too long{RESET}")
        print(f"{YELLOW}[*] Try manual install in the background{RESET}\n")
        return None
    except Exception as error:
        print(f"{RED}[!] Auto-installation failed: {str(error)}{RESET}")
        print(f"{YELLOW}[*] Install from source: https://github.com/epi052/feroxbuster{RESET}\n")
        return None


def _install_feroxbuster_from_git(system: str) -> Optional[str]:
    """Install feroxbuster by cloning from GitHub and building with Cargo."""
    print(f"{CYAN}[*] PRIMARY METHOD: Git clone + Cargo build{RESET}")

    if not shutil.which('git'):
        print(f"{RED}[!] Git not found{RESET}")
        return None

    if not shutil.which('cargo') and not os.path.exists(os.path.expanduser('~/.cargo/bin/cargo')):
        print(f"{RED}[!] Cargo not found - install Rust:{RESET}")
        print(f"{YELLOW}    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh{RESET}\n")
        return None

    print(f"{CYAN}[*] Both git and cargo available - proceeding with git clone method{RESET}\n")

    clone_dir = '/tmp/feroxbuster-build'
    if os.path.exists(clone_dir):
        print(f"{CYAN}[*] Removing existing clone directory...{RESET}")
        import shutil as sh
        sh.rmtree(clone_dir, ignore_errors=True)

    print(f"{CYAN}[*] Cloning feroxbuster from GitHub...{RESET}")
    print(f"{CYAN}[*] Running: git clone https://github.com/epi052/feroxbuster.git {clone_dir}{RESET}")

    result = subprocess.run(
        ['git', 'clone', 'https://github.com/epi052/feroxbuster.git', clone_dir],
        capture_output=True,
        text=True,
        timeout=120
    )

    if result.returncode != 0:
        print(f"{RED}[!] Git clone failed{RESET}")
        if result.stderr:
            print(f"{RED}Error: {result.stderr[:300]}{RESET}")
        return None

    print(f"{GREEN}[+] Repository cloned successfully{RESET}\n")

    print(f"{CYAN}[*] Building feroxbuster with Cargo...{RESET}")
    print(f"{CYAN}[*] Running: cargo build --release{RESET}")
    print(f"{YELLOW}[*] This may take 2-5 minutes...{RESET}\n")

    build_cmd = f'cd {clone_dir} && cargo build --release'
    result = _run_login_shell(build_cmd, timeout=600)

    if result.returncode != 0:
        print(f"{RED}[!] Build failed{RESET}")
        if result.stderr:
            stderr_msg = result.stderr[-500:]
            print(f"{RED}Error: {stderr_msg}{RESET}")

            if 'Missing manifest in toolchain' in stderr_msg or 'not installed for' in stderr_msg:
                print(f"\n{YELLOW}[*] Detected Rust toolchain issue - attempting recovery...{RESET}")
                print(f"{CYAN}[*] Running: rustup update stable{RESET}\n")

                recover = _run_login_shell('rustup update stable', timeout=300)

                if recover.returncode == 0:
                    print(f"{GREEN}[+] Rust updated{RESET}")
                    print(f"{CYAN}[*] Verifying Rust toolchain...{RESET}")
                    verify = _run_login_shell('rustup default stable && rustup show', timeout=60)

                    if verify.returncode == 0:
                        print(f"{GREEN}[+] Toolchain verified{RESET}\n")
                    else:
                        print(f"{YELLOW}[!] Toolchain verification warning{RESET}\n")
                        deep_repair_ok = _repair_rust_toolchain()
                        if not deep_repair_ok:
                            print(f"{YELLOW}[*] Deep repair failed; trying Rust-independent fallback...{RESET}")
                            prebuilt = _install_feroxbuster_prebuilt_binary()
                            if prebuilt:
                                return prebuilt

                    print(f"{CYAN}[*] Retrying build...{RESET}\n")
                    result = _run_login_shell(build_cmd, timeout=600)
                    if result.returncode == 0:
                        print(f"{GREEN}[+] Build completed successfully after recovery!{RESET}\n")
                        binary_path = f'{clone_dir}/target/release/feroxbuster'
                        if os.path.exists(binary_path):
                            return binary_path
                    else:
                        print(f"{RED}[!] Retry build also failed{RESET}")
                        if result.stderr:
                            print(f"{RED}Error (retry): {result.stderr[-600:]}{RESET}\n")

                        print(f"{YELLOW}[*] Attempting alternative: cargo install feroxbuster (2-3 min)...{RESET}\n")
                        cargo_install = _run_login_shell('cargo install feroxbuster', timeout=600)
                        if cargo_install.returncode == 0:
                            time.sleep(1)
                            ferox_path = _find_feroxbuster_binary()
                            if ferox_path:
                                print(f"{GREEN}[+] feroxbuster installed via cargo install at {ferox_path}{RESET}\n")
                                return ferox_path
                        else:
                            print(f"{RED}[!] cargo install also failed{RESET}")
                            if cargo_install.stderr:
                                print(f"{RED}Error (cargo install): {cargo_install.stderr[-600:]}{RESET}\n")

                            prebuilt = _install_feroxbuster_prebuilt_binary()
                            if prebuilt:
                                return prebuilt
                else:
                    print(f"{RED}[!] Rust recovery failed (rustup update failed){RESET}\n")
                    if _repair_rust_toolchain():
                        result = _run_login_shell(build_cmd, timeout=600)
                        if result.returncode == 0:
                            binary_path = f'{clone_dir}/target/release/feroxbuster'
                            if os.path.exists(binary_path):
                                print(f"{GREEN}[+] Build completed successfully after deep repair!{RESET}\n")
                                return binary_path

                    prebuilt = _install_feroxbuster_prebuilt_binary()
                    if prebuilt:
                        return prebuilt
        return None

    print(f"{GREEN}[+] Build completed successfully!{RESET}\n")

    binary_path = f'{clone_dir}/target/release/feroxbuster'
    if not os.path.exists(binary_path):
        print(f"{RED}[!] Binary not found at {binary_path}{RESET}")
        return None

    print(f"{GREEN}[+] feroxbuster binary found at: {binary_path}{RESET}\n")
    print(f"{CYAN}[*] To use feroxbuster globally, install to system PATH:{RESET}")
    print(f"{CYAN}    sudo cp {binary_path} /usr/local/bin/feroxbuster{RESET}")
    print(f"{CYAN}    sudo chmod +x /usr/local/bin/feroxbuster{RESET}\n")

    return binary_path


def _install_feroxbuster_macos() -> Optional[str]:
    """Install feroxbuster on macOS via Homebrew."""
    print(f"{CYAN}[*] FALLBACK: macOS - attempting Homebrew installation...{RESET}")

    if not shutil.which('brew'):
        print(f"{RED}[!] Homebrew not found - required for macOS installation{RESET}")
        print(f"{YELLOW}[*] Install Homebrew first: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"{RESET}\n")
        return None

    print(f"{CYAN}[*] Running: brew install feroxbuster{RESET}")
    result = subprocess.run(['brew', 'install', 'feroxbuster'], capture_output=True, text=True, timeout=180)

    if result.returncode == 0:
        time.sleep(2)
        ferox_path = shutil.which('feroxbuster')
        if ferox_path:
            print(f"{GREEN}[+] feroxbuster installed successfully at {ferox_path}!{RESET}\n")
            return ferox_path
        print(f"{YELLOW}[!] Installation completed but feroxbuster not in PATH{RESET}\n")
        return None

    print(f"{RED}[!] Homebrew installation failed{RESET}")
    if result.stderr:
        print(f"{RED}Error: {result.stderr[:200]}{RESET}")
    print(f"{YELLOW}[*] Try git clone method:{RESET}")
    print(f"{YELLOW}    git clone https://github.com/epi052/feroxbuster.git{RESET}")
    print(f"{YELLOW}    cd feroxbuster && cargo build --release{RESET}\n")
    return None


def _install_feroxbuster_linux() -> Optional[str]:
    """Install feroxbuster on Linux (Ubuntu/Debian/Fedora/Termux)."""
    print(f"{CYAN}[*] FALLBACK: Linux - attempting package manager installation...{RESET}\n")

    is_termux = os.path.exists('/system/build.prop') or 'TERMUX' in os.environ.get('PATH', '')
    if is_termux:
        print(f"{CYAN}[*] Termux environment detected{RESET}\n")
        print(f"{CYAN}[*] Running: pkg update && pkg upgrade -y{RESET}")
        result = subprocess.run(['pkg', 'update'], capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            print(f"{YELLOW}[!] pkg update failed{RESET}")

        result = subprocess.run(['pkg', 'upgrade', '-y'], capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            print(f"{YELLOW}[!] pkg upgrade failed{RESET}")

        print(f"{CYAN}[*] Installing dependencies: git clang make cmake pkg-config python rust{RESET}")
        result = subprocess.run(
            ['pkg', 'install', '-y', 'git', 'clang', 'make', 'cmake', 'pkg-config', 'python', 'rust'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            print(f"{GREEN}[+] Dependencies installed{RESET}\n")
            return _install_feroxbuster_from_git('Linux')
        print(f"{RED}[!] Dependency installation failed{RESET}\n")
        return None

    if shutil.which('apt-get'):
        print(f"{CYAN}[*] Attempting installation via apt-get...{RESET}")
        print(f"{CYAN}[*] Running: sudo apt-get install -y feroxbuster{RESET}")
        result = subprocess.run(['sudo', 'apt-get', 'install', '-y', 'feroxbuster'], capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            time.sleep(2)
            ferox_path = shutil.which('feroxbuster')
            if ferox_path:
                print(f"{GREEN}[+] feroxbuster installed successfully at {ferox_path}!{RESET}\n")
                return ferox_path
        else:
            print(f"{RED}[!] apt-get installation failed{RESET}\n")

    if shutil.which('dnf'):
        print(f"{CYAN}[*] Attempting installation via dnf...{RESET}")
        print(f"{CYAN}[*] Running: sudo dnf install -y feroxbuster{RESET}")
        result = subprocess.run(['sudo', 'dnf', 'install', '-y', 'feroxbuster'], capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            time.sleep(2)
            ferox_path = shutil.which('feroxbuster')
            if ferox_path:
                print(f"{GREEN}[+] feroxbuster installed successfully at {ferox_path}!{RESET}\n")
                return ferox_path
        else:
            print(f"{RED}[!] dnf installation failed{RESET}\n")

    print(f"{YELLOW}[*] Package manager installation failed or not available{RESET}\n")
    prebuilt = _install_feroxbuster_prebuilt_binary()
    if prebuilt:
        return prebuilt

    print(f"{YELLOW}[*] Attempting git clone + Cargo build method...{RESET}\n")
    has_git = shutil.which('git') is not None
    has_cargo = shutil.which('cargo') is not None or os.path.exists(os.path.expanduser('~/.cargo/bin/cargo'))

    if has_git and has_cargo:
        print(f"{CYAN}[*] git and cargo available - attempting build{RESET}\n")
        return _install_feroxbuster_from_git('Linux')

    if not has_cargo:
        print(f"{YELLOW}[*] Installing Rust/Cargo...{RESET}")
        print(f"{CYAN}[*] Running: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y{RESET}\n")
        result = subprocess.run(
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            print(f"{GREEN}[+] Rust installed successfully!{RESET}\n")
            os.environ['PATH'] = f"{os.path.expanduser('~/.cargo/bin')}:{os.environ.get('PATH', '')}"
            _repair_rust_toolchain()

            if shutil.which('git'):
                print(f"{CYAN}[*] Retrying git clone + Cargo build...{RESET}\n")
                return _install_feroxbuster_from_git('Linux')
            print(f"{RED}[!] git is required but not found{RESET}\n")
            return _install_feroxbuster_prebuilt_binary()

        print(f"{RED}[!] Rust installation failed{RESET}\n")
        if result.stderr:
            print(f"{RED}    Error: {result.stderr[:300]}{RESET}\n")
        return _install_feroxbuster_prebuilt_binary()

    if not has_git:
        print(f"{RED}[!] git is required but not found{RESET}")
        print(f"{YELLOW}[*] Install git:{RESET}")
        print(f"{YELLOW}    Ubuntu/Debian: sudo apt-get install -y git{RESET}")
        print(f"{YELLOW}    Fedora/RHEL:  sudo dnf install -y git{RESET}\n")
        return None

    return None


def _install_feroxbuster_windows() -> Optional[str]:
    """Install feroxbuster on Windows."""
    print(f"{CYAN}[*] FALLBACK: Windows - attempting Cargo installation...{RESET}")

    if not shutil.which('cargo'):
        print(f"{RED}[!] Cargo not found - install Rust from https://rustup.rs/{RESET}\n")
        return None

    print(f"{CYAN}[*] Running: cargo install feroxbuster{RESET}")
    result = subprocess.run(['cargo', 'install', 'feroxbuster'], capture_output=True, text=True, timeout=300)

    if result.returncode == 0:
        ferox_path = shutil.which('feroxbuster')
        if ferox_path:
            print(f"{GREEN}[+] feroxbuster installed successfully at {ferox_path}!{RESET}\n")
            return ferox_path

    print(f"{RED}[!] Windows installation failed{RESET}")
    print(f"{YELLOW}[*] Try git clone + build:{RESET}")
    print(f"{YELLOW}    git clone https://github.com/epi052/feroxbuster.git{RESET}")
    print(f"{YELLOW}    cd feroxbuster && cargo build --release{RESET}\n")
    return None
