@echo off
echo === Bug Bounty Hunter - GitHub Push ===
cd /d "%~dp0"

:: GUVENLIK: token ARTIK GOMULU DEGIL. Git kimlik dogrulamayi kendisi sorar
:: (Git Credential Manager) ya da onceden `git config` ile ayarlarsin.
:: .env ve hassas dosyalar .gitignore ile HARIC tutulur.

if not exist ".gitignore" (
    echo [HATA] .gitignore yok! .env sizabilir. Once .gitignore ekle.
    pause
    exit /b 1
)

git init
git config user.email "mykokko5561@gmail.com"
git config user.name "mykokko5561"
git branch -m main
git add .
git status
echo.
echo === Yukaridaki listede .env GORUNMEMELI ===
echo Devam etmek icin bir tusa bas (Ctrl+C ile iptal)...
pause >nul
git commit -m "Bug Bounty Hunter update"

:: Remote'u bir kez ayarla (token gommeden). Git push sirasinda kullanici
:: adi + PAT'i (parola yerine) sorar; Credential Manager bir daha sormamak
:: uzere saklar.
git remote get-url origin >nul 2>&1 || git remote add origin https://github.com/mykokko5561/bug-bountyhunter.git

git push -u origin main

echo.
echo === Push tamamlandi! ===
pause
