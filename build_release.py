"""
build_release.py — Compila y empaqueta WinVulnScanner sin archivos sensibles.
Uso: python build_release.py
"""
import subprocess
import sys
import zipfile
from pathlib import Path

DIST_DIR    = Path("dist/WinVulnScanner")
OUTPUT_ZIP  = Path("WinVulnScanner-v1.0.zip")

# Archivos y extensiones que nunca deben incluirse en el ZIP
EXCLUDE_FILES = {
    "scan_history.json",
    "audit.log",
    "fix_history.jsonl",
}
EXCLUDE_SUFFIXES = {".log", ".json"}
EXCLUDE_DIRS = {"reports"}


def compile_exe():
    print("[1/3] Compilando con PyInstaller...")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--clean", "-y", "WinVulnScanner.spec"],
        capture_output=False,
    )
    if result.returncode != 0:
        print("ERROR: PyInstaller falló.")
        sys.exit(1)
    print("      Compilación completada.")


def clean_dist():
    """Elimina archivos sensibles del directorio dist antes de empaquetar."""
    print("[2/3] Limpiando archivos sensibles de dist...")
    removed = []
    for f in DIST_DIR.rglob("*"):
        if not f.is_file():
            continue
        if (f.name in EXCLUDE_FILES or
                f.suffix in EXCLUDE_SUFFIXES or
                any(part in EXCLUDE_DIRS for part in f.parts)):
            f.unlink()
            removed.append(f.name)
    if removed:
        print(f"      Eliminados: {', '.join(removed)}")
    else:
        print("      Sin archivos sensibles encontrados.")


def create_zip():
    print(f"[3/3] Creando {OUTPUT_ZIP}...")
    OUTPUT_ZIP.unlink(missing_ok=True)
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(DIST_DIR.rglob("*")):
            if not f.is_file():
                continue
            arcname = f.relative_to(DIST_DIR)
            zf.write(f, arcname)
    size_mb = OUTPUT_ZIP.stat().st_size / 1_048_576
    print(f"      {OUTPUT_ZIP} ({size_mb:.1f} MB) listo.")


if __name__ == "__main__":
    compile_exe()
    clean_dist()
    create_zip()
    print("\nPortable listo para publicar.")
