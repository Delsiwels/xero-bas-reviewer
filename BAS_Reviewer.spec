# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['bas_reviewer_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('gl_parser.py', '.'), ('gl_prompts.py', '.'), ('deepseek_client.py', '.'), ('output_generator.py', '.'), ('prompts.py', '.')],
    hiddenimports=['pandas', 'openpyxl', 'requests'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='BAS_Reviewer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
app = BUNDLE(
    exe,
    name='BAS_Reviewer.app',
    icon=None,
    bundle_identifier=None,
)
