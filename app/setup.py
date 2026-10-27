from setuptools import setup

APP = ["ip_menubar.py"]
DATA_FILES = []
OPTIONS = {
    "argv_emulation": False,
    "iconfile": "AppIcon.icns",
    "plist": {
        "LSUIElement": True,
        "CFBundleName": "IP Menubar",
        "CFBundleDisplayName": "IP Menubar",
        "CFBundleIdentifier": "com.local.ipmenubar",
        "CFBundleShortVersionString": "1.6.0",
        "CFBundleVersion": "10",
        "LSMinimumSystemVersion": "13.0",
    },
    "packages": ["rumps"],
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
)
