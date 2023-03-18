from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files('spdx_matcher', excludes=['_pyinstaller'])
