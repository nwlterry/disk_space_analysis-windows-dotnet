# Disk space analysis for Windows (.NET)

Scan a folder, a volume, or a UNC path on Windows Server 2016 and later. Same reports as the PowerShell scanner: folder tree, largest files, file types, age, duplicates, and what changed between two scans.

`SizeTree.exe` in the beta release is a self-contained single file for Windows x64. It does not need a .NET install. Copy it to the server and run it.

```powershell
.\SizeTree.exe scan --path D:\ --out C:\SizeTreeReports --duplicates --hash --allocated
.\SizeTree.exe compare --before C:\SizeTreeReports\older-folders.csv --after C:\SizeTreeReports\latest-folders.csv --out C:\SizeTreeReports\compare
```

`-allocated` reads real NTFS allocation, including compressed and sparse files. It is slower because every file is opened for attributes.

Each age group in `latest.json` includes up to 40 of the largest files in that age. The SizeTree viewer lists them when you click the age. The same rows are in `latest-age-files.csv`.

## Build it yourself

.NET 8 SDK. Framework-dependent (the server must have the .NET 8 runtime):

```powershell
dotnet publish .\SizeTree.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o .\publish
```

Portable, no runtime install:

```powershell
dotnet publish .\SizeTree.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o .\publish
```

## Scan options

```text
SizeTree scan --path D:\ --out C:\SizeTreeReports --duplicates --hash --allocated

  --path <dir>            Folder, volume, or UNC path
  --out <dir>             Report folder (default SizeTreeReports)
  --top-files <n>         Largest files kept (default 200)
  --top-folders <n>       Largest folders kept in JSON (default 500)
  --depth <n>             Directory levels to descend (0 = all)
  --export-depth <n>      JSON tree depth (default 6)
  --max-children <n>      Children kept per JSON folder (default 40)
  --duplicates            Group files with the same size
  --hash                  Confirm duplicates with SHA-256
  --min-dup-bytes <n>     Minimum size for duplicate tracking (default 50MB, floor 256KB)
  --allocated             Read NTFS allocated size (slower)
  --exclude <pattern>     Name or wildcard. Repeat, or separate with semicolons
```

`--depth 3` stops after three levels. Totals then exclude anything deeper.

## Reports

| File | What it is |
|---|---|
| `latest.json` | Viewer report. Tree depth is capped. Totals still include everything scanned. |
| `latest-folders.csv` | Every folder. This is what compare uses. |
| `latest-files.csv` | Largest files on the volume. |
| `latest-extensions.csv` | Space by extension. |
| `latest-ages.csv` | Space by last-write age. |
| `latest-age-files.csv` | Largest files in each age (up to 40 per bucket). |
| `latest-duplicates.csv` | Same-size or SHA-256 groups. |
| `latest-errors.csv` | Access denied and skipped junctions. |
| `latest.html` | Printable summary, including files by age. |

Junctions and symlinks are not followed. A size match is not proof the bytes match. Add `--hash` for SHA-256.

```powershell
.\SizeTree.exe scan --path D:\Shares --exclude "node_modules;*.tmp"
```

The PowerShell 5.1 scanner is [disk_space_analysis-windows-ps](https://github.com/nwlterry/disk_space_analysis-windows-ps).
