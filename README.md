# Disk space analysis for Windows (.NET)

Scan one or more folders, volumes, or UNC paths on Windows Server 2016 and later. Same reports as the PowerShell scanner: folder tree, largest files, file types, age, duplicates, and what changed between two scans.

`SizeTree.exe` in the release is a self-contained single file for Windows x64. It does not need a .NET install. Copy it to the server and run it. The offline viewer is embedded in the executable.

```powershell
.\SizeTree.exe scan --path D:\ --path E:\Data --out C:\SizeTreeReports --duplicates --hash --allocated
.\SizeTree.exe compare --before C:\SizeTreeReports\older-folders.csv --after C:\SizeTreeReports\latest-folders.csv --out C:\SizeTreeReports\compare
```

Repeat `--path` for each directory, or separate paths in one value with a semicolon. One path still works. Several paths are drawn as one map, with a button for each path.

`--allocated` reads real NTFS allocation, including compressed and sparse files. It is slower because every file is opened for attributes.

`latest.html` is the same tabbed screen as the viewer, with the scan embedded, so it opens from disk with no network. Each age group in `latest.json` includes up to 40 of the largest files in that age. Click the age to list them. The same rows are in `latest-age-files.csv`. Each file type does the same. Click the type to list its largest files. Those rows are in `latest-extension-files.csv`.

## Build it yourself

.NET 8 SDK. `viewer.html` must sit next to `SizeTree.csproj` so the offline page is embedded.

Framework-dependent (the server must have the .NET 8 runtime):

```powershell
dotnet publish .\SizeTree.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o .\publish
```

Portable, no runtime install:

```powershell
dotnet publish .\SizeTree.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o .\publish
```

## Scan options

```text
SizeTree scan --path D:\ --path E:\Data --out C:\SizeTreeReports --duplicates --hash --allocated

  --path <dir>            Folder, volume, or UNC path. Repeat for more than one.
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
  --quiet
```

Junctions and symlinks are not followed. A size match is not proof the bytes match. Add `--hash` for SHA-256.
