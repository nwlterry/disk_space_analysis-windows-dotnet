using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

var jsonOptions = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = true
};

try
{
    return Run(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

int Run(string[] argv)
{
    if (argv.Length == 0 || argv.Contains("--help") || argv.Contains("-h"))
    {
        PrintHelp();
        return argv.Length == 0 ? 2 : 0;
    }

    var command = "scan";
    var rest = argv;
    if (!argv[0].StartsWith("--", StringComparison.Ordinal))
    {
        command = argv[0].ToLowerInvariant();
        rest = argv.Skip(1).ToArray();
    }

    var opts = ParseOptions(rest);
    return command switch
    {
        "scan" => Scan(opts),
        "compare" => Compare(opts),
        _ => throw new InvalidOperationException("Unknown command. Use: disk-space-analysis scan | compare")
    };
}

Dictionary<string, List<string>> ParseOptions(string[] argv)
{
    var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < argv.Length; i++)
    {
        var arg = argv[i];
        if (!arg.StartsWith("--", StringComparison.Ordinal) || arg.Length < 3)
            throw new InvalidOperationException("Unexpected argument: " + arg);
        var key = arg[2..];
        var value = "true";
        if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--", StringComparison.Ordinal))
            value = argv[++i];
        if (!map.TryGetValue(key, out var list))
            map[key] = list = [];
        list.Add(value);
    }
    return map;
}

string? Opt(Dictionary<string, List<string>> opts, string key) =>
    opts.TryGetValue(key, out var list) ? list[^1] : null;

bool Flag(Dictionary<string, List<string>> opts, string key) =>
    opts.TryGetValue(key, out var list) && list[^1] != "false";

int Scan(Dictionary<string, List<string>> opts)
{
    if (!opts.TryGetValue("path", out var pathArgs) || pathArgs.Count == 0)
        throw new InvalidOperationException("scan requires --path <directory>. Repeat --path for more than one.");
    var outDir = Opt(opts, "out") ?? "disk-space-analysis-reports";
    var topFiles = Math.Max(1, ParseInt(Opt(opts, "top-files"), 200));
    var topFolders = Math.Max(1, ParseInt(Opt(opts, "top-folders"), 500));
    var depth = ParseInt(Opt(opts, "depth"), 0);
    var exportDepth = Math.Max(1, ParseInt(Opt(opts, "export-depth"), 6));
    var maxChildren = Math.Max(1, ParseInt(Opt(opts, "max-children"), 40));
    var duplicates = Flag(opts, "duplicates") || Flag(opts, "hash");
    var hash = Flag(opts, "hash");
    var allocated = Flag(opts, "allocated");
    var quiet = Flag(opts, "quiet");
    var minDup = ParseLong(Opt(opts, "min-dup-bytes"), 50L * 1024 * 1024);
    if (minDup < 256 * 1024) minDup = 256 * 1024;
    var exclude = SplitPatterns(opts);
    var state = new ScanState(topFiles, topFolders, duplicates, minDup);
    var started = System.Diagnostics.Stopwatch.StartNew();

    void Walk(FolderNode walkRoot, DirectoryInfo walkInfo)
    {
    var stack = new Stack<(FolderNode Node, DirectoryInfo Info)>();
    stack.Push((walkRoot, walkInfo));
    var enumOptions = new EnumerationOptions
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false
    };

    while (stack.Count > 0)
    {
        var (node, info) = stack.Pop();
        try
        {
            foreach (var file in info.EnumerateFiles("*", enumOptions))
            {
                state.FilesSeen++;
                if (!quiet && state.FilesSeen % 20000 == 0)
                    Console.WriteLine($"{state.FilesSeen:n0} files  {node.Path}");
                try
                {
                    var display = DisplayPath(file.FullName);
                    if (IsExcluded(display, file.Name, exclude)) continue;
                    var logical = file.Length;
                    var alloc = allocated ? AllocationOf(display, logical) : logical;
                    node.DirectLogical += logical;
                    node.DirectAllocated += alloc;
                    node.DirectFiles++;
                    var ext = string.IsNullOrEmpty(file.Extension) ? "(none)" : file.Extension.ToLowerInvariant();
                    AddExt(state, ext, logical, alloc);
                    string modified = "";
                    string bucket = "";
                    try
                    {
                        var utc = file.LastWriteTimeUtc;
                        modified = utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
                        bucket = AgeBucket(utc);
                        AddAge(state, bucket, logical, alloc);
                    }
                    catch
                    {
                        modified = "";
                    }
                    if (logical > 0)
                    {
                        var row = new FileRow
                        {
                            Path = display,
                            Name = file.Name,
                            Extension = ext,
                            LogicalBytes = logical,
                            AllocatedBytes = alloc,
                            ModifiedUtc = modified
                        };
                        state.ConsiderFile(row);
                        if (bucket.Length > 0) state.ConsiderAgeFile(bucket, row);
                        state.ConsiderExtFile(ext, row);
                    }
                    if (duplicates && logical >= minDup)
                        state.AddDup(logical, display);
                }
                catch (Exception ex)
                {
                    state.AddError(file.Name, ex.Message, reparse: false);
                }
            }
        }
        catch (Exception ex)
        {
            state.AddError(node.Path, ex.Message, reparse: false);
        }

        if (depth > 0 && node.Depth >= depth) continue;
        try
        {
            foreach (var dir in info.EnumerateDirectories("*", enumOptions))
            {
                try
                {
                    var display = DisplayPath(dir.FullName);
                    if (IsExcluded(display, dir.Name, exclude)) continue;
                    if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        state.AddError(display, "Reparse point skipped (junction or symlink).", reparse: true);
                        continue;
                    }
                    var child = new FolderNode { Name = dir.Name, Path = display, Depth = node.Depth + 1 };
                    node.Children.Add(child);
                    var next = display.Length >= 240 ? new DirectoryInfo(ToLongPath(display)) : dir;
                    stack.Push((child, next));
                }
                catch (Exception ex)
                {
                    state.AddError(dir.Name, ex.Message, reparse: false);
                }
            }
        }
        catch (Exception ex)
        {
            state.AddError(node.Path, ex.Message, reparse: false);
        }
    }
    }

    var requested = ExpandPaths(pathArgs);
    if (requested.Count == 0)
        throw new InvalidOperationException("scan requires --path <directory>. Repeat --path for more than one.");
    var scanned = new List<FolderNode>();
    var fullPaths = new List<string>();
    foreach (var requestedPath in requested)
    {
        string fullRoot;
        try { fullRoot = Path.GetFullPath(requestedPath); }
        catch
        {
            Console.Error.WriteLine("Path is not valid: " + requestedPath);
            return 2;
        }
        var rootInfo = new DirectoryInfo(fullRoot.Length >= 240 ? ToLongPath(fullRoot) : fullRoot);
        if (!rootInfo.Exists)
        {
            Console.Error.WriteLine("Path not found or not a directory: " + fullRoot);
            return 2;
        }
        var rootName = fullRoot.Length <= 3 ? fullRoot : new DirectoryInfo(fullRoot).Name;
        var scannedRoot = new FolderNode { Name = rootName, Path = fullRoot, Depth = 0 };
        if (!quiet) Console.WriteLine("Scanning " + fullRoot);
        Walk(scannedRoot, rootInfo);
        scanned.Add(scannedRoot);
        fullPaths.Add(fullRoot);
    }

    FolderNode root;
    if (scanned.Count == 1)
    {
        root = scanned[0];
    }
    else
    {
        root = new FolderNode { Name = "Scanned paths", Path = string.Join(" | ", fullPaths), Depth = 0 };
        foreach (var child in scanned)
        {
            ShiftDepth(child, 1);
            root.Children.Add(child);
        }
    }

    if (!quiet) Console.WriteLine("Rolling up folder sizes...");
    Rollup(root);
    var pending = new Stack<FolderNode>();
    pending.Push(root);
    while (pending.Count > 0)
    {
        var current = pending.Pop();
        if (current.Depth > 0 && current.LogicalBytes > 0) state.ConsiderFolder(current);
        foreach (var child in current.Children) pending.Push(child);
    }
    started.Stop();

    var dupRows = BuildDuplicates(state, hash);
    var report = new ScanReport
    {
        ScannedAt = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        Host = Environment.MachineName,
        Root = root.Path,
        Roots = fullPaths,
        ElapsedMs = (long)started.Elapsed.TotalMilliseconds,
        Summary = new Summary
        {
            LogicalBytes = root.LogicalBytes,
            AllocatedBytes = root.AllocatedBytes,
            FileCount = root.FileCount,
            FolderCount = root.FolderCount,
            DeniedCount = state.Denied,
            ReparseSkipped = state.Reparse,
            DuplicateGroups = dupRows.Count,
            DuplicateWasteBytes = dupRows.Sum(row => row.WasteBytes),
            AllocatedCollected = allocated
        },
        Tree = ExportNode(root, 0, scanned.Count > 1 ? exportDepth + 1 : exportDepth, maxChildren),
        LargestFolders = state.TopFolders().OrderByDescending(row => row.LogicalBytes).ToList(),
        LargestFiles = state.TopFiles().OrderByDescending(row => row.LogicalBytes).ToList(),
        Extensions = state.Extensions
            .Select(row =>
            {
                row.Files = state.TakeExtFiles(row.Extension);
                return row;
            })
            .OrderByDescending(row => row.LogicalBytes)
            .ToList(),
        Ages = OrderedAges(state),
        Duplicates = dupRows,
        Errors = state.Errors
    };

    Directory.CreateDirectory(outDir);
    var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
    var json = JsonSerializer.Serialize(report, jsonOptions);
    File.WriteAllText(Path.Combine(outDir, "latest.json"), json, new UTF8Encoding(false));
    File.WriteAllText(Path.Combine(outDir, $"disk-space-analysis-{stamp}.json"), json, new UTF8Encoding(false));
    WriteFoldersCsv(Path.Combine(outDir, "latest-folders.csv"), root);
    WriteFoldersCsv(Path.Combine(outDir, $"disk-space-analysis-{stamp}-folders.csv"), root);
    WriteFilesCsv(Path.Combine(outDir, "latest-files.csv"), report.LargestFiles);
    WriteSimpleCsv(Path.Combine(outDir, "latest-extensions.csv"),
        ["extension", "fileCount", "logicalBytes", "allocatedBytes"],
        report.Extensions.Select(row => new[] { row.Extension, row.FileCount.ToString(CultureInfo.InvariantCulture), row.LogicalBytes.ToString(CultureInfo.InvariantCulture), row.AllocatedBytes.ToString(CultureInfo.InvariantCulture) }));
    WriteSimpleCsv(Path.Combine(outDir, "latest-extension-files.csv"),
        ["extension", "path", "name", "logicalBytes", "allocatedBytes", "modifiedUtc"],
        report.Extensions.SelectMany(ext => ext.Files.Select(file => new[]
        {
            ext.Extension, file.Path, file.Name,
            file.LogicalBytes.ToString(CultureInfo.InvariantCulture),
            file.AllocatedBytes.ToString(CultureInfo.InvariantCulture),
            file.ModifiedUtc
        })));
    WriteSimpleCsv(Path.Combine(outDir, "latest-ages.csv"),
        ["bucket", "fileCount", "logicalBytes", "allocatedBytes"],
        report.Ages.Select(row => new[] { row.Bucket, row.FileCount.ToString(CultureInfo.InvariantCulture), row.LogicalBytes.ToString(CultureInfo.InvariantCulture), row.AllocatedBytes.ToString(CultureInfo.InvariantCulture) }));
    WriteSimpleCsv(Path.Combine(outDir, "latest-age-files.csv"),
        ["bucket", "path", "name", "extension", "logicalBytes", "allocatedBytes", "modifiedUtc"],
        report.Ages.SelectMany(age => age.Files.Select(file => new[]
        {
            age.Bucket, file.Path, file.Name, file.Extension,
            file.LogicalBytes.ToString(CultureInfo.InvariantCulture),
            file.AllocatedBytes.ToString(CultureInfo.InvariantCulture),
            file.ModifiedUtc
        })));
    WriteSimpleCsv(Path.Combine(outDir, "latest-duplicates.csv"),
        ["match", "hash", "logicalBytes", "count", "wasteBytes", "paths"],
        report.Duplicates.Select(row => new[] { row.Match, row.Hash ?? "", row.LogicalBytes.ToString(CultureInfo.InvariantCulture), row.Count.ToString(CultureInfo.InvariantCulture), row.WasteBytes.ToString(CultureInfo.InvariantCulture), string.Join("|", row.Paths) }));
    WriteSimpleCsv(Path.Combine(outDir, "latest-errors.csv"),
        ["path", "message"],
        report.Errors.Select(row => new[] { row.Path, row.Message }));
    var html = BuildOfflineHtml(json);
    File.WriteAllText(Path.Combine(outDir, "latest.html"), html, new UTF8Encoding(false));
    File.WriteAllText(Path.Combine(outDir, $"disk-space-analysis-{stamp}.html"), html, new UTF8Encoding(false));

    if (!quiet)
    {
        Console.WriteLine($"Done in {started.Elapsed.TotalSeconds:n1}s. Logical {FormatBytes(root.LogicalBytes)}. Files {root.FileCount:n0}. Denied {state.Denied}. Reports in {Path.GetFullPath(outDir)}");
        if (depth > 0) Console.WriteLine($"Depth limit {depth} was set. Totals exclude anything deeper.");
    }
    return 0;
}

int Compare(Dictionary<string, List<string>> opts)
{
    var beforePath = Opt(opts, "before") ?? throw new InvalidOperationException("compare requires --before <folders.csv or .json>");
    var afterPath = Opt(opts, "after") ?? throw new InvalidOperationException("compare requires --after <folders.csv or .json>");
    var outDir = Opt(opts, "out") ?? "disk-space-analysis-compare";
    var top = Math.Max(1, ParseInt(Opt(opts, "top"), 100));
    var minDelta = Math.Max(0, ParseLong(Opt(opts, "min-delta-bytes"), 1024 * 1024));

    var before = LoadFolderMap(beforePath);
    var after = LoadFolderMap(afterPath);
    var grew = new List<ChangeRow>();
    var shrunk = new List<ChangeRow>();
    var added = new List<ChangeRow>();
    var removed = new List<ChangeRow>();

    foreach (var (path, afterRow) in after.Rows)
    {
        if (before.Rows.TryGetValue(path, out var beforeRow))
        {
            var delta = afterRow.LogicalBytes - beforeRow.LogicalBytes;
            if (Math.Abs(delta) < minDelta) continue;
            var change = new ChangeRow { Path = path, Name = afterRow.Name, BeforeBytes = beforeRow.LogicalBytes, AfterBytes = afterRow.LogicalBytes, DeltaBytes = delta };
            if (delta > 0) grew.Add(change);
            else shrunk.Add(change);
        }
        else if (afterRow.LogicalBytes >= minDelta)
        {
            added.Add(new ChangeRow { Path = path, Name = afterRow.Name, BeforeBytes = 0, AfterBytes = afterRow.LogicalBytes, DeltaBytes = afterRow.LogicalBytes });
        }
    }
    foreach (var (path, beforeRow) in before.Rows)
    {
        if (after.Rows.ContainsKey(path) || beforeRow.LogicalBytes < minDelta) continue;
        removed.Add(new ChangeRow { Path = path, Name = beforeRow.Name, BeforeBytes = beforeRow.LogicalBytes, AfterBytes = 0, DeltaBytes = -beforeRow.LogicalBytes });
    }

    static List<ChangeRow> Top(List<ChangeRow> rows, int limit) =>
        rows.OrderByDescending(row => Math.Abs(row.DeltaBytes)).Take(limit).ToList();

    var report = new CompareReport
    {
        GeneratedAt = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        Before = new CompareSide { Label = Path.GetFullPath(beforePath), LogicalBytes = before.RootBytes },
        After = new CompareSide { Label = Path.GetFullPath(afterPath), LogicalBytes = after.RootBytes },
        Grew = Top(grew, top),
        Shrunk = Top(shrunk, top),
        Added = Top(added, top),
        Removed = Top(removed, top)
    };

    Directory.CreateDirectory(outDir);
    var jsonPath = Path.Combine(outDir, "compare.json");
    File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, jsonOptions), new UTF8Encoding(false));
    WriteChangeCsv(Path.Combine(outDir, "grew.csv"), report.Grew);
    WriteChangeCsv(Path.Combine(outDir, "shrunk.csv"), report.Shrunk);
    WriteChangeCsv(Path.Combine(outDir, "added.csv"), report.Added);
    WriteChangeCsv(Path.Combine(outDir, "removed.csv"), report.Removed);
    var net = after.RootBytes - before.RootBytes;
    Console.WriteLine($"Net {net} bytes. Grew {report.Grew.Count}, shrunk {report.Shrunk.Count}, added {report.Added.Count}, removed {report.Removed.Count}.");
    Console.WriteLine("Wrote " + Path.GetFullPath(jsonPath));
    return 0;
}

FolderMap LoadFolderMap(string file)
{
    if (!File.Exists(file)) throw new InvalidOperationException("File not found: " + file);
    if (file.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        return LoadJsonMap(file);
    return LoadCsvMap(file);
}

FolderMap LoadCsvMap(string file)
{
    var map = new FolderMap();
    foreach (var row in ReadCsv(file))
    {
        if (!row.TryGetValue("path", out var path) || string.IsNullOrWhiteSpace(path)) continue;
        var logical = row.TryGetValue("logicalBytes", out var raw) && long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;
        var depth = row.TryGetValue("depth", out var depthRaw) && int.TryParse(depthRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var depthParsed) ? depthParsed : 0;
        row.TryGetValue("name", out var name);
        map.Rows[path] = new FolderMeasure { Name = name ?? path, LogicalBytes = logical };
        if (depth == 0 && logical >= map.RootBytes) map.RootBytes = logical;
    }
    return map;
}

FolderMap LoadJsonMap(string file)
{
    using var doc = JsonDocument.Parse(File.ReadAllText(file));
    var map = new FolderMap();
    if (!doc.RootElement.TryGetProperty("tree", out var tree))
        throw new InvalidOperationException("JSON report has no tree: " + file);
    WalkJson(tree, map, isRoot: true);
    return map;
}

void WalkJson(JsonElement node, FolderMap map, bool isRoot)
{
    var path = node.GetProperty("path").GetString() ?? "";
    var name = node.TryGetProperty("name", out var nameEl) ? nameEl.GetString() ?? path : path;
    if (name.StartsWith('(')) return;
    var logical = node.TryGetProperty("logicalBytes", out var sizeEl) ? sizeEl.GetInt64() : 0;
    if (!string.IsNullOrEmpty(path))
    {
        map.Rows[path] = new FolderMeasure { Name = name, LogicalBytes = logical };
        if (isRoot) map.RootBytes = logical;
    }
    if (!node.TryGetProperty("children", out var children)) return;
    foreach (var child in children.EnumerateArray())
        WalkJson(child, map, isRoot: false);
}

List<DupRow> BuildDuplicates(ScanState state, bool hash)
{
    var rows = new List<DupRow>();
    foreach (var (size, paths) in state.Dups)
    {
        if (paths.Count < 2) continue;
        if (!hash)
        {
            rows.Add(new DupRow
            {
                Match = "size",
                LogicalBytes = size,
                Count = paths.Count,
                WasteBytes = size * (paths.Count - 1),
                Paths = paths.ToList()
            });
            continue;
        }
        var groups = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var file in paths)
        {
            try
            {
                var digest = HashFile(file);
                if (!groups.TryGetValue(digest, out var list))
                    groups[digest] = list = [];
                list.Add(file);
            }
            catch (Exception ex)
            {
                state.AddError(file, "Hash failed: " + ex.Message, reparse: false);
            }
        }
        foreach (var (digest, group) in groups)
        {
            if (group.Count < 2) continue;
            rows.Add(new DupRow
            {
                Match = "sha256",
                Hash = digest,
                LogicalBytes = size,
                Count = group.Count,
                WasteBytes = size * (group.Count - 1),
                Paths = group
            });
        }
    }
    return rows.OrderByDescending(row => row.WasteBytes).ToList();
}

string HashFile(string path)
{
    var open = path.Length >= 240 ? ToLongPath(path) : path;
    using var stream = new FileStream(open, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    var bytes = SHA256.HashData(stream);
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

void Rollup(FolderNode node)
{
    var stack = new Stack<(FolderNode Node, bool Visited)>();
    stack.Push((node, false));
    while (stack.Count > 0)
    {
        var (current, visited) = stack.Pop();
        if (!visited)
        {
            stack.Push((current, true));
            foreach (var child in current.Children)
                stack.Push((child, false));
            continue;
        }
        var logical = current.DirectLogical;
        var alloc = current.DirectAllocated;
        var files = current.DirectFiles;
        long folders = 0;
        foreach (var child in current.Children)
        {
            logical += child.LogicalBytes;
            alloc += child.AllocatedBytes;
            files += child.FileCount;
            folders += 1 + child.FolderCount;
        }
        current.LogicalBytes = logical;
        current.AllocatedBytes = alloc;
        current.FileCount = files;
        current.FolderCount = folders;
    }
}

FolderDto ExportNode(FolderNode node, int level, int exportDepth, int maxChildren)
{
    var kids = new List<FolderDto>();
    if (level < exportDepth)
    {
        var positive = node.Children.Where(child => child.LogicalBytes > 0).OrderByDescending(child => child.LogicalBytes).ToList();
        long sumL = 0;
        long sumA = 0;
        foreach (var child in positive.Take(maxChildren))
        {
            var exported = ExportNode(child, level + 1, exportDepth, maxChildren);
            kids.Add(exported);
            sumL += exported.LogicalBytes;
            sumA += exported.AllocatedBytes;
        }
        var remainder = node.LogicalBytes - sumL;
        if (kids.Count > 0 && remainder > 0)
        {
            kids.Add(new FolderDto
            {
                Name = positive.Count <= maxChildren ? "(files here)" : "(other)",
                Path = node.Path,
                LogicalBytes = remainder,
                AllocatedBytes = Math.Max(0, node.AllocatedBytes - sumA)
            });
        }
    }
    return new FolderDto
    {
        Name = node.Name,
        Path = node.Path,
        LogicalBytes = node.LogicalBytes,
        AllocatedBytes = node.AllocatedBytes,
        FileCount = node.FileCount,
        FolderCount = node.FolderCount,
        Children = kids
    };
}

void AddExt(ScanState state, string ext, long logical, long allocated)
{
    var row = state.ExtMap.GetValueOrDefault(ext);
    if (row is null)
    {
        row = new ExtRow { Extension = ext };
        state.ExtMap[ext] = row;
        state.Extensions.Add(row);
    }
    row.FileCount++;
    row.LogicalBytes += logical;
    row.AllocatedBytes += allocated;
}

void AddAge(ScanState state, string bucket, long logical, long allocated)
{
    if (!state.AgeMap.TryGetValue(bucket, out var row))
    {
        row = new AgeRow { Bucket = bucket };
        state.AgeMap[bucket] = row;
    }
    row.FileCount++;
    row.LogicalBytes += logical;
    row.AllocatedBytes += allocated;
}

List<AgeRow> OrderedAges(ScanState state)
{
    string[] order = ["0-7 days", "8-30 days", "31-90 days", "91-365 days", "1-3 years", "Older than 3 years"];
    return order.Select(bucket =>
    {
        var row = state.AgeMap.GetValueOrDefault(bucket) ?? new AgeRow { Bucket = bucket };
        row.Files = state.TakeAgeFiles(bucket);
        return row;
    }).ToList();
}

string AgeBucket(DateTime utc)
{
    var days = (DateTime.UtcNow - utc).TotalDays;
    if (days < 0) days = 0;
    if (days <= 7) return "0-7 days";
    if (days <= 30) return "8-30 days";
    if (days <= 90) return "31-90 days";
    if (days <= 365) return "91-365 days";
    if (days <= 1095) return "1-3 years";
    return "Older than 3 years";
}

string[] SplitPatterns(Dictionary<string, List<string>> opts)
{
    if (!opts.TryGetValue("exclude", out var values)) return [];
    return values.SelectMany(value => value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray();
}

bool IsExcluded(string full, string name, string[] patterns)
{
    foreach (var pattern in patterns)
    {
        if (pattern.Contains('*') || pattern.Contains('?'))
        {
            if (Wildcard(name, pattern) || Wildcard(full, pattern)) return true;
        }
        else if (name.Equals(pattern, StringComparison.OrdinalIgnoreCase)
            || full.EndsWith("\\" + pattern, StringComparison.OrdinalIgnoreCase)
            || full.Contains("\\" + pattern + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
    }
    return false;
}

bool Wildcard(string text, string pattern)
{
    var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
    return Regex.IsMatch(text, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
}

string DisplayPath(string full)
{
    if (full.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + full[8..];
    if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full[4..];
    return full;
}

string ToLongPath(string full)
{
    if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full;
    if (full.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + full[2..];
    return @"\\?\" + full;
}

long AllocationOf(string path, long logical)
{
    if (!OperatingSystem.IsWindows()) return logical;
    var value = Native.GetAllocation(path.Length >= 240 ? ToLongPath(path) : path);
    return value >= 0 ? value : logical;
}

int ParseInt(string? text, int fallback) =>
    int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : fallback;

long ParseLong(string? text, long fallback) =>
    long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : fallback;

void WriteFoldersCsv(string target, FolderNode root)
{
    using var writer = new StreamWriter(target, false, new UTF8Encoding(true));
    writer.WriteLine("path,name,logicalBytes,allocatedBytes,fileCount,folderCount,depth");
    var stack = new Stack<FolderNode>();
    stack.Push(root);
    while (stack.Count > 0)
    {
        var node = stack.Pop();
        writer.WriteLine(string.Join(",",
            Csv(node.Path), Csv(node.Name),
            node.LogicalBytes.ToString(CultureInfo.InvariantCulture),
            node.AllocatedBytes.ToString(CultureInfo.InvariantCulture),
            node.FileCount.ToString(CultureInfo.InvariantCulture),
            node.FolderCount.ToString(CultureInfo.InvariantCulture),
            node.Depth.ToString(CultureInfo.InvariantCulture)));
        foreach (var child in node.Children) stack.Push(child);
    }
}

void WriteFilesCsv(string target, List<FileRow> files)
{
    WriteSimpleCsv(target,
        ["path", "name", "extension", "logicalBytes", "allocatedBytes", "modifiedUtc"],
        files.Select(file => new[]
        {
            file.Path, file.Name, file.Extension,
            file.LogicalBytes.ToString(CultureInfo.InvariantCulture),
            file.AllocatedBytes.ToString(CultureInfo.InvariantCulture),
            file.ModifiedUtc
        }));
}

void WriteChangeCsv(string target, List<ChangeRow> rows)
{
    WriteSimpleCsv(target,
        ["path", "name", "beforeBytes", "afterBytes", "deltaBytes"],
        rows.Select(row => new[]
        {
            row.Path, row.Name,
            row.BeforeBytes.ToString(CultureInfo.InvariantCulture),
            row.AfterBytes.ToString(CultureInfo.InvariantCulture),
            row.DeltaBytes.ToString(CultureInfo.InvariantCulture)
        }));
}

void WriteSimpleCsv(string target, string[] headers, IEnumerable<string[]> rows)
{
    using var writer = new StreamWriter(target, false, new UTF8Encoding(true));
    writer.WriteLine(string.Join(",", headers));
    foreach (var row in rows)
        writer.WriteLine(string.Join(",", row.Select(Csv)));
}

string Csv(string? value)
{
    var text = value ?? "";
    if (text.IndexOfAny([',', '"', '\n', '\r']) >= 0)
        return "\"" + text.Replace("\"", "\"\"") + "\"";
    return text;
}

List<Dictionary<string, string>> ReadCsv(string file)
{
    var text = File.ReadAllText(file);
    var rows = new List<List<string>>();
    var row = new List<string>();
    var cell = new StringBuilder();
    var quoted = false;
    for (var i = 0; i < text.Length; i++)
    {
        var ch = text[i];
        if (quoted)
        {
            if (ch == '"')
            {
                if (i + 1 < text.Length && text[i + 1] == '"') { cell.Append('"'); i++; }
                else quoted = false;
            }
            else cell.Append(ch);
            continue;
        }
        if (ch == '"') { quoted = true; continue; }
        if (ch == ',') { row.Add(cell.ToString()); cell.Clear(); continue; }
        if (ch == '\n')
        {
            row.Add(cell.ToString());
            cell.Clear();
            rows.Add(row);
            row = [];
            continue;
        }
        if (ch != '\r') cell.Append(ch);
    }
    if (cell.Length > 0 || row.Count > 0)
    {
        row.Add(cell.ToString());
        rows.Add(row);
    }
    if (rows.Count == 0) return [];
    var headers = rows[0];
    var result = new List<Dictionary<string, string>>();
    for (var r = 1; r < rows.Count; r++)
    {
        if (rows[r].Count == 1 && rows[r][0].Length == 0) continue;
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var c = 0; c < headers.Count && c < rows[r].Count; c++)
            dict[headers[c]] = rows[r][c];
        result.Add(dict);
    }
    return result;
}

string BuildOfflineHtml(string json)
{
    var template = LoadViewerTemplate();
    var safe = json.Replace("<", "\\u003c", StringComparison.Ordinal).Replace(">", "\\u003e", StringComparison.Ordinal).Replace("&", "\\u0026", StringComparison.Ordinal);
    var embed = "<script id=\"disk-space-analysis-embed\" type=\"application/json\">" + safe + "</script>";
    if (template.Contains("<!--DISK_SPACE_ANALYSIS_EMBED-->", StringComparison.Ordinal))
        return template.Replace("<!--DISK_SPACE_ANALYSIS_EMBED-->", embed, StringComparison.Ordinal);
    return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>disk-space-analysis</title></head><body><p>Place viewer.html next to disk-space-analysis.exe.</p>" + embed + "</body></html>";
}

string LoadViewerTemplate()
{
    var beside = Path.Combine(AppContext.BaseDirectory, "viewer.html");
    if (File.Exists(beside)) return File.ReadAllText(beside);
    using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("disk-space-analysis.viewer.html");
    if (stream == null) return "";
    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}

List<string> ExpandPaths(List<string> args)
{
    var paths = new List<string>();
    foreach (var arg in args)
    {
        foreach (var part in arg.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Length > 0) paths.Add(part);
        }
    }
    return paths;
}

void ShiftDepth(FolderNode node, int delta)
{
    node.Depth += delta;
    foreach (var child in node.Children) ShiftDepth(child, delta);
}

string FormatBytes(long number)
{
    var sign = number < 0 ? "-" : "";
    double value = Math.Abs((double)number);
    string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
    var index = 0;
    while (value >= 1024 && index < units.Length - 1) { value /= 1024; index++; }
    var digits = index == 0 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
    return sign + value.ToString("F" + digits, CultureInfo.InvariantCulture) + " " + units[index];
}

void PrintHelp()
{
    Console.WriteLine("""
        disk-space-analysis 1.0 — disk space analysis for Windows Server

          disk-space-analysis scan --path D:\ --path E:\Data --out C:\disk-space-analysis-reports --duplicates --hash --allocated
          disk-space-analysis compare --before older-folders.csv --after latest-folders.csv --out C:\disk-space-analysis-reports\compare

        scan
          --path <dir>            Folder, volume, or UNC path. Repeat for more than one. Semicolons also split a value.
          --out <dir>             Report folder (default disk-space-analysis-reports)
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

        compare reads folders.csv or a scan JSON. Open latest.json in the disk-space-analysis viewer, or double-click latest.html for the same screen offline.

        Publish:
          dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
        """);
}

sealed class ScanState
{
    readonly int _topFiles;
    readonly int _topFolders;
    readonly PriorityQueue<FileRow, long> _files = new();
    readonly PriorityQueue<FolderRow, long> _folders = new();
    readonly Dictionary<string, PriorityQueue<FileRow, long>> _ageFiles = new(StringComparer.Ordinal);
    readonly Dictionary<string, PriorityQueue<FileRow, long>> _extFiles = new(StringComparer.OrdinalIgnoreCase);
    const int AgeFileCap = 40;
    const int ExtFileCap = 40;

    public ScanState(int topFiles, int topFolders, bool duplicates, long minDup)
    {
        _topFiles = topFiles;
        _topFolders = topFolders;
        Duplicates = duplicates;
        MinDup = minDup;
    }

    public bool Duplicates { get; }
    public long MinDup { get; }
    public long FilesSeen { get; set; }
    public long Denied { get; private set; }
    public long Reparse { get; private set; }
    public Dictionary<string, ExtRow> ExtMap { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ExtRow> Extensions { get; } = [];
    public Dictionary<string, AgeRow> AgeMap { get; } = new(StringComparer.Ordinal);
    public Dictionary<long, List<string>> Dups { get; } = [];
    public List<ErrRow> Errors { get; } = [];

    public void ConsiderFile(FileRow row)
    {
        if (_files.Count < _topFiles) _files.Enqueue(row, row.LogicalBytes);
        else if (row.LogicalBytes > _files.Peek().LogicalBytes)
        {
            _files.Dequeue();
            _files.Enqueue(row, row.LogicalBytes);
        }
    }

    public void ConsiderAgeFile(string bucket, FileRow row)
    {
        if (!_ageFiles.TryGetValue(bucket, out var heap))
            _ageFiles[bucket] = heap = new PriorityQueue<FileRow, long>();
        if (heap.Count < AgeFileCap) heap.Enqueue(row, row.LogicalBytes);
        else if (row.LogicalBytes > heap.Peek().LogicalBytes)
        {
            heap.Dequeue();
            heap.Enqueue(row, row.LogicalBytes);
        }
    }

    public List<FileRow> TakeAgeFiles(string bucket)
    {
        if (!_ageFiles.TryGetValue(bucket, out var heap)) return [];
        var list = new List<FileRow>();
        while (heap.Count > 0) list.Add(heap.Dequeue());
        list.Sort((a, b) => b.LogicalBytes.CompareTo(a.LogicalBytes));
        return list;
    }

    public void ConsiderExtFile(string extension, FileRow row)
    {
        if (!_extFiles.TryGetValue(extension, out var heap))
            _extFiles[extension] = heap = new PriorityQueue<FileRow, long>();
        if (heap.Count < ExtFileCap) heap.Enqueue(row, row.LogicalBytes);
        else if (row.LogicalBytes > heap.Peek().LogicalBytes)
        {
            heap.Dequeue();
            heap.Enqueue(row, row.LogicalBytes);
        }
    }

    public List<FileRow> TakeExtFiles(string extension)
    {
        if (!_extFiles.TryGetValue(extension, out var heap)) return [];
        var list = new List<FileRow>();
        while (heap.Count > 0) list.Add(heap.Dequeue());
        list.Sort((a, b) => b.LogicalBytes.CompareTo(a.LogicalBytes));
        return list;
    }

    public void ConsiderFolder(FolderNode node)
    {
        var row = new FolderRow
        {
            Path = node.Path,
            Name = node.Name,
            LogicalBytes = node.LogicalBytes,
            AllocatedBytes = node.AllocatedBytes,
            FileCount = node.FileCount,
            Depth = node.Depth
        };
        if (_folders.Count < _topFolders) _folders.Enqueue(row, row.LogicalBytes);
        else if (row.LogicalBytes > _folders.Peek().LogicalBytes)
        {
            _folders.Dequeue();
            _folders.Enqueue(row, row.LogicalBytes);
        }
    }

    public List<FileRow> TopFiles()
    {
        var list = new List<FileRow>();
        while (_files.Count > 0) list.Add(_files.Dequeue());
        return list;
    }

    public List<FolderRow> TopFolders()
    {
        var list = new List<FolderRow>();
        while (_folders.Count > 0) list.Add(_folders.Dequeue());
        return list;
    }

    public void AddDup(long size, string path)
    {
        if (!Dups.TryGetValue(size, out var list))
            Dups[size] = list = [];
        if (list.Count < 100) list.Add(path);
    }

    public void AddError(string path, string message, bool reparse)
    {
        if (reparse) Reparse++;
        else Denied++;
        if (Errors.Count < 500) Errors.Add(new ErrRow { Path = path, Message = message });
    }
}

static class Native
{
    const uint FileReadAttributes = 0x80;
    const uint ShareAll = 7;
    const uint OpenExisting = 3;
    const uint Backup = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    struct FileStandardInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending;
        public byte Directory;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr handle, int cls, out FileStandardInfo info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    public static long GetAllocation(string path)
    {
        var handle = CreateFileW(path, FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, Backup, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return -1;
        try
        {
            if (!GetFileInformationByHandleEx(handle, 1, out var info, (uint)Marshal.SizeOf<FileStandardInfo>()))
                return -1;
            return info.AllocationSize;
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}

sealed class FolderNode
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public int Depth { get; set; }
    public long DirectLogical { get; set; }
    public long DirectAllocated { get; set; }
    public long DirectFiles { get; set; }
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public long FileCount { get; set; }
    public long FolderCount { get; set; }
    public List<FolderNode> Children { get; } = [];
}

sealed class FolderMap
{
    public Dictionary<string, FolderMeasure> Rows { get; } = new(StringComparer.OrdinalIgnoreCase);
    public long RootBytes { get; set; }
}

sealed class FolderMeasure
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public long LogicalBytes { get; set; }
}

sealed class ScanReport
{
    public string Kind { get; set; } = "scan";
    public string Tool { get; set; } = "disk-space-analysis.dotnet";
    public string Version { get; set; } = "1.0";
    public string ScannedAt { get; set; } = "";
    public string Host { get; set; } = "";
    public string Root { get; set; } = "";
    public List<string> Roots { get; set; } = [];
    public long ElapsedMs { get; set; }
    public Summary Summary { get; set; } = new();
    public FolderDto Tree { get; set; } = new();
    public List<FolderRow> LargestFolders { get; set; } = [];
    public List<FileRow> LargestFiles { get; set; } = [];
    public List<ExtRow> Extensions { get; set; } = [];
    public List<AgeRow> Ages { get; set; } = [];
    public List<DupRow> Duplicates { get; set; } = [];
    public List<ErrRow> Errors { get; set; } = [];
}

sealed class Summary
{
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public long FileCount { get; set; }
    public long FolderCount { get; set; }
    public long DeniedCount { get; set; }
    public long ReparseSkipped { get; set; }
    public int DuplicateGroups { get; set; }
    public long DuplicateWasteBytes { get; set; }
    public bool AllocatedCollected { get; set; }
}

sealed class FolderDto
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public long FileCount { get; set; }
    public long FolderCount { get; set; }
    public List<FolderDto> Children { get; set; } = [];
}

sealed class FolderRow
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public long FileCount { get; set; }
    public int Depth { get; set; }
}

sealed class FileRow
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Extension { get; set; } = "";
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public string ModifiedUtc { get; set; } = "";
}

sealed class ExtRow
{
    public string Extension { get; set; } = "";
    public long FileCount { get; set; }
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public List<FileRow> Files { get; set; } = [];
}

sealed class AgeRow
{
    public string Bucket { get; set; } = "";
    public long FileCount { get; set; }
    public long LogicalBytes { get; set; }
    public long AllocatedBytes { get; set; }
    public List<FileRow> Files { get; set; } = [];
}

sealed class DupRow
{
    public string Match { get; set; } = "size";
    public string? Hash { get; set; }
    public long LogicalBytes { get; set; }
    public int Count { get; set; }
    public long WasteBytes { get; set; }
    public List<string> Paths { get; set; } = [];
}

sealed class ErrRow
{
    public string Path { get; set; } = "";
    public string Message { get; set; } = "";
}

sealed class CompareReport
{
    public string Kind { get; set; } = "compare";
    public string Tool { get; set; } = "disk-space-analysis.dotnet";
    public string Version { get; set; } = "1.0";
    public string GeneratedAt { get; set; } = "";
    public CompareSide Before { get; set; } = new();
    public CompareSide After { get; set; } = new();
    public List<ChangeRow> Grew { get; set; } = [];
    public List<ChangeRow> Shrunk { get; set; } = [];
    public List<ChangeRow> Added { get; set; } = [];
    public List<ChangeRow> Removed { get; set; } = [];
}

sealed class CompareSide
{
    public string Label { get; set; } = "";
    public long LogicalBytes { get; set; }
}

sealed class ChangeRow
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public long BeforeBytes { get; set; }
    public long AfterBytes { get; set; }
    public long DeltaBytes { get; set; }
}
