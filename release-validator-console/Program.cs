// ---------------- Program.cs ----------------
using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text.Json;
using Mono.Cecil;
using AssemblyDefinition = Mono.Cecil.AssemblyDefinition;

// *** Data model ***
public record ManifestEntry(
    string FileName,
    string RelativePath,
    string AssemblyFullName,
    string AssemblyVersion,
    string FileVersion,
    string PublicKeyToken,
    string Sha256,
    long FileSizeBytes,
    DateTime LastWriteUtc,
    List<string> ReferencedAssemblies
);

public record Manifest(List<ManifestEntry> Assemblies)
{
    public static Manifest Load(string path) =>
        JsonSerializer.Deserialize<Manifest>(File.ReadAllText(path)) ??
        throw new InvalidOperationException("Failed to read manifest");

    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        File.WriteAllText(path, json);
    }
}

internal class Program
{
    private static int Main(string[] args)
    {
        // root
        var root = new RootCommand("DLL manifest generator / validator");

        var optionBin = new Option<DirectoryInfo>(
             name: "--bin",
             description: "Path to bin/Release folder (default: current folder)",
             getDefaultValue: () => new DirectoryInfo(Environment.CurrentDirectory)
         );

        var optionOut = new Option<FileInfo>(
            name: "--out",
            description: "Output manifest JSON file (default: manifest.json in the current folder)",
            getDefaultValue: () => new FileInfo(Path.Combine(Environment.CurrentDirectory, "manifest.json"))
        );

        var optionTransitive = new Option<bool>("--include-transitive", () => false, "Include transitive referenced assemblies");


        // --- generate command ---
        var generate = new Command("generate", "Generate manifest from bin folder")
        {
            optionBin,
            optionOut,
            optionTransitive
        };
        generate.SetHandler((DirectoryInfo bin, FileInfo outFile, bool includeTransitive) =>
        {
            var manifest = BuildManifest(bin.FullName, includeTransitive);
            manifest.Save(outFile.FullName);
            Console.WriteLine($"Manifest written to {outFile.FullName}");
        },
        optionBin,
        optionOut,
        optionTransitive
        );
        root.AddCommand(generate);

        var optionManifest = new Option<FileInfo>(
             name: "--manifest",
             description: "Manifest JSON file (default: manifest.json in the current folder)",
             getDefaultValue: () => new FileInfo(Path.Combine(Environment.CurrentDirectory, "manifest.json"))
         );

        // --- validate command ---
        var validate = new Command("validate", "Validate bin folder using a manifest")
        {
            optionBin,
            optionManifest
        };
        validate.SetHandler((DirectoryInfo bin, FileInfo manifestFile) =>
        {

            // Check if the manifest file exists
            if (!manifestFile.Exists)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: Manifest file '{manifestFile.FullName}' does not exist.");
                Console.ResetColor();
                Environment.ExitCode = 1;
                return;
            }

            var manifest = Manifest.Load(manifestFile.FullName);
            var errors = Validate(bin.FullName, manifest);
            if (errors.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Validation PASSED");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Validation FAILED:");
                foreach (var e in errors) Console.WriteLine("  " + e);
                Console.ResetColor();
                Environment.ExitCode = 1;
            }
        },
        optionBin,
        optionManifest
        );
        root.AddCommand(validate);

        return root.Invoke(args);
    }

    // Build manifest
    private static Manifest BuildManifest(string binPath, bool includeTransitive)
    {
        var entries = new List<ManifestEntry>();
        foreach (var file in Directory.EnumerateFiles(binPath, "*.dll", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(binPath, file);
            var hash = ComputeSha256(file);
            var fvi = FileVersionInfo.GetVersionInfo(file);
            string asmFullName = string.Empty;
            string asmVer = string.Empty;
            string pkt = string.Empty;
            var refs = new List<string>();

            try
            {
                var asmName = AssemblyName.GetAssemblyName(file);
                asmFullName = asmName.FullName;
                asmVer = asmName.Version?.ToString() ?? string.Empty;
                pkt = string.Concat(asmName.GetPublicKeyToken()?.Select(b => b.ToString("x2")) ?? Array.Empty<string>());

                if (includeTransitive)
                {
                    refs = ReadReferences(file);
                }
            }
            catch
            {
                // Non‑managed DLL or reflection load failed; skip meta but keep hash.
            }

            entries.Add(new ManifestEntry(
                Path.GetFileName(file),
                relative,
                asmFullName,
                asmVer,
                fvi.FileVersion ?? string.Empty,
                pkt,
                hash,
                new FileInfo(file).Length,
                File.GetLastWriteTimeUtc(file),
                refs
            ));
        }
        return new Manifest(entries);
    }

    // Validate
    private static List<string> Validate(string binPath, Manifest manifest)
    {
        var errorList = new List<string>();
        var manifestMap = manifest.Assemblies.ToDictionary(a => a.RelativePath, StringComparer.OrdinalIgnoreCase);

        // Scan actual files
        var foundFiles = Directory.EnumerateFiles(binPath, "*.dll", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(binPath, f))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Missing
        foreach (var m in manifestMap.Keys)
        {
            if (!foundFiles.Contains(m)) errorList.Add($"MISSING: {m}");
        }
        // Unexpected
        foreach (var f in foundFiles)
        {
            if (!manifestMap.ContainsKey(f)) errorList.Add($"UNEXPECTED: {f}");
        }
        // Compare hashes / versions
        foreach (var f in foundFiles)
        {
            if (!manifestMap.TryGetValue(f, out var entry)) continue;
            var actualPath = Path.Combine(binPath, f);
            var hash = ComputeSha256(actualPath);
            if (!hash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                errorList.Add($"HASH MISMATCH: {f}");
            }
            var fvi = FileVersionInfo.GetVersionInfo(actualPath);
            if ((fvi.FileVersion ?? string.Empty) != entry.FileVersion)
            {
                errorList.Add($"VERSION MISMATCH: {f} (actual {fvi.FileVersion}, expected {entry.FileVersion})");
            }
        }
        return errorList;
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    private static List<string> ReadReferences(string assemblyPath)
    {
        var list = new List<string>();
        try
        {
            var def = AssemblyDefinition.ReadAssembly(assemblyPath);
            list.AddRange(def.MainModule.AssemblyReferences.Select(r => r.FullName));
        }
        catch { }
        return list;
    }
}