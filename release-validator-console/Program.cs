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

// Represents a single DLL's metadata stored in the manifest.
public record ManifestEntry(
    string FileName,              // The file name of the DLL.
    string RelativePath,          // The path of the DLL relative to the bin folder.
    string AssemblyFullName,      // The full assembly name (includes version and public key token).
    string AssemblyVersion,       // The version of the assembly.
    string FileVersion,           // File version from the file metadata.
    string PublicKeyToken,        // The public key token of the assembly.
    string Sha256,                // The computed SHA256 hash of the DLL's content.
    long FileSizeBytes,           // The size of the file in bytes.
    DateTime LastWriteUtc,        // The last write time in UTC.
    List<string> ReferencedAssemblies  // List of assembly references (transitive dependencies).
);

// Container for the complete manifest consisting of multiple ManifestEntry instances.
public record Manifest(List<ManifestEntry> Assemblies)
{
    // Loads the manifest from a JSON file.
    public static Manifest Load(string path) =>
        JsonSerializer.Deserialize<Manifest>(File.ReadAllText(path)) ??
        throw new InvalidOperationException("Failed to read manifest");

    // Saves the current manifest to a JSON file with indentation.
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
    // Program entry point. Sets up command line commands and options.
    private static int Main(string[] args)
    {
        // Create a root command with a brief description.
        var root = new RootCommand("DLL manifest generator / validator");

        // Option to specify the bin folder. Defaults to the current directory.
        var optionBin = new Option<DirectoryInfo>(
             name: "--bin",
             description: "Path to bin/Release folder (default: current folder)",
             getDefaultValue: () => new DirectoryInfo(Environment.CurrentDirectory)
         );

        // Option to specify the output file for the manifest. Defaults to manifest.json in current folder.
        var optionOut = new Option<FileInfo>(
            name: "--out",
            description: "Output manifest JSON file (default: manifest.json in the current folder)",
            getDefaultValue: () => new FileInfo(Path.Combine(Environment.CurrentDirectory, "manifest.json"))
        );

        // Option to include transitive (referenced) assemblies in the manifest.
        var optionTransitive = new Option<bool>("--include-transitive", () => false, "Include transitive referenced assemblies");

        // --- 'generate' command ---
        // This command scans the specified bin folder and generates a manifest file.
        var generate = new Command("generate", "Generate manifest from bin folder")
        {
            optionBin,
            optionOut,
            optionTransitive
        };
        generate.SetHandler((DirectoryInfo bin, FileInfo outFile, bool includeTransitive) =>
        {
            // Build the manifest using the provided bin directory and flag for transitive dependencies.
            var manifest = BuildManifest(bin.FullName, includeTransitive);
            // Save the generated manifest to the specified output file.
            manifest.Save(outFile.FullName);
            Console.WriteLine($"Manifest written to {outFile.FullName}");
        },
        optionBin,
        optionOut,
        optionTransitive
        );
        root.AddCommand(generate);

        // Option to specify the manifest file for validation. Defaults to manifest.json.
        var optionManifest = new Option<FileInfo>(
             name: "--manifest",
             description: "Manifest JSON file (default: manifest.json in the current folder)",
             getDefaultValue: () => new FileInfo(Path.Combine(Environment.CurrentDirectory, "manifest.json"))
         );

        // --- 'validate' command ---
        // This command validates the contents of the bin folder against the manifest file.
        var validate = new Command("validate", "Validate bin folder using a manifest")
        {
            optionBin,
            optionManifest
        };
        validate.SetHandler((DirectoryInfo bin, FileInfo manifestFile) =>
        {
            // Ensure the manifest file exists before attempting validation.
            if (!manifestFile.Exists)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: Manifest file '{manifestFile.FullName}' does not exist.");
                Console.ResetColor();
                Environment.ExitCode = 1;
                return;
            }

            // Load the manifest from the specified file.
            var manifest = Manifest.Load(manifestFile.FullName);
            // Get a tuple containing lists of errors and warnings from the validation routine.
            var (errors, warnings) = Validate(bin.FullName, manifest);

            // If there are no errors, validation is considered passed.
            if (errors.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Validation PASSED");
                Console.ResetColor();
                // Print warnings if any.
                if (warnings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Warnings:");
                    foreach (var w in warnings)
                        Console.WriteLine("  " + w);
                    Console.ResetColor();
                }
            }
            else
            {
                // If there are errors, display validation failure details.
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Validation FAILED:");
                foreach (var e in errors)
                    Console.WriteLine("  " + e);
                Console.ResetColor();
                // Also print warnings if there are any.
                if (warnings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Warnings:");
                    foreach (var w in warnings)
                        Console.WriteLine("  " + w);
                    Console.ResetColor();
                }
                // Mark process exit code as failure.
                Environment.ExitCode = 1;
            }
        },
        optionBin,
        optionManifest
        );
        root.AddCommand(validate);

        // Invoke the appropriate command based on the provided command line arguments.
        return root.Invoke(args);
    }

    // BuildManifest method scans the bin folder for .dll files and builds a manifest of metadata.
    private static Manifest BuildManifest(string binPath, bool includeTransitive)
    {
        var entries = new List<ManifestEntry>();
        // Enumerate all DLL files in the specified bin folder (including subdirectories).
        foreach (var file in Directory.EnumerateFiles(binPath, "*.dll", SearchOption.AllDirectories))
        {
            // Get the relative path of the DLL from the bin folder.
            var relative = Path.GetRelativePath(binPath, file);
            // Compute SHA256 hash for file integrity verification.
            var hash = ComputeSha256(file);
            // Get the file version information.
            var fvi = FileVersionInfo.GetVersionInfo(file);
            string asmFullName = string.Empty;
            string asmVer = string.Empty;
            string pkt = string.Empty;
            var refs = new List<string>();

            try
            {
                // Read the assembly name from the DLL.
                var asmName = AssemblyName.GetAssemblyName(file);
                asmFullName = asmName.FullName;
                asmVer = asmName.Version?.ToString() ?? string.Empty;
                // Convert public key token to hexadecimal string.
                pkt = string.Concat(asmName.GetPublicKeyToken()?.Select(b => b.ToString("x2")) ?? Array.Empty<string>());

                // If including transitive dependencies, try reading referenced assemblies.
                if (includeTransitive)
                {
                    refs = ReadReferences(file);
                }
            }
            catch
            {
                // If the DLL is not a managed assembly or fails to load reflection data,
                // only file hash is recorded, but the process continues.
            }

            // Add the discovered DLL information as a new manifest entry.
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
        // Return a manifest containing all the entries.
        return new Manifest(entries);
    }

    // Validate method checks the bin folder against the manifest, verifying file presence and integrity.
    private static (List<string> errors, List<string> warnings) Validate(string binPath, Manifest manifest)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        // Create a dictionary of manifest entries keyed by their relative path for quick lookups.
        var manifestMap = manifest.Assemblies.ToDictionary(a => a.RelativePath, StringComparer.OrdinalIgnoreCase);

        // Get a set of DLLs actually found in the bin folder.
        var foundFiles = Directory.EnumerateFiles(binPath, "*.dll", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(binPath, f))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // For each entry in the manifest, check if the file is missing in the bin folder.
        foreach (var m in manifestMap.Keys)
        {
            if (!foundFiles.Contains(m))
                errors.Add($"MISSING: {m}");
        }

        // For each found file, perform hash and version validations if the file is expected.
        foreach (var f in foundFiles)
        {
            if (!manifestMap.ContainsKey(f))
            {
                // Mark DLLs not present in the manifest as warnings.
                warnings.Add($"UNEXPECTED: {f}");
                continue;
            }
            var actualPath = Path.Combine(binPath, f);
            var hash = ComputeSha256(actualPath);
            if (!string.Equals(hash, manifestMap[f].Sha256, StringComparison.OrdinalIgnoreCase))
            {
                errors.Add($"HASH MISMATCH: {f}");
            }
            var fvi = FileVersionInfo.GetVersionInfo(actualPath);
            if ((fvi.FileVersion ?? string.Empty) != manifestMap[f].FileVersion)
            {
                errors.Add($"VERSION MISMATCH: {f} (actual {fvi.FileVersion}, expected {manifestMap[f].FileVersion})");
            }
        }

        // Build a hash set of all assembly full names present in the manifest.
        var assemblyNamesInManifest = new HashSet<string>(
            manifest.Assemblies.Select(a => a.AssemblyFullName).Where(n => !string.IsNullOrWhiteSpace(n)),
            StringComparer.OrdinalIgnoreCase);

        // Define a set of common .NET Framework assemblies to skip during transitive dependency checks.
        var frameworkAssemblies = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft.Bcl.AsyncInterfaces",
            "Microsoft.Build.Framework",
            "Microsoft.CSharp",
            "Microsoft.Extensions.Configuration.Abstractions",
            "Microsoft.Extensions.DependencyInjection.Abstractions",
            "Microsoft.Extensions.FileProviders.Abstractions",
            "Microsoft.Extensions.Logging.Abstractions",
            "Microsoft.Extensions.Options",
            "Microsoft.Extensions.Primitives",
            "Microsoft.ReportViewer.ProcessingObjectModel",
            "Microsoft.VisualBasic",
            "Microsoft.Win32.Registry",
            "mscorlib",
            "netstandard",
            "PresentationCore",
            "PresentationFramework",
            "System",
            "System.Buffers",
            "System.ComponentModel.Composition",
            "System.Configuration",
            "System.Core",
            "System.Data",
            "System.Data.Common",
            "System.Data.DataSetExtensions",
            "System.Data.OracleClient",
            "System.Design",
            "System.Diagnostics.DiagnosticSource",
            "System.Diagnostics.StackTrace",
            "System.Diagnostics.Tracing",
            "System.Drawing",
            "System.Drawing.Design",
            "System.Globalization.Extensions",
            "System.IO.Compression",
            "System.IO.Compression.FileSystem",
            "System.Management",
            "System.Memory",
            "System.Net.Http",
            "System.Net.Sockets",
            "System.Numerics",
            "System.Numerics.Vectors",
            "System.Runtime.CompilerServices.Unsafe",
            "System.Runtime.InteropServices.RuntimeInformation",
            "System.Runtime.Serialization",
            "System.Runtime.Serialization.Primitives",
            "System.Runtime.Serialization.Xml",
            "System.Security",
            "System.Security.Cryptography.Algorithms",
            "System.Security.Cryptography.Xml",
            "System.Security.Principal.Windows",
            "System.Security.SecureString",
            "System.ServiceModel",
            "System.Text.Encoding.CodePages",
            "System.Text.Encodings.Web",
            "System.Text.Json",
            "System.Threading.Overlapped",
            "System.Threading.Tasks.Extensions",
            "System.Transactions",
            "System.ValueTuple",
            "System.Web",
            "System.Web.Extensions",
            "System.Web.Services",
            "System.Windows.Forms",
            "System.Xml",
            "System.Xml.Linq",
            "System.Xml.XPath.XDocument",
            "WindowsBase",
            "WindowsFormsIntegration"
        };

        // Validate that transitive dependency references are also present in the manifest.
        foreach (var entry in manifest.Assemblies)
        {
            foreach (var reference in entry.ReferencedAssemblies)
            {
                // Extract the simple assembly name by splitting at the first comma.
                var simpleName = reference.Split(',')[0].Trim();
                // If the reference is a known .NET Framework assembly, skip the check.
                if (frameworkAssemblies.Contains(simpleName))
                    continue;

                // If the referenced assembly is not found among the manifest entries, add an error.
                if (!assemblyNamesInManifest.Contains(reference))
                {
                    errors.Add($"TRANSITIVE MISSING: {reference} (referenced by {entry.FileName})");
                }
            }
        }

        return (errors, warnings);
    }

    // ComputeSha256 method calculates the SHA256 hash of the file at the specified path.
    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha.ComputeHash(stream);
        // Convert hash to a hexadecimal string.
        return Convert.ToHexString(hash);
    }

    // ReadReferences method retrieves the list of assembly references (transitive dependencies)
    // from a given .NET assembly using Mono.Cecil.
    private static List<string> ReadReferences(string assemblyPath)
    {
        var list = new List<string>();
        try
        {
            // Load the assembly using Mono.Cecil to avoid executing any code.
            var def = AssemblyDefinition.ReadAssembly(assemblyPath);
            // Add all referenced assembly full names.
            list.AddRange(def.MainModule.AssemblyReferences.Select(r => r.FullName));
        }
        catch
        {
            // In case of errors (e.g. non-managed DLL), simply return an empty list.
        }
        return list;
    }
}