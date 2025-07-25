# ManifestValidator

Simple CLI to generate and validate DLL manifests. Requires .NET 6 SDK.

## Build
```bash
dotnet build -c Release
```

## Generate manifest
```bash
release-validator-console.exe generate --bin "D:\Dev\Embrace\EPD\Release-69\Bin" --out "manifest.json"" --include-transitive
```
Omit `--include-transitive` if you only care about top‑level DLLs.

## Validate
```bash
release-validator-console.exe validate --bin "C:\Some\SharePointDrop\Release-69" --manifest manifest.json
```
The tool exits with code 0 when validation passes, non‑zero otherwise (so you can fail CI).
