#!/usr/bin/env python3
"""Generate the NuGet `.nupkg` test fixtures used by `plugins/nuget`.

A `.nupkg` is just an OPC zip whose root contains a `<id>.nuspec` manifest. We
build small, deterministic archives here so the parsing tests have real (not
hand-rolled-bytes) inputs. The generated `.nupkg` files are checked into the
repo; re-run this script only when the fixtures need to change:

    python3 fixtures/nuget/make_fixtures.py

The fixtures intentionally cover:
  * two different nuspec `xmlns` schema versions (Addendum A3 — the parser must
    be namespace-insensitive);
  * grouped and flat dependency declarations;
  * a "zip bomb" archive with a hugely compressible payload entry next to a
    valid manifest. Only the .nuspec is ever decompressed, so the parser must
    ACCEPT it under the default limits (large native packages look like this)
    and reject it only via the total-declared-size budget; manifest bombs are
    generated in the Rust tests.
"""
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# A 2013-schema nuspec with grouped dependencies.
SAMPLE_LIB_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.02.3</version>
    <authors>envisia</authors>
    <description>A sample library fixture.</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="[13.0.1, )" />
        <dependency id="Serilog" version="3.0.0" />
      </group>
      <group targetFramework="netstandard2.0">
        <dependency id="Newtonsoft.Json" version="[12.0.0, )" />
      </group>
    </dependencies>
  </metadata>
</package>
"""

# A variant of Sample.Lib with the SAME id + version (1.02.3 -> 1.2.3) but a
# DISTINCT dependency id. Used by the web e2e group scenario: when two group
# members carry the same (id, version), the highest-priority member wins, and
# its dependency group (`WinnerMarker.Dependency`) is what the group's package
# detail must surface — making the winner observable end to end.
SAMPLE_LIB_WINNER_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Sample.Lib</id>
    <version>1.02.3</version>
    <authors>envisia</authors>
    <description>Group winner variant of Sample.Lib (distinct dependency).</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="WinnerMarker.Dependency" version="[1.0.0, )" />
      </group>
    </dependencies>
  </metadata>
</package>
"""

# A 2011-schema nuspec (different xmlns) with flat (groupless) dependencies and
# a prerelease version that must be lowercased on normalization.
OTHER_PKG_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd">
  <metadata>
    <id>Other.Package</id>
    <version>2.0.0-Beta.1</version>
    <authors>envisia</authors>
    <description>A second fixture with a different namespace.</description>
    <dependencies>
      <dependency id="Microsoft.Extensions.Logging" version="8.0.0" />
    </dependencies>
  </metadata>
</package>
"""


def write_nupkg(path, nuspec_name, nuspec_body, extra=None):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Minimal OPC content-types part (real .nupkg files have this).
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="nuspec" ContentType="application/octet" />'
            '<Default Extension="dll" ContentType="application/octet" />'
            "</Types>",
        )
        z.writestr(nuspec_name, nuspec_body)
        # A token payload so the archive resembles a real package.
        z.writestr("lib/net8.0/Sample.dll", b"\x00MZ fake assembly payload\x00")
        for name, body in (extra or {}).items():
            z.writestr(name, body)


def write_zip_bomb(path):
    # A single, highly compressible payload entry: ~64 MiB of zeros compresses
    # to a few KiB. It is never decompressed (only the .nuspec is), so only a
    # tight total-declared-size budget rejects the archive.
    bomb = b"\x00" * (64 * 1024 * 1024 + 1)
    write_nupkg(
        path,
        "Sample.Lib.nuspec",
        SAMPLE_LIB_NUSPEC,
        extra={"content/huge.bin": bomb},
    )


def main():
    write_nupkg(
        os.path.join(HERE, "sample.lib.1.0.0.nupkg"),
        "Sample.Lib.nuspec",
        SAMPLE_LIB_NUSPEC,
    )
    write_nupkg(
        os.path.join(HERE, "sample.lib.winner.1.0.0.nupkg"),
        "Sample.Lib.nuspec",
        SAMPLE_LIB_WINNER_NUSPEC,
    )
    write_nupkg(
        os.path.join(HERE, "other.package.2.0.0-beta.1.nupkg"),
        "Other.Package.nuspec",
        OTHER_PKG_NUSPEC,
    )
    write_zip_bomb(os.path.join(HERE, "zip-bomb.nupkg"))
    print("fixtures written to", HERE)


if __name__ == "__main__":
    main()
