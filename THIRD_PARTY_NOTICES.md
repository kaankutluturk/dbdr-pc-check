# Third-party notices

## YARA / libyara.NET

DBDR Evidence Suite uses `Microsoft.O365.Security.Native.libyara.NET.Core` 4.5.5, a Microsoft .NET wrapper around VirusTotal YARA/libyara. The package and upstream projects are distributed under the BSD 3-Clause License. Preserve their copyright and license notices in source and binary distributions.

- https://github.com/microsoft/libyara.NET
- https://github.com/VirusTotal/yara

## Eric Zimmerman Prefetch parser

DBDR Evidence Suite uses the `Prefetch` 2026.5.2 package by Eric Zimmerman to parse Windows Prefetch headers and last-run timestamps. It is distributed under the MIT License. The collector wraps it with compressed-input and declared-decompression-size limits and does not serialize referenced-file or volume lists exposed by the parser.

- https://github.com/EricZimmerman/Prefetch
- https://www.nuget.org/packages/Prefetch/2026.5.2
