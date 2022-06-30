# Harvest PE
[![MIT License][li]][ll]

Harvest PE provides a datatype for the PE format[^1] that leverages Data.Binary[^2] to provide a fast, accurate typed representation of PE with the goal to be resilient against maliciously crafted PE files.

### TODO
- Add features as needed once disassembly work has started.

### Tested on
- Emotet (Trojan)[^3]

### Documentation
- Ero Carrera Picture[^4]
- Microsoft Documentation[^5]
- Lost in the Loader: The Many Faces of the Windows PE File Format[^6]

[li]: https://img.shields.io/badge/License-MIT-yellow.svg
[ll]: https://opensource.org/licenses/MIT

[^1]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
[^2]: https://hackage.haskell.org/package/binary-0.10.0.0/docs/Data-Binary.html
[^3]: https://www.virustotal.com/gui/file/15abd370b867de0223943f0ea149cddf2992b0341cf9420ed9bee3063727998e
[^4]: https://drive.google.com/file/d/0B3_wGJkuWLytbnIxY1J5WUs4MEk/view?resourcekey=0-n5zZ2UW39xVTH8ZSu6C2aQ
[^5]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
[^6]: https://www.youtube.com/watch?v=oswbh4UnJFE
