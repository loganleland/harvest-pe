# Harvest PE
[![MIT License][li]][ll]

Harvest PE provides a datatype for the PE format[^1] that leverages Data.Binary[^2] to provide a fast, accurate typed representation of PE with the goal to be resilient against maliciously crafted PE files.

### TODO
- Add features as needed once disassembly work has started.

### Tested on
- Trojan[^3]

[li]: https://img.shields.io/badge/License-MIT-yellow.svg
[ll]: https://opensource.org/licenses/MIT

[^1]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
[^2]: https://hackage.haskell.org/package/binary-0.10.0.0/docs/Data-Binary.html
[^3]: https://www.virustotal.com/gui/file/15abd370b867de0223943f0ea149cddf2992b0341cf9420ed9bee3063727998e
