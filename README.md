# Opinionated static elf64 linker

This is currently just a small toy project, and it's only able to do static linking of simple hand-written asm files at the moment.

## TODO:
* support .bss
* actually parse some of the linker args
* diagnostics
* string table
* output section table
* LTO
    * dead code elemination at least
* tests
* fuzzing
* caching
* parallelism
* layout randomization
* deterministic mode
* "self-hosting"
