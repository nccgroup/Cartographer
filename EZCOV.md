# EZCOV Format

The EZCOV ("Easy Coverage") format was created to simplify the formatting of coverage data and to provide Ghidra-specific functionality in Cartographer.

Below is an example of the EZCOV format.

```
EZCOV VERSION: 1
0x00101000,       20, [  ]
0x00101016,        5, [  ]
0x00201251,        6, [ MAIN ]
0x00201257,       22, [ MAIN ]
0x00101160,        9, [ OVR1 ]
```

## Structure

EZCOV files consist of 3 sections:

- [Version](#version)
- [Options](#options) (optional)
- [Coverage Data](#coverage-data)

Single-line comments start with the `#` character.

## Version

The version is a single line at the top of the file that dictates the EZCOV version.

```
EZCOV VERSION: 1
```

## Options

The options section is an **optional** section that defines any additional functionality, features, or options about the coverage data.

This section begins with the `OPTIONS:` keyword, followed by one or more lines of options.

**Note:** This section is unused in EZCOV version 1.

```
OPTIONS:
    fix_jumps
    auto_disassemble
    ...
```

## Coverage Data

Each line of coverage data contains a series of comma-separate values that determine which parts of the program were executed.

At minimum, this contains the **offset**, **size**, and **address space**.

* **Offset**: Hexadecimal address in memory where the program began execution.
* **Size**: Decimal number of bytes executed.
* **Address Space**: Name of the address space where the code was executed.
  * This is useful for exploring multiple loaded binaries that occupy the same address(es) in RAM.
  * If blank, the program's default address space is used.

```
#
# Columns:
#
#   OFFSET,     SIZE, [ ADDRESS_SPACE ]
#
0x4002B260,       12, [  ]
0x4002B270,       12, [  ]
0x400A2F34,        8, [ OV1 ]
0x400A3278,       20, [ OV1 ]
0x400A328C,       12, [ OV1 ]
```
