![DUMB Logo](dumb.svg)

This is a very simple architecture (and executable format) made for the purpose of teaching how to write Binja loaders and architectures.

# DUMB Architecture

Following is a description of the architecture. In this document, we use the following format to specify bitfields:

`0:xxyy` represents a single byte: `0` means that the first (upper) nibble of the byte is zero, while `xxyy` indicates two 2-bit fields making up the lower nibble of the byte.

## Registery

* `sp` (stack pointer)
* `r0` (GPR)
* `r1` (GPR)
* `r2` (GPR)
* `r3` (GPR)

## Instructions

### One Byte Instructions

| Format   | Tokenization  | Meaning                                                              |
| -------- | ------------  | ------------------------------------                                 |
| `0:xxyy` | `mov rx ry`   | Move the value in `ry` into `rx`                                     |
| `1:xxyy` | `add rx ry`   | Add the values of `ry` and `rx` and store the result in `rx`         |
| `2:xxyy` | `and rx ry`   | And the values of `ry` and `rx` and store the result in `rx`         |
| `3:xxyy` | `or rx ry`    | Or the values of `ry` and `rx` and store the result in `rx`          |
| `4:xxyy` | `xor rx ry`   | Xor the values of `ry` and `rx` and store the result in `rx`         |
| `9:____` | `ret`         | Return from the current function to the address stored on the stack. |

### Five Byte Instructions
| Format               |  Tokenization          |   Meaning                                                                        |
| -------------------- | ---------------------- | -------------------------------------------------------------------------------- |
| `a0 XX XX XX XX`     | `call XXXXXXXXX`       | Push `addr + 5` onto the stack and transfer execution to `XXXXXXXX` (`le` dword) |
| `7:xxyy XX XX XX XX` | `jlt xx, yy, XXXXXXXX` | If `rx` is less than `rx`, jump to `XXXXXXXX`, otherwise continue to next instr  |
| `8:__rr XX XX XX XX` | `mov rr, XXXXXXXX`     | Move the immediate `XXXXXXXX` into `rr`                                          |

# DUMB Format

DUMB files are extremely simple, containing only magic, and metadata for a single section. The format is as follows:

| Offset | Length | Contents (if applicable) | Description                                                |
| ------ | ------ | ------------------------ | ---------------------------------------------              |
| 0      | 4      | "`DUMB`"                 | Magic                                                      |
| 4      | 4      |          N/A             | Section length stored as little endian dword               |
| 8      | 4      |            N/A           | Address to load section at, stored as little endian dworx  |

