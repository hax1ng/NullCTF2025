# wordleOS - CTF Writeup

**Challenge:** wordleOS
**Category:** Reverse Engineering
**Flag:** `nullctf{b00t_1nt0_w0rdl3}`

---

## The Challenge

We're given a raw binary file `wordle_os.bin` that boots directly as an operating system - a custom Wordle game written in Rust that runs without any underlying OS. Pretty cool concept!

To run it:
```bash
qemu-system-x86_64 -drive format=raw,file=wordle_os.bin
```

The goal? Find the secret 5-letter word (or in this case, the full flag).

---

## Initial Analysis

The binary is a DOS/MBR boot sector with an embedded Rust kernel. When you boot it up, you get a "Welcome to WordleOS!" message and can type guesses.

From static analysis in the CLAUDE.md notes, we knew:
- It's compiled from Rust with the pc-keyboard crate
- There's a keyboard interrupt handler that processes input
- Somewhere in there is a comparison against the secret word

The previous attempts tried XOR encoding, searching for plaintext 5-letter words, and looking for byte-by-byte character comparisons - but none of that worked.

---

## The Solution: VGA Buffer Comparison

Using Ghidra with the ReVa MCP tools, I loaded the extracted ELF kernel and went straight for the `keyboard_interrupt_handler` function at `0x2032b0`.

This function is 1265 bytes and handles all keyboard input. Scrolling through the decompiled code, I found the money shot at lines 198-210:

```c
if (((((*(long *)(DAT_0020a490 + 0xf00) == 0xf200f750f200f6e) &&
      (*(long *)(DAT_0020a490 + 0xf08) == 0xf200f6c0f200f6c)) &&
     ((*(long *)(DAT_0020a490 + 0xf10) == 0xf200f740f200f63 &&
      ((*(long *)(DAT_0020a490 + 0xf18) == 0xf200f7b0f200f66 &&
       (*(long *)(DAT_0020a490 + 0xf20) == 0xf200f300f200f62)))))) &&
    (*(long *)(DAT_0020a490 + 0xf28) == 0xf200f740f200f30)) &&
   // ... more comparisons
```

Wait, those aren't just characters - those are **VGA buffer values**!

### Understanding VGA Buffer Format

The VGA text buffer (at address `0xb8000` in real mode) stores each character as 2 bytes:
- **Byte 0:** ASCII character
- **Byte 1:** Color attribute (foreground/background colors)

The value `0xf2` you see in the comparison is the color attribute (white on black, blinking). Each 64-bit value contains 4 character+attribute pairs.

### Decoding the Flag

Taking those hex values and extracting just the character bytes:

```python
values = [
    0xf200f750f200f6e,  # n, u (with spaces)
    0xf200f6c0f200f6c,  # l, l
    0xf200f740f200f63,  # c, t
    0xf200f7b0f200f66,  # f, {
    0xf200f300f200f62,  # b, 0
    0xf200f740f200f30,  # 0, t
    0xf200f310f200f5f,  # _, 1
    0xf200f740f200f6e,  # n, t
    0xf200f5f0f200f30,  # 0, _
    0xf200f300f200f77,  # w, 0
    0xf200f640f200f72,  # r, d
    0xf200f330f200f6c,  # l, 3
    0xf200f200f200f7d,  # }
]
```

Each 64-bit value in little-endian format gives us character bytes at positions 0, 2, 4, 6. The odd bytes are the `0xf2` color attribute.

Extracting them in order:
- `0x6e` = 'n'
- `0x75` = 'u'
- `0x6c` = 'l'
- `0x6c` = 'l'
- `0x63` = 'c' (wait, not '0'?)
- `0x74` = 't'
- `0x66` = 'f'
- `0x7b` = '{'
- `0x62` = 'b'
- `0x30` = '0'
- `0x30` = '0'
- `0x74` = 't'
- `0x5f` = '_'
- `0x31` = '1'
- `0x6e` = 'n'
- `0x74` = 't'
- `0x30` = '0'
- `0x5f` = '_'
- `0x77` = 'w'
- `0x30` = '0'
- `0x72` = 'r'
- `0x64` = 'd'
- `0x6c` = 'l'
- `0x33` = '3'
- `0x7d` = '}'

**Flag: `nullctf{b00t_1nt0_w0rdl3}`**

---

## Why Previous Attempts Failed

1. **Static string search**: The flag isn't stored as a simple string - it's stored as VGA buffer format values (char + color byte pairs)

2. **XOR/encoding attempts**: There's no encoding at all! The characters are plaintext, just interleaved with VGA color attributes

3. **Searching for 5-letter word**: The actual flag is much longer than 5 characters. This isn't really a traditional Wordle where you guess a 5-letter word - it's checking for the entire flag string

---

## Key Takeaways

1. **Understand the platform**: This is a bare-metal OS using VGA text mode. Data formats are different from regular programs.

2. **Follow the input path**: The keyboard interrupt handler is where all the magic happens in a simple OS like this.

3. **VGA buffer format matters**: Each character takes 2 bytes (char + color). Comparisons include the color byte, making the patterns look weird at first glance.

4. **The comparison IS the answer**: Sometimes the check itself contains the expected value in plaintext (well, VGA-format plaintext).

---

## Tools Used

- **QEMU**: To boot and test the OS
- **Ghidra + ReVa**: For decompilation and analysis
- **Python**: For decoding the VGA buffer values

Fun challenge with a clever twist on the Wordle theme!
