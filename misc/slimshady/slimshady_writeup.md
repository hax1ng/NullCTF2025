# Slim Shady - Malware Analysis CTF Writeup

**Challenge:** Slim Shady
**Category:** Threat Hunting
**Flag:** `nullctf{St4rt1ng_Y0ur_M4lw4r3_C4r33r_41n't_H4rd!}`

---

## The Setup

We're given a suspicious Windows executable called `TheRealSlimShady.exe` and a quiz server that asks us questions about what this malware does. The challenge description warns us this is based on real malware techniques - so let's be careful and analyze it in a safe environment!

## Tools Used

- **Ghidra** - For reverse engineering and decompiling the binary
- **Python** - For decoding obfuscated strings
- **strings** - Quick string extraction

## The Analysis

### Question 1: What user does the malware create?

First thing I noticed was the malware imports `NetUserAdd` from NETAPI32.dll - that's a Windows API for creating user accounts. Suspicious already!

Looking at the function that calls `NetUserAdd`, I found a bunch of hex bytes being XOR'd with `0xb9`:

```
0xeb, 0xdc, 0xd8, 0xd5, 0xea, 0xd5, 0xd0, 0xd4, 0xea, 0xd1, 0xd8, 0xdd, 0xc0, 0x88, 0x8a, 0x8a, 0x8e
```

Quick Python decode:
```python
encoded = [0xeb, 0xdc, 0xd8, 0xd5, 0xea, 0xd5, 0xd0, 0xd4, 0xea, 0xd1, 0xd8, 0xdd, 0xc0, 0x88, 0x8a, 0x8a, 0x8e]
decoded = ''.join(chr(b ^ 0xb9) for b in encoded)
# Result: RealSlimShady1337
```

**Answer: `RealSlimShady1337`**

---

### Question 2: What is the password for the backdoor user?

Same deal - found another function that generates the password using XOR with `0x55`:

```python
encoded = [0x0D, 0x65, 0x27, 0x66, 0x31, 0x06, 0x66, 0x36, 0x27, 0x30, 0x21, 0x26, 0x74]
decoded = ''.join(chr(b ^ 0x55) for b in encoded)
# Result: X0r3dS3crets!
```

The password is literally "XOR'd Secrets" - the malware author has a sense of humor!

**Answer: `X0r3dS3crets!`**

---

### Question 3: What MITRE technique is used for persistence?

Looking at other functions, I found one that:
1. Copies itself to `%TEMP%\NotShady.exe`
2. Opens a registry key
3. Sets a value to auto-run on login

The registry key path was also XOR encoded with `0xb9`:

```python
# Decodes to: Software\Microsoft\Windows\CurrentVersion\Run
```

This is the classic Run key persistence technique - programs listed here start automatically when a user logs in.

**Answer: `T1547.001`** (Boot or Logon Autostart Execution: Registry Run Keys)

---

### Question 4: What is the value of the registry key added?

The registry value name was also encoded:

```python
encoded = [0xea, 0xd1, 0xd8, 0xdd, 0xd0, 0xdc, 0xca, 0xcd]
decoded = ''.join(chr(b ^ 0xb9) for b in encoded)
# Result: Shadiest
```

**Answer: `Shadiest`**

---

### Question 5: What domain does the malware connect to?

Found a function that sets up network connections using `getaddrinfo`. The domain was (you guessed it) XOR encoded:

```python
encoded = [0xca, 0xd1, 0xd8, 0xdd, 0xc0, 0xca, 0xcd, 0xdc, 0xd8, 0xd5, 0xdc, 0xcb, 0xda, 0xd6, 0xd7, 0xd7, 0xdc, 0xda, 0xcd, 0x97, 0xcd, 0xd2]
decoded = ''.join(chr(b ^ 0xb9) for b in encoded)
# Result: shadystealerconnect.tk
```

The malware exfiltrates stolen data to this C2 (Command & Control) server.

**Answer: `shadystealerconnect.tk`**

---

### Question 6: What process are they injecting into?

Found a function that:
1. Calls `GetSystemDirectoryA` to get the Windows system folder
2. Appends `\notepad.exe`
3. Uses `CreateProcessA` to spawn notepad
4. Uses `VirtualAllocEx` and `WriteProcessMemory` to inject data

Classic process injection into a trusted Windows process!

**Answer: `notepad.exe`**

---

### Question 7: What is being injected?

This was the trickiest part. The malware:
1. Extracts an embedded resource called "MY_IMAGE"
2. Saves it as `vmware_log.jpg` in temp folder
3. Searches for a marker string `hXJakl` in the image
4. XOR decodes the data after the marker with key `0x7d`
5. Injects this decoded data into notepad.exe

Using Python to extract and decode the resource:

```python
import pefile

pe = pefile.PE('TheRealSlimShady.exe')
# Extract resource, find marker, XOR decode...
# Result: FIN{50y0u41n7r34llysh4dy}
```

It's hiding a flag in plain sight using steganography! The flag translates to "so you ain't really shady" - nice Eminem reference.

**Answer: `FIN{50y0u41n7r34llysh4dy}`**

---

## Summary of Malware Capabilities

This "Slim Shady" malware does the following nasty things:

1. **Creates a backdoor user** (`RealSlimShady1337`) with a known password
2. **Establishes persistence** via Registry Run key
3. **Collects system info** (IP, username, country, OS version, etc.) and saves to `goodies.txt`
4. **Exfiltrates data** to `shadystealerconnect.tk`
5. **Process injection** into notepad.exe (for stealthy execution)
6. **Anti-debugging** checks (calls `IsDebuggerPresent`)
7. **Self-deletion** after execution

All strings are XOR obfuscated to avoid simple detection - a common malware technique.

## Key Takeaways

- Malware authors love XOR encoding - it's simple but effective against basic string analysis
- Registry Run keys are still a popular persistence mechanism
- Process injection into legitimate Windows processes helps evade detection
- Steganography (hiding data in images) is used to conceal payloads
- Always analyze suspicious binaries in an isolated environment!

---

**Final Flag: `nullctf{St4rt1ng_Y0ur_M4lw4r3_C4r33r_41n't_H4rd!}`**

Will the real Slim Shady please stand up? 🎤
