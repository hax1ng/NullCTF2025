# What Does The Fox Say? - CTF Writeup

**Category:** Misc
**Difficulty:** Easy
**Author:** cshark3008

## Challenge Description

> The fox left behind a strange melody... Hidden in the noise lies the truth. Can you figure out what the fox says?

We're given a URL: `http://public.ctf.r0devnull.team:3012`

---

## Solution

### Step 1: Initial Recon

When we first visit the URL with a default user-agent (like curl), we get redirected to a "Browser Not Supported" page. Interesting! The server is checking our browser.

```bash
curl -v http://public.ctf.r0devnull.team:3012
# Returns 302 redirect to /wrong/wrong.html
```

Using a Firefox user-agent works:

```bash
curl -s http://public.ctf.r0devnull.team:3012 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
```

### Step 2: Finding the Hidden Files

Checking `robots.txt` reveals a secret:

```
User-agent: *
Disallow: /secret.txt
```

Grabbing `/secret.txt`:

```
The fox whispers a secret hidden in the noise... Can you hear it?
G44TUJJQIZLEU5DKHZTSONDNKRMF2YATGJ4D2VLPKUBDO5LFHNRFYVYCK5UCEMJU
```

That string looks like Base32 encoding!

### Step 3: Analyzing the CSS

The main page links to `style.css` which contains something weird - a CSS animation with opacity values that look like binary data:

```css
@keyframes blink {
  0.00% { opacity: 1; }
  0.79% { opacity: 1; }
  0.79% { opacity: 1; }
  1.57% { opacity: 1; }
  /* ... lots more ... */
}
```

The animation has 127 steps (mentioned in `steps(127, end)`), and the opacity values alternate between 0 and 1. This is clearly hiding something!

Extracting the binary pattern from the opacity values gives us 128 bits:

```
11110101110111000101110101000101010111000101000101010001010111011101110001110111011101110111000101110111011101110001010101110111
```

### Step 4: Decoding the Morse Code

Here's where it gets clever! Looking at the run-lengths of 1s and 0s:
- Long runs of 1s = dashes (-)
- Short runs of 1s = dots (.)
- Long runs of 0s = letter separators

The pattern translates to Morse code:

```
-.--  .-..  ...-  ..  ...  ..---  -----  .----  ...--
  Y     L     V    I   S     2      0      1      3
```

**The CSS hides "YLVIS2013" in Morse code!**

This is a reference to Ylvis, the Norwegian comedy duo who made the viral hit "What Does The Fox Say?" in 2013.

### Step 5: Decrypting the Flag

Now we have:
- **Ciphertext**: The Base32-decoded string from `secret.txt`
- **Key**: `YLVIS2013`

XOR decryption time!

```python
import base64

ciphertext = base64.b32decode("G44TUJJQIZLEU5DKHZTSONDNKRMF2YATGJ4D2VLPKUBDO5LFHNRFYVYCK5UCEMJU")
key = b'YLVIS2013'

plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(40)])
print(plaintext.decode())
```

Output:
```
nullctf{G3r1ng_din9_d1ng_d1n93r1ng3d1ng}
```

---

## Flag

```
nullctf{G3r1ng_din9_d1ng_d1n93r1ng3d1ng}
```

The flag content is "Gering ding ding dingeringeding" in leetspeak - which is literally what the fox says in the song!

---

## Summary

1. Found `robots.txt` pointing to `secret.txt` containing Base32-encoded ciphertext
2. Discovered CSS animation hiding binary data in opacity values
3. Decoded the binary as Morse code to get "YLVIS2013" (the band + year of the song)
4. Used "YLVIS2013" as XOR key to decrypt the ciphertext
5. Got the flag referencing the iconic "ring ding ding" lyrics

The challenge cleverly ties together:
- The "What Does The Fox Say?" song theme
- Ylvis (the band) as the encryption key
- The song's famous nonsensical fox sounds as the flag content
- 2013, the year the song went viral

A fun tribute to one of the internet's most memorable memes!
