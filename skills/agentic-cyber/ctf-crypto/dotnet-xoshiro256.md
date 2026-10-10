# Crypto - .NET System.Random and xoshiro256** state recovery

## .NET System.Random (xoshiro256**) state recovery from bounded Next() outputs

**Trigger:** An ASP.NET/C# service shares one `Random` instance between an endpoint that returns its outputs to you and a privileged path that compares a caller-supplied token against the next output. Outputs typically arrive as `Convert.ToBase64String(Encoding.ASCII.GetBytes(_random.Next(0, 2147483647).ToString()))` — decode to a decimal string, not raw bytes.

On .NET 6+ x64 `System.Random`'s parameterless constructor uses xoshiro256** with a 256-bit state, output `rotl(s1 * 5, 7) * 9 mod 2^64`, and `Next(0, bound)` returns the *high* 32 bits pushed through a bounded reduction, so each observation constrains only 32 of 64 output bits. Do not hand the whole generator to an SMT solver — it does not converge. Split it: first invert the bounded reduction to the possible high-32 values, then peel the multiply-by-9 mod 2^32 over all carries, undo the rotate, and invert the multiply-by-5 relation to enumerate a short list (~76) of candidate 34-bit slices of s1 per observation. Second, exploit that the xoshiro state transition is GF(2)-linear: every bit of every future slice is a linear form in the 256 initial state bits, so nine observations give 9*34 = 306 equations of rank 256, leaving ~50 parity relations that any valid combination of slice choices must satisfy. Meet in the middle on those parities — bucket XOR syndromes for four observations, then enumerate the remaining five looking for the zero syndrome — instead of 76^9 blind combinations. Lift each hit into a GF(2) basis and validate against all collected outputs; exactly one survives. Collect the outputs by pipelining requests over a single socket so the sequence stays contiguous. Finally, account for every *other* consumer of the same instance: a background health probe that burns a fixed number of draws on a timer means you cannot know the exact index when your forged request lands, so fire a batch of guesses at predicted offsets (one per skipped draw plus one per failed attempt) and let one of them hit.

```python
# .NET 8 xoshiro256** output + bounded reduction to model
# result = rotl(s1 * 5, 7) * 9  (mod 2^64)
# x      = result >> 32
# value  = (2147483647 * x) >> 32     # plus a small rejection loop for modulo bias

# outputs arrive base64'd as ASCII decimal, not raw bytes:
import base64
v = int(base64.b64decode("NDQyOTA4NTQ="))   # -> 44290854
```

Source: https://cybersecurityelite.com/ctf-writeups/r3ctf-2026-writeup/
