# Misc - Speculative side channels in supplied soft-core CPUs

## Speculative side channel around a commit-time check in a supplied soft-core

**Trigger:** The handout is a full RTL CPU (Verilog/SystemVerilog SoC plus a simulator or submit endpoint) and an architectural gate blocks what you need — a pointer-authentication tag on indirect jumps, a privilege check, a range check — with a fault counter that locks the gate permanently after one or a few committed violations, so brute force is off the table.

Grep the RTL for the two halves of the classic Spectre shape rather than attacking the check itself. First, find where exceptions are gated on commit: a line like `takenException = (|next_exc_code) && !spec` means a faulting instruction on a squashed path raises nothing, so a wrong guess costs nothing when it executes speculatively. Second, find a second, quieter consumer of the same secret-dependent gate — typically a gated data-load path in the EX stage that redirects to a fixed probe address when the check passes and does nothing when it fails. That asymmetry is the oracle: a correct guess leaves a cache line resident at the probe address, a wrong one does not. To run the gated instruction speculatively without ever committing it, read the branch predictor's index function (usually `rd_idx = pc[IDX_BITS+1:2]`), place a harmless always-not-taken training branch at a PC that aliases to the same BHT index as the real oracle branch, train it a handful of times, then execute the oracle branch — which is actually taken — so its delay slot / fall-through runs on the wrong path. Time the probe with the core's own cycle counter after invalidating every way of the probe set (`cache 1, 0($reg)` for each way address), and threshold hit versus miss; the gap is only a few cycles in simulation, so confirm every hit with a second probe before acting. Iterate the whole tag space this way, then execute the confirmed value architecturally — that one commits cleanly. Calibrate the threshold against a dummy/local kernel build before running against the live instance.

```bash
# RTL greps that identify the shape
grep -rn 'spec\|squash\|takenException\|exc_code' rtl/units/*.sv rtl/modules/cp0.sv
grep -rn 'PROBE_ADDR\|_gated\|fault_count\|FAULT_LIMIT' rtl/
grep -rn 'rd_idx\|bht\|predictor' rtl/

# MIPS-style oracle: training branch and probe branch alias to the same BHT index
.org 0x40          # (0x40  >> 2) & 0x3F == 0x10
train_alias: bne $zero, $zero, 1f
             nop
1:           jr $ra
.org 0x140         # (0x140 >> 2) & 0x3F == 0x10
oracle_probe: bne $zero, $s2, 1f
              lb  $9, 0($t0)     # wrong-path gated load; $t0 = (guess<<56)|target
1:            jr $ra

# timing the probe line
lw   $t2, 0($s7)   # cycle counter
lb   $9,  0($s5)   # probe load from PROBE_ADDR
lw   $t3, 0($s7)
dsub $v0, $t3, $t2
sltiu $t3, $v0, 4  # threshold from local calibration
```

Source: https://cybersecurityelite.com/ctf-writeups/r3ctf-2026-writeup/
