# CTF Reverse - CUDA and GPU kernel targets

Use this workflow for a supplied CTF executable, CUDA artifact, or local challenge environment. Do not run untrusted GPU workloads on shared/production infrastructure.

## Recognize the split program

GPU CTF challenges often contain a normal CPU host program plus CUDA artifacts such as PTX, cubin, fatbin, or driver/runtime API calls. The host normally owns input, allocation, copies, launch dimensions, and final verification; the device kernel owns a parallel transformation.

## Map host to device first

1. Locate device initialization, module loading, memory allocation/copies, kernel lookup, launch, synchronization, and host-side comparison/output.
2. Record every kernel argument in order: pointer/buffer, scalar values, lengths, and launch geometry (`grid`, `block`, dynamic shared memory).
3. Build a host/device buffer table with element width, byte length, direction, and ownership. Do not infer an array's element type only from a variable name.
4. Extract available code representation in the supplied bundle—prefer readable PTX, then use the host's embedded module/fatbin metadata, before trying to reason from machine code alone.

## Reduce a kernel to a scalar model

- Identify the global thread index and bounds check. Most CTF kernels apply one repeated transformation per index, lane, or chunk.
- Track CUDA memory spaces separately: registers, local memory, shared memory, global memory, constant memory, and texture/surface accesses.
- Determine whether synchronization or shared-memory reduction makes threads interdependent. A simple per-thread check can be modeled one index at a time; a reduction requires the block-level ordering.
- Pay close attention to 32-bit arithmetic, signedness, shifts, vector widths, byte packing, warp/lane indexes, and host/device endianness assumptions.
- Translate the recovered scalar semantics into a small CPU reference implementation and verify it against one or two known inputs. A GPU is not required for this validation when the kernel semantics are understood.

## Common traps

- Reversing only the kernel and missing a host-side pre/post transform or a wrong kernel argument order.
- Treating `threadIdx.x` as the global index without incorporating block/grid dimensions.
- Assuming a device pointer is meaningful in host memory.
- Ignoring the final host comparison, which often exposes the exact intended output shape.
- Mistaking parallel code for cryptography before checking whether it is merely a vectorized byte transform.

## Pivot rules

- Load `/ctf-crypto` when the recovered kernel implements a known cipher, hash, or algebraic construction.
- Load `/ctf-pwn` only when the supplied local challenge clearly depends on a memory-safety bug rather than the kernel's logic.
- Keep the final answer tied to a CPU reference and the supplied host verifier whenever GPU tooling is unavailable.

## Source-backed pattern

VolgaCTF's CUDA reverse challenges, including *cuCRACKME*, show the value of separating host launch logic from the device transformation and reconstructing the latter at the thread/index level: [CTFtime entry](https://ctftime.org/writeup/39400).
