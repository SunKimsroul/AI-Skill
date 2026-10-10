# WebGPU / WGSL CTF Triage

Use this note for a supplied WebGPU challenge bundle, WGSL shader, or locally hosted CTF page. Treat the browser, JavaScript wrapper, GPU pipeline, textures, buffers, and displayed model as separate layers of one local computation. Do not modify or automate an unrelated website.

## Recover the local pipeline

1. Preserve the bundle and identify the local entry point, shader-module creation, compute/fragment/vertex pipelines, bind groups, texture dimensions/formats, buffer sizes, and workgroup dispatches.
2. Beautify only the smallest relevant JavaScript region. Follow challenge inputs through parameter normalization, PRNG/state setup, shader uniforms/storage, compute passes, and final rendering.
3. Record resource geometry exactly: width, height, layer count, pixel/element format, bytes per element, row stride, and coordinate convention. A plausible output is often wrong because a rectangular texture was reconstructed as square.
4. Keep shader coordinate modes distinct. Texture sampling normally uses normalized UV coordinates, while a direct texture load uses integer texel coordinates; prove the path from the supplied shader rather than converting by intuition.

## Make a bounded local experiment

1. Derive the candidate input domain from the supplied UI and source, then enumerate only that finite local challenge domain. Preserve parameters, bundle hash, browser/runtime version, and each result identifier.
2. Remove artificial presentation delays only in a copied local challenge bundle. Do not change the algorithm until a baseline input/output result is recorded.
3. Prefer a deterministic completion hook or a local output checkpoint over screenshots. If a visual result remains necessary, store its exact texture/model dimensions with the image.

## Read back computed output

1. Trace the final fragment/compute output to its source texture/buffer. If the supplied local shader writes only to a render target, add an equivalent local storage/readback path in a copied bundle and keep its element layout identical.
2. Verify buffer element type, alignment, row stride, and channel conversion with a small marker pattern before interpreting the full result.
3. Separate raw texture reconstruction from model projection. UV mapping, mirroring, clipping, and vertex transforms can conceal an otherwise correct flag texture.
4. Validate the recovered data independently: compare a local shader readback with the visual output, then decode only after all coordinate and byte-order transformations agree.

## Source-derived pattern

SAS CTF 2025 Quals' *Washing Machine* combined minified JavaScript, WGSL compute/fragment shaders, finite UI parameters, a rectangular texture readback, and a distorted model projection. The reusable method is pipeline mapping -> bounded local enumeration -> resource-correct readback -> separate UV/model reconstruction.

Source: <https://ctftime.org/writeup/40286>
