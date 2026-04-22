## PPCG Findings

### Current dense validation line

The current dense line worth keeping is:

- outer: `sysBand`
- inner: `wrapConvDp`

with the stage lengths

- `n_out = 2k + sigma`
- `n_final = n_out + tau`

and the best-performing tested dense setting so far has been `sigma = 8`.

### Negative results we already learned

- The non-systematic dense outer is not the right line.
- For `band -> wrapConv` / `wrapConvDp`, the dominant failure mode was not tiny input weights.
- The bad mass came from moderate message weights collapsing under the outer to very small intermediate weights.
- Wrapping helped only mildly on that line.
- Inner extension helped absolute threshold slightly but did not rescue relative distance on the non-systematic line.

### Structural improvement that mattered

- Switching to a systematic outer changed the failure mode materially.
- `sysBand` eliminates the catastrophic outer left-tail collapse to very small intermediate weights.
- After that change, the remaining bad mass comes from genuine low/moderate message weights, which is a much cleaner regime to study.

### Extension status

We tested inner extension with the exact DP enumerator and compared it directly against the no-extension line.

For `sysBand -> wrapConvDp` with `sigma = 8`:

- extension consistently improved the absolute threshold by about `+1` output weight
- extension usually hurt the *relative* threshold because the blocklength increased more than the kernel threshold

So extension is currently on the back burner. It is not the main reason the current dense line works.

### Exact vs float backend

The float backend is now validated against exact mode on the active dense line.

Representative exact-vs-float checks matched on:

- `k = 24`
- `k = 48`
- `k = 72`

including the reported:

- `MD`
- `zero`
- `zeroVal`

The float backend is therefore the default for scaling sweeps, with exact mode retained as a reference.

### Current scaling picture

For the extended line `sysBand -> wrapConvDp` with:

- `sigma = 8`
- `tau = round(0.1 * n_out)`

the measured relative threshold drifted downward with `k`, roughly:

- `k = 24`: `9/62 = 0.145161`
- `k = 64`: `18/150 = 0.120000`
- `k = 96`: `24/220 = 0.109091`
- `k = 120`: `29/273 = 0.106227`

For the no-extension line `sysBand -> wrapConvDp` with:

- `sigma = 8`
- `tau = 0`

the overlapping points were uniformly slightly better in relative distance:

- `k = 24`: `8/56 = 0.142857`
- `k = 64`: `17/136 = 0.125000`
- `k = 96`: `23/200 = 0.115000`
- `k = 104`: `25/216 = 0.115741`

### Immediate engineering direction

The next work item is not more construction changes. It is enumerator performance.

The hot path to optimize is:

- `WrapConvDPEnumerator`

The first concrete optimization already in progress is low-tail DP capping.

For the no-extension dense line

- `sysBand -> wrapConvDp`
- `k = 64`
- `sigma = 8`
- float backend

we measured:

- full DP: about `161s`
- low-tail cap `hMax = 24`: about `39s`

with the same reported threshold:

- `17/136 = 0.125`

So low-tail restriction is already a meaningful optimization lever.

The new relative-pruning knob is currently experimental. It exists for further exploration, but its scale is not yet calibrated well enough for production sweeps.

The next concrete targets are:

1. low-tail-only DP (`h <= h_max`)
2. approximate DP pruning for low-mass states
3. discarded-mass accounting so approximate runs still come with an explicit error budget
4. eventually, intermediate-weight trimming in composition
