# REA and Ghidra binary evaluation

On October 9, 2026, the `Synthetic binary and REA comparison` workflow ran REA 3.1.0 with Ghidra 12.1.2 on three locally compiled synthetic ELF files. The [completed CI run](https://github.com/Amal-David/keyleak-detector/actions/runs/37928101877) used no model provider, real credentials, external artifact uploads, or target execution. The reproducible evaluator is [`scripts/evaluate_binary_rea.py`](../scripts/evaluate_binary_rea.py).

KeyLeak found the plaintext synthetic credential once, at byte offset 8208; the evaluator checked that offset against the binary bytes. The public example and runtime-constructed XOR value were not flagged. Coverage was complete, and the JSON report contained no raw canary. REA/Ghidra string search returned two matches for both the plaintext canary and the public example, and none for the XOR value. These are search results, not secret classifications. Ghidra decompilation exposed the XOR operation in the synthetic function, providing a review clue that static string scanning missed.

This supports using REA/Ghidra as an optional local analysis aid for investigating encoded strings. It does not establish automatic secret classification: the evaluator deliberately uses known synthetic inputs, and the visible XOR operation does not by itself determine whether reconstructed data is sensitive. The model provider was not called, so this run did not validate any provider's data handling or privacy boundary.

**Decision: no-go for production model integration.** Reconsider only after a separate evaluation proves classification quality and the provider data boundary for the exact integration. Keep deterministic local binary scanning as the supported behavior; treat REA output as human-review evidence.
