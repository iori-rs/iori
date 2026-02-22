# ssa-wasm

Wasm bindings for Sample-AES and CENC decryption.

## Build

```bash
wasm-pack build crates/ssa-wasm --target web
```

## API

- `decryptSegment(input, key, iv)`  
  Decrypts a Sample-AES segment. `key` and `iv` are 16-byte `Uint8Array`.

- `decryptSegmentCenc(input, "keyid:key")`  
  Decrypts a CENC fMP4/MP4 segment with a single `keyid:key` pair. Both are 32-hex chars.
