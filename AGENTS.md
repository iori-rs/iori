# Agent Instructions

## iori-cenc

`iori-cenc` is designed to decrypt in place and produce output with the same
byte length as the input. Do not copy Bento4's metadata rewrite strategy when it
would change file size, shift later box offsets, or reorder MP4 boxes.

Metadata cleanup after decryption is allowed when it preserves the original
file size and the relative order of boxes. Size-preserving edits such as
clearing encryption signaling, replacing removed box payloads with inert bytes,
or normalizing metadata in place are acceptable when they keep all downstream
box offsets stable.
