# Elephant Scrape 
[Logo:]([![LOGO-(1).png](https://i.postimg.cc/2jMXByB8/LOGO-(1).png)](https://postimg.cc/23dxszwP))

Elephant Scrape is a privacy-first unified storage layer.

## Current MVP

- Local disk storage provider.
- Provider adapter interface for adding unlimited storage services.
- Automatic placement based on available free space.
- Client-side encryption using authenticated encryption (AES-256-GCM via the `cryptography` package).
- Encrypted file metadata and original filename.
- Explicit unencrypted mode.
- Download/decrypt to the device.
- Opt-in anonymous provider recommendations (disabled by default).
- Security-policy framework for downloads with 5/10/20/40 inspection-layer targets.
- Clear, human-readable security warnings with an explicit "Download anyway" path.

## Architecture

```
File
  -> local encryption
  -> storage router
  -> provider adapter(s)
  -> local disk / cloud provider / future connector

download
  <- provider adapter
  <- encrypted object
  <- local authenticated decryption
  <- original file

P2P sharing is designed as a separate transport layer. Signaling may be used to establish a connection, but file contents and encryption keys must remain end-to-end protected.
```

## Run

Install Python 3.11+ and:

```bash
pip install -r requirements.txt
python elephant_scrape.py
```

This is an initial foundation, not a claim that every cloud connector or production P2P path is complete yet.


## Implemented MVP behavior

- Client-side AES-256-GCM encryption by default.
- Persistent local vault key for this installation.
- Local storage folders can be connected as providers.
- New files are routed to a provider with sufficient free space, preferring the most available capacity.
- Encrypted objects keep their original filename inside authenticated encrypted metadata.
- Unencrypted storage requires an explicit warning confirmation.
- Download checks classify text/images, code, executables and unknown files with 5/10/20/40 target security layers. The current foundation implements deterministic local checks; additional AV/sandbox layers are still extension points.
- Anonymous provider recommendations remain disabled by default and are not needed for core storage.
- The provider interface is designed for future Google Drive, Dropbox, OneDrive and other connectors.
- P2P sharing is planned as a separate end-to-end encrypted transport layer and is not falsely presented as complete in this MVP.
