# Elephant Scrape

Elephant Scrape is a privacy-first unified storage layer.

## Web application

The repository now contains a browser-based Web MVP in addition to the original Tkinter desktop MVP.

The Web version provides:
- Browser file manager.
- Upload, download, delete and search.
- Client-side AES-GCM encryption using the Web Crypto API.
- Encrypted original filenames and file metadata.
- Vault passphrase stays in the browser tab and is never sent to the server.
- Server stores opaque encrypted blobs.
- Security classification before upload with the 5/10/20/40 target model.
- Security headers and no-cache responses.
- Vercel entrypoint at `api/index.py`.

### Run locally

Python 3.11+:

```bash
pip install -r requirements.txt
python web_app.py
```

Then open `http://127.0.0.1:5000`.

Set `ELEPHANT_SESSION_SECRET` to a long random secret for a stable deployment.

### Storage note

The Web MVP currently uses the server filesystem as its storage provider. This is suitable for a normal server/VPS. Serverless platforms such as Vercel use ephemeral filesystem storage, so Vercel is currently suitable for testing the Web UI/API rather than final persistent storage.

The storage layer is designed so Google Drive, Dropbox, OneDrive, WebDAV, S3-compatible storage, or another provider can be plugged in while the browser continues uploading only encrypted objects.

## Desktop MVP

`elephant_scrape.py` remains the original Tkinter desktop application and retains its storage-provider abstraction, local storage, WebDAV, Google Drive, Dropbox and OneDrive connector foundations, automatic placement, AES-256-GCM encryption and download security checks.

The Web application is intentionally separate from the Tkinter UI.

## Privacy model

The browser encrypts file bytes and original filename metadata before sending them to the Web server. The server stores ciphertext and encrypted metadata. Losing the vault passphrase means the server cannot recover the plaintext.

This is an MVP privacy model, not a claim of a complete production key-recovery or multi-device synchronization system.

## License

See `LICENSE.md`.
