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

### Cloud connections

The Web app uses **connections, not provider IDs**.

- **Google Drive / Dropbox / OneDrive:** click **Connect** and sign in normally through the provider.
- No client ID or folder ID is entered by the user.
- An existing provider token can also be supplied through **Connect token**.
- Tokens are encrypted at rest with `ELEPHANT_SERVER_KEY`.
- OAuth requires the corresponding server-side provider credentials:
  - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
  - `DROPBOX_CLIENT_ID` / `DROPBOX_CLIENT_SECRET`
  - `ONEDRIVE_CLIENT_ID` / `ONEDRIVE_CLIENT_SECRET`
- `ELEPHANT_SERVER_KEY` must be a Fernet key. Generate one with Python:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

The user experience remains simple: **Connections → Connect → provider login → connected**.

## Stored website mode

Elephant Scrape is not tied to Google Drive for website hosting.

The idea is **storage provider + Elephant Scrape renderer**:

1. HTML/CSS/JavaScript files remain stored on the connected storage provider.
2. Elephant Scrape retrieves the file when the browser requests the site.
3. Elephant Scrape sends the correct web `Content-Type` instead of exposing the storage provider's generic file/download behavior.
4. The browser therefore treats `index.html` as a web page and renders it.
5. The same concept can be implemented for Google Drive, Dropbox, OneDrive, WebDAV and local storage.

The user does not need to know or enter provider file IDs. Internal provider identifiers may be used by Elephant Scrape behind the scenes.

Supported browser resource types in the Web MVP include HTML, CSS, JavaScript, JSON and SVG.

## Storage note

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
