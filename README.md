# Birdhole

A simple, self-hosted, temporary file sharing service with a gallery view, built with Go.

## Features

*   **Temporary File Storage:** Files automatically expire and are deleted after a configurable duration (default 24 hours).
*   **Secure Uploads:** Requires an `UploadKey` for uploading files.
*   **Optional Gallery Access Control:** Configure a `GalleryKey` to restrict access to the gallery view.
*   **Admin Control:** Use an `AdminKey` for administrative actions (like viewing hidden files, deleting files).
*   **Metadata Support:** Uploads can include descriptions, messages, tags, hidden status, custom expiry, and custom key-value metadata.
*   **Unique Filenames:** Generates short, random, unique base32 filenames.
*   **Gallery View:**
    *   Displays uploaded files (respecting hidden status and keys).
    *   Filtering by tags and MIME type.
    *   Sorting by newest/oldest.
    *   Text search for filename/description.
    *   Auto-refreshes.
*   **Detail View:** Shows file details, previews (image, video, audio, text, panorama), metadata, tags, view count, and expiry.
*   **Panorama Support:** Includes an integrated 360° panorama viewer (based on Photo Sphere Viewer).
*   **Thumbnail Generation:** Creates thumbnails for image files displayed in the gallery.
*   **Unique View Counting:** Tracks unique views per file within its lifetime using salted+hashed IP addresses for privacy.
*   **Docker Support:** Includes `Dockerfile` and `docker-compose.yml` for easy containerization.
*   **Bitcask Storage:** Uses Bitcask embedded key-value store for metadata and file content.

## Prerequisites

*   **Go:** Version 1.21 or later.
*   **Docker & Docker Compose (Optional):** For running the application in a container.

## Configuration

Configuration is managed via a `config.toml` file located in the project root.

1.  **Copy Example:** If `config.toml` doesn't exist, copy `config.toml.example` to `config.toml`.
2.  **Edit `config.toml`:**
    *   **Required:**
        *   `UploadKey`: Secret key required for uploads.
        *   `AdminKey`: Secret key required for admin actions.
        *   `ViewCounterSalt`: **CRITICAL:** Change this from the default to a long, random, secret string. Used for hashing IPs for view counts.
    *   **Optional (Defaults Available):**
        *   `Port`: Port the application listens on (default: `"8080"`). **Note:** The logs currently show it configured to `9999`, ensure your config matches your expectation.
        *   `ListenAddr`: Address to bind to (default: `"0.0.0.0"`).
        *   `DefaultExpiry`: Default time before files expire (default: `"24h"`). Use units like `h`, `m`, `s` (e.g., `"168h"` for 7 days).
        *   `BitcaskPath`: Path to the database directory (default: `"./birdhole.db"`). Must match Docker volume mount if using Docker.
        *   `GalleryKey`: Key required to view the gallery. If empty, the gallery is public (default: `""`).
        *   `MaxUploadSizeMB`: Maximum upload size in megabytes (default: `100`).
        *   `BaseURL`: Base URL for constructing links (default: `"/"`). Ensure trailing slash if not root.
        *   `LogLevel`: Logging level (`debug`, `info`, `warn`, `error`) (default: `"info"`).
        *   `ExpiryCheckInterval`: How often to scan for and delete expired files (default: `"10m"`).

## Local Setup

1.  **Clone:** Clone the repository.
2.  **Configure:** Create and edit `config.toml` as described above.
3.  **Build:** `go build`
4.  **Run:** `./birdhole`
5.  Access the application (default: `http://localhost:8080` or the port set in config).

## Docker Setup

1.  **Configure:** Create and edit `config.toml` in the project root. Ensure `BitcaskPath = "./birdhole.db"` and set a secure `ViewCounterSalt`.
2.  **Build:** `docker compose build`
3.  **Run:** `docker compose up -d`
4.  **Access:** `http://localhost:9999` (or the host port mapped in `docker-compose.yml`).
5.  **Logs:** `docker compose logs -f birdhole_container`
6.  **Stop:** `docker compose down`

## Usage / API

*   **Gallery:** Access via `/gallery` (potentially requires `?key=<GalleryKey>` or `?key=<AdminKey>`).
*   **Detail View:** Access via `/detail/{filename}` (potentially requires `?key=<AdminKey>` or `?key=<GalleryKey>` if the file is hidden).
*   **Direct File:** Access via `/{filename}`.
*   **Thumbnail:** Access via `/thumbnail/{filename}`.
*   **Upload:** `POST` to `/`
    *   Requires `X-Api-Key: <UploadKey>` header.
    *   Multipart form data:
        *   `file`: The file content.
        *   `urllen` (optional): Desired length of the unique part of the filename (6-16, default 8).
        *   `description` (optional): File description.
        *   `message` (optional): Message associated with the file.
        *   `tags` (optional): Comma-separated list of tags.
        *   `hidden` (optional): `"true"` to make the file hidden.
        *   `expiry_duration` (optional): Override default expiry (e.g., `"1h"`, `"30m"`).
        *   `panorama` (optional): `"true"` if the image is a 360 panorama.
        *   `meta_*` (optional): Any number of fields prefixed with `meta_` for custom metadata (e.g., `meta_source=irc`).
    *   Returns JSON: `{"url": "<URL_to_file_or_detail>"}`
*   **Delete:** `DELETE` to `/{filename}`
    *   Requires `Authorization: Bearer <AdminKey>` header.

## Terms of Use

Accessing or using the Birdhole service signifies your agreement to these terms. You agree not to upload content that is illegal, harmful, malicious, infringing on copyright, or otherwise objectionable. The service operators reserve the right to remove content or restrict access for any violation. Files uploaded to the service are stored temporarily and are subject to automatic deletion after the configured expiry period. This service is provided "as is", without warranties of any kind. Use of the service is at your own risk.

## Privacy Policy

This policy outlines how Birdhole handles information.

*   **Uploaded Content:** Files and associated metadata (description, tags, etc.) are stored temporarily until the configured expiry time.
*   **Access Control:** Upload, Gallery, and Admin keys are used solely for authentication and authorization purposes.
*   **View Tracking:** To display file view counts, a salted SHA-256 hash derived from the visitor's IP address is stored alongside the file. This hash helps approximate unique views during the file's lifetime and is deleted upon file expiry. Raw IP addresses are not persistently stored for this purpose. Salting enhances the privacy of this mechanism.
*   **Server Logs:** Standard web server access and error logs, which may include IP addresses, may be maintained for operational and security purposes.

Information collected is not shared with third parties except as required to operate the service or comply with legal obligations. Users are responsible for the content they upload. Ensure appropriate access keys are configured to manage content visibility.

## License

MIT License