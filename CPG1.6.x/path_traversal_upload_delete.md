# Authenticated path traversal in chunked upload allows arbitrary file write and recursive delete

### Summary

The chunked upload flow allows an authenticated low-privilege user to traverse directories via `identifier` and `filename`, leading to arbitrary path write and recursive delete on the server.

### Details

`uniload.php` forwards chunked upload requests to `upchunk.php` (for example around `uniload.php:207` and `uniload.php:274`).

In `upchunk.php` (around lines 31-46), user-controlled `identifier` and `filename` are concatenated into filesystem paths without path normalization or traversal checks. In `upchunk.php` (around lines 86-105), `cleanup()` recursively deletes the same attacker-controlled path.

The input is obtained through `getEscaped()` from `include/inspekt.php`, but that only performs HTML/SQL-style escaping and does not prevent `../` path traversal.

### PoC

Verified on Coppermine Photo Gallery 1.6.28.

Prerequisite:
Log in as a user who can access the upload flow. In the tested instance, group `Registered` (`group_id=2`) had `can_upload_pictures=1` and `can_create_albums=1`, so administrator privileges were not required.

(1) Send a chunk upload request to `uniload.php` with:
`chunkact=chnk`
`identifier=../../../chunkuser`
`filename=probe.txt`

(2) The request creates:
`<webroot>/chunkuser/probe.txt.part1`

(3) The written file was reachable at:
`http://localhost/chunkuser/probe.txt.part1`

(4) Send another request with:
`chunkact=abrt`
`identifier=../../../chunkuser`
`filename=probe.txt`

(5) The attacker-controlled directory was then recursively deleted by `cleanup()`.

This was reproduced both with an admin session and with a temporary normal registered user account; the normal user case confirms this is not admin-only.

### Impact

Any authenticated user with upload access can write files outside the intended chunk directory and can also trigger recursive deletion of attacker-chosen paths reachable through traversal. This affects confidentiality, integrity, and availability, and may become more severe depending on server configuration and writable locations.