# Pen Testing Examples

## Web Server fingerprinting

Let's break down web server fingerprinting and the provided example step by step.

**What is Web Server Fingerprinting?**

Web server fingerprinting is the process of identifying the software and hardware running a web server.  

* It's like detective work for websites.  The goal is to gather information about the server's operating system, web server software (e.g., Apache, Nginx, IIS), versions, and other details. 

* This information can be valuable for various purposes, both ethical and malicious.  Ethical hackers use it to assess security posture, while attackers might use it to find vulnerabilities.

### Example: Using Netcat for Web Server Fingerprinting

Here's an example of using Netcat to perform basic web server fingerprinting:

1. **Establish a Connection:**

    ```bash
    nc www.google.com 80
    ```
    
    Press the enter key  - then type in the HEAD request as below - in the same terminal window session and press the `Enter` key twice. 

2. **Send a Request:**

    ```bash
    HEAD / HTTP/1.0
    ```

Note: that once you run the `nc` command, you won't see the request you send, but it happens behind the scenes. 

3. **Output (HTTP Response Headers):**

```
HTTP/1.0 200 OK
Content-Type: text/html; charset=ISO-8859-1
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-Y9m77fZaTJIVibaD_w604Q' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
* P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Date: Thu, 13 Feb 2025 20:02:32 GMT
Server: gws
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Expires: Thu, 13 Feb 2025 20:02:32 GMT
Cache-Control: private
Set-Cookie: AEC=AVcja2d7HZ9CpmDp9DQsGqKknCfRZXAiza_0sEuMXEnSiD3r_dHnf_yFMg; expires=Tue, 12-Aug-2025 20:02:32 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
Set-Cookie: NID=521=jPb17ttO5Wry2enPLhRDFZqcKQ-mtKSlUZR8nVPZ7AqhGL3KyqRAae2WWsSa9lCymHvJPrTvzq7Ormguy3WWySTdyxWhc-8s3KfusOng28MV0rMHRAlENrUcSo6exw72Zs345egPJVr--Ztn1jMEweqT23AxiPfQTs6EESD1FQJKnZjpfymcYbNsuZw-vG9wlxDt_Too; expires=Fri, 15-Aug-2025 20:02:32 GMT; path=/; domain=.google.com; HttpOnly
```


**Step-by-Step Explanation of the Example:**

1.  **`nc www.google.com 80`**: This command uses the `nc` (Netcat) utility to establish a network connection to `www.google.com` on port 80.

    *   `nc`: Invokes the Netcat tool.
    *   `www.google.com`: The hostname of the web server you want to connect to. Netcat will resolve this to an IP address behind the scenes.
    *   `80`: The port number. Port 80 is the standard port for HTTP (unencrypted web traffic).

2.  **`HEAD / HTTP/1.0`**:  *After* the connection is established (you won't see this in the output you provided, but it happens behind the scenes), this command is *sent* to the web server.

    *   `HEAD`: This is an HTTP method.  Unlike `GET`, which retrieves the entire web page, `HEAD` only requests the *headers* of the page.  Headers contain metadata about the web page and the server. This is much more efficient for fingerprinting.
    *   `/`: This represents the root path of the website (the main page).
    *   `HTTP/1.0`: This specifies the HTTP version.  Using 1.0 can sometimes provide slightly different output than 1.1, which might be useful for fingerprinting (though in this case, Google responded with HTTP/1.0 regardless).

3.  **The Output (HTTP Response Headers):**  The output you provided is the web server's response to the `HEAD` request.  It consists of HTTP headers. Let's examine the key headers:

    *   **`HTTP/1.0 200 OK`:** This is the status line.  `HTTP/1.0` confirms the HTTP version used in the response. `200 OK` means the request was successful.

    *   **`Content-Type: text/html; charset=ISO-8859-1`:** This header indicates that if you were to request the full page, it would be HTML content encoded using the ISO-8859-1 character set.

    *   **`Content-Security-Policy-Report-Only: ...`:** This header is related to Content Security Policy (CSP). It defines a set of rules that the browser should enforce when loading the page, helping to mitigate XSS attacks. The `Report-Only` directive means that violations of the policy are reported but not blocked.

    *   **`P3P: CP="..."`:** This header relates to the now-deprecated Platform for Privacy Preferences (P3P).  The message indicates that no actual P3P policy is in place.

    *   **`Date: Thu, 13 Feb 2025 20:02:32 GMT`:** The current date and time on the server.

    *   **`Server: gws`:**  *This is the most important header for fingerprinting in this example.*  `gws` stands for Google Web Server.  This tells us that Google uses its own custom web server software.  It's a key piece of information.  If it were Apache, Nginx, or IIS, you would see that here.

    *   **`X-XSS-Protection: 0`:**  This header indicates that XSS (Cross-Site Scripting) protection is disabled.

    *   **`X-Frame-Options: SAMEORIGIN`:** This header helps prevent clickjacking attacks by specifying that the page can only be displayed within a frame on the same origin as the page itself.

    *   **`Expires: Thu, 13 Feb 2025 20:02:32 GMT`:**  Specifies when the content expires. In this case, it's the same as the current time, indicating that the content should not be cached.

    *   **`Cache-Control: private`:**  Instructs browsers and other caches that the response is specific to the user and should not be cached.

    *   **`Set-Cookie: ...`:** These headers set cookies in the user's browser. Cookies are used for various purposes, such as session management and tracking.  The `HttpOnly` flag makes the cookie inaccessible to JavaScript, which improves security. The `SameSite` attribute helps prevent CSRF attacks.

**Key Takeaways about Fingerprinting:**

*   **Server Header is Key:** The `Server` header is usually the most informative for basic web server fingerprinting.
*   **Other Headers Provide Clues:** Other headers can give additional information about the server configuration, technologies used, and security settings.
*   **Tools Like Nmap:**  While Netcat is useful for basic examples, tools like Nmap are much more powerful for comprehensive fingerprinting. They can perform more advanced scans and identify a wider range of services and versions.
*   **Ethical Considerations:** Always remember to practice ethical hacking techniques only on systems you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.
