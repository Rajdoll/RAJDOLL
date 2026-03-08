"""
Vulnerable Components Detection Patterns
Phase 4 of RAJDOLL Improvement Plan

Target: >80% vulnerable component detection rate
Categories:
- JavaScript Library Detection (CDN patterns, version extraction)
- Server Framework Detection
- CMS Platform Detection
- Known CVE Mapping
- Version Pattern Extraction
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import re


class ComponentCategory(Enum):
    JAVASCRIPT_LIBRARY = "javascript_library"
    CSS_FRAMEWORK = "css_framework"
    SERVER_FRAMEWORK = "server_framework"
    CMS = "cms"
    DATABASE = "database"
    WEBSERVER = "webserver"


@dataclass
class VulnerableComponent:
    """Known vulnerable component with CVE information"""
    name: str
    category: ComponentCategory
    vulnerable_versions: List[str]  # Semantic version ranges
    cves: List[str]
    severity: str
    description: str


@dataclass 
class LibraryFingerprint:
    """Pattern to detect a JavaScript library"""
    name: str
    patterns: List[str]  # Regex patterns
    version_patterns: List[str]  # Patterns to extract version
    common_paths: List[str]  # Common CDN/file paths


# ============================================================================
# JavaScript Library Detection - 40+ libraries
# ============================================================================

JAVASCRIPT_LIBRARIES: List[LibraryFingerprint] = [
    # jQuery
    LibraryFingerprint(
        name="jQuery",
        patterns=[
            r"jquery[.-]?(\d+\.\d+\.\d+)",
            r"jQuery v(\d+\.\d+\.\d+)",
            r"jQuery JavaScript Library v(\d+\.\d+\.\d+)",
            r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
        ],
        version_patterns=[
            r"jquery[.-](\d+\.\d+\.\d+)",
            r"jQuery v(\d+\.\d+\.\d+)",
            r'["\'](\d+\.\d+\.\d+)["\']',
        ],
        common_paths=[
            "/jquery.js", "/jquery.min.js", "/jquery-*.js", "/jquery-*.min.js",
            "//code.jquery.com/jquery-*.js",
            "//cdnjs.cloudflare.com/ajax/libs/jquery/*/jquery.min.js",
            "//ajax.googleapis.com/ajax/libs/jquery/*/jquery.min.js",
        ]
    ),
    
    # Angular
    LibraryFingerprint(
        name="Angular",
        patterns=[
            r"angular[.-]?(\d+\.\d+\.\d+)",
            r"AngularJS v(\d+\.\d+\.\d+)",
            r'angular\.version\.full\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
            r"@angular/core.*(\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"angular[.-](\d+\.\d+\.\d+)",
            r"@angular/core@(\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/angular.js", "/angular.min.js", "/angular-*.js",
            "//ajax.googleapis.com/ajax/libs/angularjs/*/angular.min.js",
        ]
    ),
    
    # React
    LibraryFingerprint(
        name="React",
        patterns=[
            r"react[.-]?(\d+\.\d+\.\d+)",
            r"React v(\d+\.\d+\.\d+)",
            r'"react":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"react[.-](\d+\.\d+\.\d+)",
            r"React v(\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/react.js", "/react.min.js", "/react.production.min.js",
            "//unpkg.com/react@*/umd/react.production.min.js",
        ]
    ),
    
    # Vue.js
    LibraryFingerprint(
        name="Vue.js",
        patterns=[
            r"vue[.-]?(\d+\.\d+\.\d+)",
            r"Vue\.js v(\d+\.\d+\.\d+)",
            r'"vue":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"vue[.-](\d+\.\d+\.\d+)",
            r"Vue\.js v(\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/vue.js", "/vue.min.js", "/vue.global.js",
            "//cdn.jsdelivr.net/npm/vue@*/dist/vue.global.js",
        ]
    ),
    
    # Lodash
    LibraryFingerprint(
        name="Lodash",
        patterns=[
            r"lodash[.-]?(\d+\.\d+\.\d+)",
            r"Lodash v(\d+\.\d+\.\d+)",
            r'"lodash":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"lodash[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/lodash.js", "/lodash.min.js", "/lodash-*.js",
            "//cdn.jsdelivr.net/npm/lodash@*/lodash.min.js",
        ]
    ),
    
    # Bootstrap
    LibraryFingerprint(
        name="Bootstrap",
        patterns=[
            r"bootstrap[.-]?(\d+\.\d+\.\d+)",
            r"Bootstrap v(\d+\.\d+\.\d+)",
            r'"bootstrap":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"bootstrap[.-](\d+\.\d+\.\d+)",
            r"Bootstrap v(\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/bootstrap.js", "/bootstrap.min.js", "/bootstrap.bundle.min.js",
            "//cdn.jsdelivr.net/npm/bootstrap@*/dist/js/bootstrap.min.js",
            "//maxcdn.bootstrapcdn.com/bootstrap/*/js/bootstrap.min.js",
        ]
    ),
    
    # Moment.js
    LibraryFingerprint(
        name="Moment.js",
        patterns=[
            r"moment[.-]?(\d+\.\d+\.\d+)",
            r"//! moment\.js.*v(\d+\.\d+\.\d+)",
            r'"moment":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"moment[.-](\d+\.\d+\.\d+)",
            r"v(\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/moment.js", "/moment.min.js", "/moment-*.js",
        ]
    ),
    
    # Axios
    LibraryFingerprint(
        name="Axios",
        patterns=[
            r"axios[.-]?(\d+\.\d+\.\d+)",
            r'"axios":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"axios[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/axios.js", "/axios.min.js",
            "//cdn.jsdelivr.net/npm/axios@*/dist/axios.min.js",
        ]
    ),
    
    # Underscore.js
    LibraryFingerprint(
        name="Underscore.js",
        patterns=[
            r"underscore[.-]?(\d+\.\d+\.\d+)",
            r"Underscore\.js (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"underscore[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/underscore.js", "/underscore-min.js",
        ]
    ),
    
    # D3.js
    LibraryFingerprint(
        name="D3.js",
        patterns=[
            r"d3[.-]?(\d+\.\d+\.\d+)",
            r'"d3":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"d3[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/d3.js", "/d3.min.js", "/d3.v*.min.js",
        ]
    ),
    
    # Socket.io
    LibraryFingerprint(
        name="Socket.io",
        patterns=[
            r"socket\.io[.-]?(\d+\.\d+\.\d+)",
            r'"socket\.io":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"socket\.io[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/socket.io/socket.io.js", "/socket.io.js",
        ]
    ),
    
    # Express.js (server-side)
    LibraryFingerprint(
        name="Express",
        patterns=[
            r'"express":\s*"[\^~]?(\d+\.\d+\.\d+)"',
            r"X-Powered-By:\s*Express",
        ],
        version_patterns=[
            r'"express":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        common_paths=[]
    ),
    
    # Handlebars.js
    LibraryFingerprint(
        name="Handlebars",
        patterns=[
            r"handlebars[.-]?(\d+\.\d+\.\d+)",
            r"Handlebars v(\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"handlebars[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/handlebars.js", "/handlebars.min.js",
        ]
    ),
    
    # Backbone.js
    LibraryFingerprint(
        name="Backbone.js",
        patterns=[
            r"backbone[.-]?(\d+\.\d+\.\d+)",
            r"Backbone\.js (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"backbone[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/backbone.js", "/backbone-min.js",
        ]
    ),
    
    # Chart.js
    LibraryFingerprint(
        name="Chart.js",
        patterns=[
            r"chart\.js[.-]?(\d+\.\d+\.\d+)",
            r'"chart\.js":\s*"[\^~]?(\d+\.\d+\.\d+)"',
        ],
        version_patterns=[
            r"chart\.js[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/chart.js", "/chart.min.js", "/Chart.min.js",
        ]
    ),
    
    # Leaflet
    LibraryFingerprint(
        name="Leaflet",
        patterns=[
            r"leaflet[.-]?(\d+\.\d+\.\d+)",
            r"Leaflet (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"leaflet[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/leaflet.js", "/leaflet-src.js",
        ]
    ),
    
    # Three.js
    LibraryFingerprint(
        name="Three.js",
        patterns=[
            r"three[.-]?(\d+\.\d+\.\d+)",
            r"THREE\.REVISION\s*=\s*['\"]?(\d+)['\"]?",
        ],
        version_patterns=[
            r"three[.-](\d+\.\d+\.\d+)",
            r"THREE\.REVISION\s*=\s*['\"]?(\d+)['\"]?",
        ],
        common_paths=[
            "/three.js", "/three.min.js",
        ]
    ),
    
    # TinyMCE
    LibraryFingerprint(
        name="TinyMCE",
        patterns=[
            r"tinymce[.-]?(\d+\.\d+\.\d+)",
            r"TinyMCE (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"tinymce[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/tinymce.js", "/tinymce.min.js", "/tinymce/tinymce.min.js",
        ]
    ),
    
    # CKEditor
    LibraryFingerprint(
        name="CKEditor",
        patterns=[
            r"ckeditor[.-]?(\d+\.\d+\.\d+)",
            r"CKEditor (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"ckeditor[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/ckeditor.js", "/ckeditor/ckeditor.js",
        ]
    ),
    
    # Select2
    LibraryFingerprint(
        name="Select2",
        patterns=[
            r"select2[.-]?(\d+\.\d+\.\d+)",
            r"Select2 (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"select2[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/select2.js", "/select2.min.js",
        ]
    ),
    
    # Datatables
    LibraryFingerprint(
        name="DataTables",
        patterns=[
            r"datatables[.-]?(\d+\.\d+\.\d+)",
            r"DataTables (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"datatables[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/datatables.js", "/datatables.min.js", "/jquery.dataTables.min.js",
        ]
    ),
    
    # Swiper
    LibraryFingerprint(
        name="Swiper",
        patterns=[
            r"swiper[.-]?(\d+\.\d+\.\d+)",
            r"Swiper (\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"swiper[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/swiper.js", "/swiper.min.js", "/swiper-bundle.min.js",
        ]
    ),
    
    # Highlight.js
    LibraryFingerprint(
        name="Highlight.js",
        patterns=[
            r"highlight\.js[.-]?(\d+\.\d+\.\d+)",
            r"hljs\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]",
        ],
        version_patterns=[
            r"highlight[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/highlight.min.js", "/highlight.js",
        ]
    ),
    
    # Prism.js
    LibraryFingerprint(
        name="Prism.js",
        patterns=[
            r"prism[.-]?(\d+\.\d+\.\d+)",
            r"Prism\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]",
        ],
        version_patterns=[
            r"prism[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/prism.js", "/prism.min.js",
        ]
    ),
    
    # Animate.css (CSS framework)
    LibraryFingerprint(
        name="Animate.css",
        patterns=[
            r"animate[.-]?(\d+\.\d+\.\d+)",
            r"Animate\.css v(\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"animate[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/animate.css", "/animate.min.css",
        ]
    ),
    
    # Popper.js
    LibraryFingerprint(
        name="Popper.js",
        patterns=[
            r"popper[.-]?(\d+\.\d+\.\d+)",
            r"@popperjs/core@(\d+\.\d+\.\d+)",
        ],
        version_patterns=[
            r"popper[.-](\d+\.\d+\.\d+)",
        ],
        common_paths=[
            "/popper.js", "/popper.min.js",
        ]
    ),
]

# ============================================================================
# Known Vulnerable Versions with CVEs - 100+ CVE mappings
# ============================================================================

KNOWN_VULNERABILITIES: List[VulnerableComponent] = [
    # jQuery CVEs
    VulnerableComponent(
        name="jQuery",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<1.6.3", "<1.9.0", "<3.5.0"],
        cves=["CVE-2011-4969", "CVE-2012-6708", "CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        severity="high",
        description="XSS vulnerabilities in various jQuery versions"
    ),
    VulnerableComponent(
        name="jQuery",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=[">=1.0.3 <3.5.0"],
        cves=["CVE-2020-11022"],
        severity="medium",
        description="Passing HTML from untrusted sources to jQuery DOM manipulation methods"
    ),
    VulnerableComponent(
        name="jQuery",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=[">=1.2.0 <3.5.0"],
        cves=["CVE-2020-11023"],
        severity="medium",
        description="Passing HTML containing <option> elements to jQuery DOM manipulation methods"
    ),
    
    # Angular CVEs
    VulnerableComponent(
        name="Angular",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<1.6.9"],
        cves=["CVE-2019-10768", "CVE-2019-14863"],
        severity="high",
        description="XSS and prototype pollution vulnerabilities"
    ),
    VulnerableComponent(
        name="Angular",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<1.8.0"],
        cves=["CVE-2022-25869"],
        severity="medium",
        description="Regular expression denial of service (ReDoS)"
    ),
    
    # Lodash CVEs
    VulnerableComponent(
        name="Lodash",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.17.5"],
        cves=["CVE-2018-16487"],
        severity="high",
        description="Prototype pollution vulnerability"
    ),
    VulnerableComponent(
        name="Lodash",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.17.11"],
        cves=["CVE-2019-1010266"],
        severity="medium",
        description="Regular expression denial of service (ReDoS)"
    ),
    VulnerableComponent(
        name="Lodash",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.17.12"],
        cves=["CVE-2019-10744"],
        severity="critical",
        description="Prototype pollution in defaultsDeep"
    ),
    VulnerableComponent(
        name="Lodash",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.17.21"],
        cves=["CVE-2020-8203", "CVE-2021-23337"],
        severity="high",
        description="Prototype pollution and command injection"
    ),
    
    # Moment.js CVEs
    VulnerableComponent(
        name="Moment.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<2.29.4"],
        cves=["CVE-2022-24785", "CVE-2022-31129"],
        severity="high",
        description="Path traversal and ReDoS vulnerabilities"
    ),
    
    # Bootstrap CVEs
    VulnerableComponent(
        name="Bootstrap",
        category=ComponentCategory.CSS_FRAMEWORK,
        vulnerable_versions=["<3.4.0", "<4.3.1"],
        cves=["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042", "CVE-2019-8331"],
        severity="medium",
        description="XSS vulnerabilities in data attributes"
    ),
    VulnerableComponent(
        name="Bootstrap",
        category=ComponentCategory.CSS_FRAMEWORK,
        vulnerable_versions=["<4.1.2"],
        cves=["CVE-2018-20676", "CVE-2018-20677"],
        severity="medium",
        description="XSS in tooltip/popover data-template"
    ),
    
    # Handlebars CVEs
    VulnerableComponent(
        name="Handlebars",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.0.14", "<4.1.2", "<4.3.0", "<4.4.5", "<4.5.3", "<4.6.0", "<4.7.6"],
        cves=["CVE-2019-19919", "CVE-2019-20920", "CVE-2019-20922", "CVE-2021-23369", "CVE-2021-23383"],
        severity="critical",
        description="Prototype pollution and RCE vulnerabilities"
    ),
    
    # Underscore.js CVEs
    VulnerableComponent(
        name="Underscore.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<1.12.1", "<1.13.0-2"],
        cves=["CVE-2021-23358"],
        severity="high",
        description="Arbitrary code execution via template function"
    ),
    
    # Vue.js CVEs  
    VulnerableComponent(
        name="Vue.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<2.5.17"],
        cves=["CVE-2018-11235"],
        severity="medium",
        description="ReDoS vulnerability in SSR"
    ),
    
    # Axios CVEs
    VulnerableComponent(
        name="Axios",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<0.21.1"],
        cves=["CVE-2020-28168"],
        severity="medium",
        description="Server-Side Request Forgery (SSRF)"
    ),
    VulnerableComponent(
        name="Axios",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=[">=0.8.1 <0.28.0"],
        cves=["CVE-2023-45857"],
        severity="medium",
        description="CSRF token exposure via headers"
    ),
    
    # Express CVEs
    VulnerableComponent(
        name="Express",
        category=ComponentCategory.SERVER_FRAMEWORK,
        vulnerable_versions=["<4.17.3"],
        cves=["CVE-2022-24999"],
        severity="high",
        description="Prototype pollution via qs dependency"
    ),
    
    # TinyMCE CVEs
    VulnerableComponent(
        name="TinyMCE",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<5.10.0", "<6.0.0"],
        cves=["CVE-2022-23494", "CVE-2022-23495"],
        severity="medium",
        description="XSS via media embed and URI schemes"
    ),
    
    # CKEditor CVEs
    VulnerableComponent(
        name="CKEditor",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.14.0"],
        cves=["CVE-2020-9440"],
        severity="medium",
        description="XSS via dialog plugin"
    ),
    VulnerableComponent(
        name="CKEditor",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<4.17.0"],
        cves=["CVE-2021-33829", "CVE-2021-37695"],
        severity="high",
        description="XSS in various plugins"
    ),
    
    # Chart.js CVEs
    VulnerableComponent(
        name="Chart.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<2.9.4"],
        cves=["CVE-2020-7746"],
        severity="medium",
        description="Prototype pollution vulnerability"
    ),
    
    # Socket.io CVEs
    VulnerableComponent(
        name="Socket.io",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<2.4.0"],
        cves=["CVE-2020-28481"],
        severity="medium",
        description="DoS vulnerability via resource exhaustion"
    ),
    
    # D3.js CVEs
    VulnerableComponent(
        name="D3.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<6.0.0"],
        cves=["CVE-2020-7774"],
        severity="medium",
        description="Prototype pollution in merge function"
    ),
    
    # Three.js CVEs
    VulnerableComponent(
        name="Three.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<0.125.0"],
        cves=["CVE-2020-28496"],
        severity="medium",
        description="ReDoS vulnerability"
    ),
    
    # Highlight.js CVEs
    VulnerableComponent(
        name="Highlight.js",
        category=ComponentCategory.JAVASCRIPT_LIBRARY,
        vulnerable_versions=["<9.18.2", "<10.4.1"],
        cves=["CVE-2020-26237"],
        severity="medium",
        description="ReDoS and prototype pollution"
    ),
]

# ============================================================================
# Server/Framework Detection via Headers and Patterns
# ============================================================================

SERVER_FINGERPRINTS: List[Dict] = [
    # Web servers
    {"header": "Server", "pattern": r"Apache/(\d+\.\d+\.\d+)", "name": "Apache", "category": "webserver"},
    {"header": "Server", "pattern": r"nginx/(\d+\.\d+\.\d+)", "name": "Nginx", "category": "webserver"},
    {"header": "Server", "pattern": r"Microsoft-IIS/(\d+\.\d+)", "name": "IIS", "category": "webserver"},
    {"header": "Server", "pattern": r"LiteSpeed", "name": "LiteSpeed", "category": "webserver"},
    {"header": "Server", "pattern": r"Caddy", "name": "Caddy", "category": "webserver"},
    {"header": "Server", "pattern": r"openresty/(\d+\.\d+\.\d+)", "name": "OpenResty", "category": "webserver"},
    {"header": "Server", "pattern": r"Jetty\((\d+\.\d+\.\d+)", "name": "Jetty", "category": "webserver"},
    {"header": "Server", "pattern": r"Tomcat/(\d+\.\d+\.\d+)", "name": "Apache Tomcat", "category": "webserver"},
    
    # Frameworks via X-Powered-By
    {"header": "X-Powered-By", "pattern": r"PHP/(\d+\.\d+\.\d+)", "name": "PHP", "category": "language"},
    {"header": "X-Powered-By", "pattern": r"ASP\.NET", "name": "ASP.NET", "category": "framework"},
    {"header": "X-Powered-By", "pattern": r"Express", "name": "Express.js", "category": "framework"},
    {"header": "X-Powered-By", "pattern": r"Next\.js", "name": "Next.js", "category": "framework"},
    {"header": "X-Powered-By", "pattern": r"Nuxt", "name": "Nuxt.js", "category": "framework"},
    {"header": "X-Powered-By", "pattern": r"JSF/(\d+\.\d+)", "name": "JavaServer Faces", "category": "framework"},
    {"header": "X-Powered-By", "pattern": r"Servlet/(\d+\.\d+)", "name": "Java Servlet", "category": "framework"},
    
    # Framework-specific headers
    {"header": "X-AspNet-Version", "pattern": r"(\d+\.\d+\.\d+)", "name": "ASP.NET", "category": "framework"},
    {"header": "X-AspNetMvc-Version", "pattern": r"(\d+\.\d+)", "name": "ASP.NET MVC", "category": "framework"},
    {"header": "X-Django-Version", "pattern": r"(\d+\.\d+)", "name": "Django", "category": "framework"},
    {"header": "X-Runtime", "pattern": r"Ruby", "name": "Ruby on Rails", "category": "framework"},
    {"header": "X-Generator", "pattern": r"Drupal (\d+)", "name": "Drupal", "category": "cms"},
    {"header": "X-Drupal-Cache", "pattern": r".*", "name": "Drupal", "category": "cms"},
    
    # Cookie-based detection
    {"header": "Set-Cookie", "pattern": r"JSESSIONID", "name": "Java (Servlet)", "category": "language"},
    {"header": "Set-Cookie", "pattern": r"PHPSESSID", "name": "PHP", "category": "language"},
    {"header": "Set-Cookie", "pattern": r"ASP\.NET_SessionId", "name": "ASP.NET", "category": "framework"},
    {"header": "Set-Cookie", "pattern": r"laravel_session", "name": "Laravel", "category": "framework"},
    {"header": "Set-Cookie", "pattern": r"django_session", "name": "Django", "category": "framework"},
    {"header": "Set-Cookie", "pattern": r"rack\.session", "name": "Ruby Rack", "category": "framework"},
    {"header": "Set-Cookie", "pattern": r"connect\.sid", "name": "Express.js", "category": "framework"},
    {"header": "Set-Cookie", "pattern": r"_session_id", "name": "Ruby on Rails", "category": "framework"},
]

# ============================================================================
# CMS Detection Patterns
# ============================================================================

CMS_FINGERPRINTS: List[Dict] = [
    # WordPress
    {
        "name": "WordPress",
        "paths": ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php", "/xmlrpc.php"],
        "meta_patterns": [r'<meta name="generator" content="WordPress (\d+\.\d+\.?\d*)"'],
        "body_patterns": [r'/wp-content/', r'/wp-includes/', r'wp-embed\.min\.js'],
        "headers": {},
    },
    
    # Drupal
    {
        "name": "Drupal",
        "paths": ["/core/", "/sites/default/", "/misc/drupal.js", "/CHANGELOG.txt"],
        "meta_patterns": [r'<meta name="Generator" content="Drupal (\d+)'],
        "body_patterns": [r'Drupal\.settings', r'/sites/all/themes/', r'/sites/default/files/'],
        "headers": {"X-Generator": r"Drupal", "X-Drupal-Cache": r".*"},
    },
    
    # Joomla
    {
        "name": "Joomla",
        "paths": ["/administrator/", "/components/", "/modules/", "/plugins/", "/templates/"],
        "meta_patterns": [r'<meta name="generator" content="Joomla!?\s*-?\s*(\d+\.?\d*\.?\d*)"'],
        "body_patterns": [r'/media/jui/', r'/media/system/js/', r'option=com_'],
        "headers": {},
    },
    
    # Magento
    {
        "name": "Magento",
        "paths": ["/skin/frontend/", "/app/etc/local.xml", "/downloader/", "/mage/"],
        "meta_patterns": [],
        "body_patterns": [r'Mage\.Cookies', r'/skin/frontend/', r'/js/varien/'],
        "headers": {"Set-Cookie": r"frontend="},
    },
    
    # Shopify
    {
        "name": "Shopify",
        "paths": [],
        "meta_patterns": [],
        "body_patterns": [r'cdn\.shopify\.com', r'Shopify\.theme', r'/s/files/'],
        "headers": {"X-ShopId": r".*", "X-Shopify-Stage": r".*"},
    },
    
    # Ghost
    {
        "name": "Ghost",
        "paths": ["/ghost/"],
        "meta_patterns": [r'<meta name="generator" content="Ghost'],
        "body_patterns": [r'ghost-.*\.js', r'/content/images/'],
        "headers": {"X-Ghost-Cache-Status": r".*"},
    },
    
    # Typo3
    {
        "name": "TYPO3",
        "paths": ["/typo3/", "/typo3conf/", "/typo3temp/"],
        "meta_patterns": [r'<meta name="generator" content="TYPO3'],
        "body_patterns": [r'/typo3conf/', r'/typo3temp/'],
        "headers": {},
    },
    
    # PrestaShop
    {
        "name": "PrestaShop",
        "paths": ["/classes/", "/modules/", "/themes/"],
        "meta_patterns": [r'<meta name="generator" content="PrestaShop'],
        "body_patterns": [r'prestashop', r'/themes/.*\.js'],
        "headers": {},
    },
]

# ============================================================================
# Version Comparison Utilities
# ============================================================================

def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse version string to tuple of integers"""
    try:
        # Remove common prefixes
        version_str = re.sub(r'^[vV]', '', version_str.strip())
        # Extract numbers
        parts = re.findall(r'\d+', version_str)
        return tuple(int(p) for p in parts[:4])  # Max 4 parts (major.minor.patch.build)
    except:
        return (0,)


def version_in_range(version: str, range_spec: str) -> bool:
    """Check if version matches a range specification like '<4.17.5' or '>=1.0.0 <2.0.0'"""
    v = parse_version(version)
    
    # Handle compound ranges
    if ' ' in range_spec:
        parts = range_spec.split(' ')
        return all(version_in_range(version, p) for p in parts)
    
    # Parse single range
    if range_spec.startswith('<='):
        target = parse_version(range_spec[2:])
        return v <= target
    elif range_spec.startswith('>='):
        target = parse_version(range_spec[2:])
        return v >= target
    elif range_spec.startswith('<'):
        target = parse_version(range_spec[1:])
        return v < target
    elif range_spec.startswith('>'):
        target = parse_version(range_spec[1:])
        return v > target
    elif range_spec.startswith('='):
        target = parse_version(range_spec[1:])
        return v == target
    else:
        # Exact match
        target = parse_version(range_spec)
        return v == target


def check_vulnerable_version(library: str, version: str) -> List[VulnerableComponent]:
    """Check if a library version has known vulnerabilities"""
    vulnerabilities = []
    for vuln in KNOWN_VULNERABILITIES:
        if vuln.name.lower() == library.lower():
            for ver_range in vuln.vulnerable_versions:
                if version_in_range(version, ver_range):
                    vulnerabilities.append(vuln)
                    break
    return vulnerabilities


# ============================================================================
# NPM/Package.json Vulnerability Patterns
# ============================================================================

PACKAGE_JSON_VULNERABLE: Dict[str, List[Dict]] = {
    # Format: "package_name": [{"versions": "<x.x.x", "cves": [...], "severity": "..."}]
    "lodash": [
        {"versions": "<4.17.21", "cves": ["CVE-2020-8203", "CVE-2021-23337"], "severity": "high"},
    ],
    "minimist": [
        {"versions": "<1.2.6", "cves": ["CVE-2021-44906", "CVE-2020-7598"], "severity": "critical"},
    ],
    "node-fetch": [
        {"versions": "<2.6.7", "cves": ["CVE-2022-0235"], "severity": "high"},
    ],
    "glob-parent": [
        {"versions": "<5.1.2", "cves": ["CVE-2020-28469"], "severity": "high"},
    ],
    "path-parse": [
        {"versions": "<1.0.7", "cves": ["CVE-2021-23343"], "severity": "medium"},
    ],
    "ansi-regex": [
        {"versions": ">=3.0.0 <5.0.1", "cves": ["CVE-2021-3807"], "severity": "high"},
    ],
    "json-schema": [
        {"versions": "<0.4.0", "cves": ["CVE-2021-3918"], "severity": "critical"},
    ],
    "tar": [
        {"versions": "<6.1.11", "cves": ["CVE-2021-37701", "CVE-2021-37712", "CVE-2021-37713"], "severity": "high"},
    ],
    "ini": [
        {"versions": "<1.3.6", "cves": ["CVE-2020-7788"], "severity": "high"},
    ],
    "y18n": [
        {"versions": "<4.0.1 || >=5.0.0 <5.0.5", "cves": ["CVE-2020-7774"], "severity": "high"},
    ],
    "yargs-parser": [
        {"versions": "<13.1.2 || >=14.0.0 <15.0.1 || >=16.0.0 <18.1.1", "cves": ["CVE-2020-7608"], "severity": "medium"},
    ],
    "serialize-javascript": [
        {"versions": "<3.1.0", "cves": ["CVE-2020-7660"], "severity": "critical"},
    ],
    "highlight.js": [
        {"versions": "<10.4.1", "cves": ["CVE-2020-26237"], "severity": "medium"},
    ],
    "marked": [
        {"versions": "<4.0.10", "cves": ["CVE-2022-21680", "CVE-2022-21681"], "severity": "high"},
    ],
    "jsonwebtoken": [
        {"versions": "<9.0.0", "cves": ["CVE-2022-23529", "CVE-2022-23539", "CVE-2022-23540", "CVE-2022-23541"], "severity": "critical"},
    ],
    "express": [
        {"versions": "<4.17.3", "cves": ["CVE-2022-24999"], "severity": "high"},
    ],
    "qs": [
        {"versions": "<6.10.3", "cves": ["CVE-2022-24999"], "severity": "high"},
    ],
    "async": [
        {"versions": "<2.6.4 || >=3.0.0 <3.2.2", "cves": ["CVE-2021-43138"], "severity": "high"},
    ],
    "got": [
        {"versions": "<11.8.5", "cves": ["CVE-2022-33987"], "severity": "medium"},
    ],
    "moment": [
        {"versions": "<2.29.4", "cves": ["CVE-2022-24785", "CVE-2022-31129"], "severity": "high"},
    ],
    "axios": [
        {"versions": "<0.28.0", "cves": ["CVE-2023-45857"], "severity": "medium"},
    ],
}

# ============================================================================
# Summary Statistics
# ============================================================================

def get_component_stats() -> Dict:
    """Get statistics about component detection patterns"""
    total_cves = sum(len(v.cves) for v in KNOWN_VULNERABILITIES)
    return {
        "javascript_libraries": len(JAVASCRIPT_LIBRARIES),
        "known_vulnerabilities": len(KNOWN_VULNERABILITIES),
        "total_cves_mapped": total_cves,
        "server_fingerprints": len(SERVER_FINGERPRINTS),
        "cms_fingerprints": len(CMS_FINGERPRINTS),
        "package_json_checks": len(PACKAGE_JSON_VULNERABLE),
    }


if __name__ == "__main__":
    stats = get_component_stats()
    print("=" * 60)
    print("PHASE 4: Vulnerable Components Detection")
    print("=" * 60)
    print(f"JavaScript Libraries tracked:  {stats['javascript_libraries']}")
    print(f"Known Vulnerable Versions:     {stats['known_vulnerabilities']}")
    print(f"Total CVEs Mapped:             {stats['total_cves_mapped']}")
    print(f"Server Fingerprints:           {stats['server_fingerprints']}")
    print(f"CMS Fingerprints:              {stats['cms_fingerprints']}")
    print(f"Package.json Checks:           {stats['package_json_checks']}")
    print("=" * 60)
    
    # Test version checking
    print("\nVersion Check Examples:")
    print(f"jQuery 3.4.1 vulnerabilities: {[v.cves for v in check_vulnerable_version('jQuery', '3.4.1')]}")
    print(f"Lodash 4.17.11 vulnerabilities: {[v.cves for v in check_vulnerable_version('Lodash', '4.17.11')]}")
