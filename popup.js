// BreachBlocker - Security Analysis Extension

// Security analysis patterns and configurations
const securityPatterns = {
  securityHeaders: {
    'Content-Security-Policy': {
      description: 'Prevents XSS and code injection attacks',
      severity: 'high',
      icon: '🛡️'
    },
    'X-Frame-Options': {
      description: 'Prevents clickjacking attacks',
      severity: 'medium',
      icon: '🖼️'
    },
    'X-Content-Type-Options': {
      description: 'Prevents MIME type sniffing',
      severity: 'medium',
      icon: '📄'
    },
    'Strict-Transport-Security': {
      description: 'Enforces HTTPS connections',
      severity: 'high',
      icon: '🔒'
    },
    'X-XSS-Protection': {
      description: 'Enables XSS filtering',
      severity: 'medium',
      icon: '⚡'
    },
    'Referrer-Policy': {
      description: 'Controls referrer information',
      severity: 'low',
      icon: '🔗'
    }
  },
  malwarePatterns: [
    'eval(',
    'document.write(',
    'innerHTML =',
    'outerHTML =',
    'javascript:',
    'vbscript:',
    'data:text/html',
    'base64,',
    'fromCharCode',
    'unescape(',
    'decodeURIComponent('
  ],
  suspiciousScripts: [
    'crypto',
    'mining',
    'coinhive',
    'jsecoin',
    'authedmine',
    'cnhv.co',
    'coin-hive.com'
  ]
};

// Initialize security scanner when popup loads
document.addEventListener('DOMContentLoaded', () => {
  initializeSecurityScanner();
});

// Initialize the security scanner interface
function initializeSecurityScanner() {
  const scanBtn = document.getElementById('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', performSecurityScan);
  }
}

// Main security scan function
async function performSecurityScan() {
  const scanBtn = document.getElementById('scanBtn');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  
  // Show loading state
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.textContent = 'SCANNING...';
  }
  if (loading) loading.style.display = 'block';
  if (results) results.innerHTML = '';
  
  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    // Execute security analysis in the page context
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // All security analysis functions defined inline
        function analyzeSecurityHeaders() {
          const securityHeaders = {
            'Content-Security-Policy': { icon: 'CSP' },
            'X-Frame-Options': { icon: 'FRAME' },
            'X-Content-Type-Options': { icon: 'MIME' },
            'Strict-Transport-Security': { icon: 'HSTS' },
            'X-XSS-Protection': { icon: 'XSS' },
            'Referrer-Policy': { icon: 'REF' }
          };
          
          const headers = {};
          const metaTags = document.querySelectorAll('meta[http-equiv]');
          
          metaTags.forEach(meta => {
            const httpEquiv = meta.getAttribute('http-equiv');
            const content = meta.getAttribute('content');
            if (httpEquiv && content) {
              headers[httpEquiv] = content;
            }
          });
          
          return {
            present: Object.keys(headers),
            missing: Object.keys(securityHeaders).filter(
              header => !headers[header] && !headers[header.toLowerCase()]
            ),
            details: headers
          };
        }
        
        function analyzeHttpProtocols() {
          const protocol = window.location.protocol;
          const isHttps = protocol === 'https:';
          const mixedContent = [];
          
          const resources = document.querySelectorAll('script[src], link[href], img[src], iframe[src]');
          resources.forEach(resource => {
            const src = resource.src || resource.href;
            if (src && src.startsWith('http:') && isHttps) {
              mixedContent.push({
                type: resource.tagName.toLowerCase(),
                url: src
              });
            }
          });
          
          return {
            protocol: protocol,
            isSecure: isHttps,
            mixedContent: mixedContent,
            tlsVersion: 'Unknown'
          };
        }
        
        function analyzeMalwarePhishing() {
          const malwarePatterns = ['eval(', 'document.write(', 'innerHTML =', 'outerHTML =', 'javascript:', 'vbscript:', 'data:text/html', 'base64,', 'fromCharCode', 'unescape(', 'decodeURIComponent('];
          const suspiciousScripts = ['crypto', 'mining', 'coinhive', 'jsecoin', 'authedmine', 'cnhv.co', 'coin-hive.com'];
          
          const suspiciousPatterns = [];
          const pageContent = document.documentElement.outerHTML.toLowerCase();
          const scripts = Array.from(document.scripts);
          
          malwarePatterns.forEach(pattern => {
            if (pageContent.includes(pattern.toLowerCase())) {
              suspiciousPatterns.push({ type: 'suspicious_code', pattern: pattern, severity: 'high' });
            }
          });
          
          suspiciousScripts.forEach(pattern => {
            if (pageContent.includes(pattern)) {
              suspiciousPatterns.push({ type: 'crypto_mining', pattern: pattern, severity: 'critical' });
            }
          });
          
          const externalScripts = scripts.filter(script => 
            script.src && !script.src.includes(window.location.hostname)
          ).map(script => script.src);
          
          return {
            suspiciousPatterns: suspiciousPatterns,
            externalScripts: externalScripts,
            riskLevel: suspiciousPatterns.length > 0 ? 'high' : 'low'
          };
        }
        
        function analyzeCookieStorageSecurity() {
          const cookies = document.cookie.split(';').map(cookie => {
            const [name, ...valueParts] = cookie.trim().split('=');
            return {
              name: name,
              value: valueParts.join('='),
              secure: cookie.includes('Secure'),
              httpOnly: cookie.includes('HttpOnly'),
              sameSite: cookie.includes('SameSite')
            };
          }).filter(cookie => cookie.name);
          
          const localStorage = {
            itemCount: window.localStorage ? window.localStorage.length : 0,
            items: []
          };
          
          const sessionStorage = {
            itemCount: window.sessionStorage ? window.sessionStorage.length : 0,
            items: []
          };
          
          if (window.localStorage) {
            for (let i = 0; i < Math.min(5, window.localStorage.length); i++) {
              const key = window.localStorage.key(i);
              localStorage.items.push({
                key: key,
                hasValue: window.localStorage.getItem(key) !== null
              });
            }
          }
          
          return {
            cookies: cookies,
            localStorage: localStorage,
            sessionStorage: sessionStorage,
            insecureCookies: cookies.filter(cookie => !cookie.secure && window.location.protocol === 'https:')
          };
        }
        
        function analyzeThirdPartyScripts() {
          const scripts = Array.from(document.scripts);
          const currentDomain = window.location.hostname;
          const thirdPartyScripts = [];
          const inlineScripts = [];
          
          scripts.forEach(script => {
            if (script.src) {
              try {
                const scriptUrl = new URL(script.src);
                if (scriptUrl.hostname !== currentDomain) {
                  thirdPartyScripts.push({
                    src: script.src,
                    domain: scriptUrl.hostname,
                    async: script.async,
                    defer: script.defer,
                    integrity: script.integrity || null
                  });
                }
              } catch (e) {
                // Invalid URL
              }
            } else if (script.innerHTML.trim()) {
              inlineScripts.push({
                length: script.innerHTML.length,
                hasEval: script.innerHTML.includes('eval('),
                hasDocumentWrite: script.innerHTML.includes('document.write')
              });
            }
          });
          
          return {
            thirdPartyScripts: thirdPartyScripts,
            inlineScripts: inlineScripts,
            totalThirdParty: thirdPartyScripts.length,
            scriptsWithoutIntegrity: thirdPartyScripts.filter(script => !script.integrity).length
          };
        }
        
        // Main analysis function
        return {
          url: window.location.href,
          timestamp: new Date().toISOString(),
          securityHeaders: analyzeSecurityHeaders(),
          httpProtocols: analyzeHttpProtocols(),
          malwarePhishing: analyzeMalwarePhishing(),
          cookieStorage: analyzeCookieStorageSecurity(),
          thirdPartyScripts: analyzeThirdPartyScripts()
        };
      }
    });
    
    // Display security analysis results
    displaySecurityResults(result.result);
    
  } catch (error) {
    if (results) {
      results.innerHTML = '<div class="security-error">ERROR: Failed to analyze security - ' + error.message + '</div>';
    }
  } finally {
    // Reset button state
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.textContent = 'ANALYZE SECURITY';
    }
    if (loading) loading.style.display = 'none';
  }
}

// 1. Security Headers Analysis
function analyzeSecurityHeaders() {
  const securityHeaders = {
    'Content-Security-Policy': {
      description: 'Prevents XSS and code injection attacks',
      severity: 'high',
      icon: '🛡️'
    },
    'X-Frame-Options': {
      description: 'Prevents clickjacking attacks',
      severity: 'medium',
      icon: '🖼️'
    },
    'X-Content-Type-Options': {
      description: 'Prevents MIME type sniffing',
      severity: 'medium',
      icon: '📄'
    },
    'Strict-Transport-Security': {
      description: 'Enforces HTTPS connections',
      severity: 'high',
      icon: '🔒'
    },
    'X-XSS-Protection': {
      description: 'Enables XSS filtering',
      severity: 'medium',
      icon: '⚡'
    },
    'Referrer-Policy': {
      description: 'Controls referrer information',
      severity: 'low',
      icon: '🔗'
    }
  };
  
  const headers = {};
  const metaTags = document.querySelectorAll('meta[http-equiv]');
  
  // Check meta tags for security headers
  metaTags.forEach(meta => {
    const httpEquiv = meta.getAttribute('http-equiv');
    const content = meta.getAttribute('content');
    if (httpEquiv && content) {
      headers[httpEquiv] = content;
    }
  });
  
  return {
    present: Object.keys(headers),
    missing: Object.keys(securityHeaders).filter(
      header => !headers[header] && !headers[header.toLowerCase()]
    ),
    details: headers
  };
}

// 2. HTTP Protocol Analysis
function analyzeHttpProtocols() {
  const protocol = window.location.protocol;
  const isHttps = protocol === 'https:';
  const mixedContent = [];
  
  // Check for mixed content
  const resources = document.querySelectorAll('script[src], link[href], img[src], iframe[src]');
  resources.forEach(resource => {
    const src = resource.src || resource.href;
    if (src && src.startsWith('http:') && isHttps) {
      mixedContent.push({
        type: resource.tagName.toLowerCase(),
        url: src
      });
    }
  });
  
  return {
    protocol: protocol,
    isSecure: isHttps,
    mixedContent: mixedContent,
    tlsVersion: 'Unknown' // Would need server-side detection
  };
}

// 3. Malware & Phishing Detection
function analyzeMalwarePhishing() {
  const malwarePatterns = [
    'eval(',
    'document.write(',
    'innerHTML =',
    'outerHTML =',
    'javascript:',
    'vbscript:',
    'data:text/html',
    'base64,',
    'fromCharCode',
    'unescape(',
    'decodeURIComponent('
  ];
  
  const suspiciousScripts = [
    'crypto',
    'mining',
    'coinhive',
    'jsecoin',
    'authedmine',
    'cnhv.co',
    'coin-hive.com'
  ];
  
  const suspiciousPatterns = [];
  const pageContent = document.documentElement.outerHTML.toLowerCase();
  const scripts = Array.from(document.scripts);
  
  // Check for suspicious patterns in content
  malwarePatterns.forEach(pattern => {
    if (pageContent.includes(pattern.toLowerCase())) {
      suspiciousPatterns.push({
        type: 'suspicious_code',
        pattern: pattern,
        severity: 'high'
      });
    }
  });
  
  // Check for crypto mining scripts
  suspiciousScripts.forEach(pattern => {
    if (pageContent.includes(pattern)) {
      suspiciousPatterns.push({
        type: 'crypto_mining',
        pattern: pattern,
        severity: 'critical'
      });
    }
  });
  
  // Check for suspicious external scripts
  const externalScripts = scripts.filter(script => 
    script.src && !script.src.includes(window.location.hostname)
  ).map(script => script.src);
  
  return {
    suspiciousPatterns: suspiciousPatterns,
    externalScripts: externalScripts,
    riskLevel: suspiciousPatterns.length > 0 ? 'high' : 'low'
  };
}

// 4. Cookie & Storage Security Analysis
function analyzeCookieStorageSecurity() {
  const cookies = document.cookie.split(';').map(cookie => {
    const [name, ...valueParts] = cookie.trim().split('=');
    return {
      name: name,
      value: valueParts.join('='),
      secure: cookie.includes('Secure'),
      httpOnly: cookie.includes('HttpOnly'),
      sameSite: cookie.includes('SameSite')
    };
  }).filter(cookie => cookie.name);
  
  const localStorage = {
    itemCount: window.localStorage ? window.localStorage.length : 0,
    items: []
  };
  
  const sessionStorage = {
    itemCount: window.sessionStorage ? window.sessionStorage.length : 0,
    items: []
  };
  
  // Get storage items (limited for privacy)
  if (window.localStorage) {
    for (let i = 0; i < Math.min(5, window.localStorage.length); i++) {
      const key = window.localStorage.key(i);
      localStorage.items.push({
        key: key,
        hasValue: window.localStorage.getItem(key) !== null
      });
    }
  }
  
  return {
    cookies: cookies,
    localStorage: localStorage,
    sessionStorage: sessionStorage,
    insecureCookies: cookies.filter(cookie => !cookie.secure && window.location.protocol === 'https:')
  };
}

// 5. Third Party Script Analysis
function analyzeThirdPartyScripts() {
  const scripts = Array.from(document.scripts);
  const currentDomain = window.location.hostname;
  const thirdPartyScripts = [];
  const inlineScripts = [];
  
  scripts.forEach(script => {
    if (script.src) {
      try {
        const scriptUrl = new URL(script.src);
        if (scriptUrl.hostname !== currentDomain) {
          thirdPartyScripts.push({
            src: script.src,
            domain: scriptUrl.hostname,
            async: script.async,
            defer: script.defer,
            integrity: script.integrity || null
          });
        }
      } catch (e) {
        // Invalid URL
      }
    } else if (script.innerHTML.trim()) {
      inlineScripts.push({
        length: script.innerHTML.length,
        hasEval: script.innerHTML.includes('eval('),
        hasDocumentWrite: script.innerHTML.includes('document.write')
      });
    }
  });
  
  return {
    thirdPartyScripts: thirdPartyScripts,
    inlineScripts: inlineScripts,
    totalThirdParty: thirdPartyScripts.length,
    scriptsWithoutIntegrity: thirdPartyScripts.filter(script => !script.integrity).length
  };
}

// Main security analysis function (runs in page context)
function analyzePageSecurity() {
  try {
    return {
      url: window.location.href,
      timestamp: new Date().toISOString(),
      securityHeaders: analyzeSecurityHeaders(),
      httpProtocols: analyzeHttpProtocols(),
      malwarePhishing: analyzeMalwarePhishing(),
      cookieStorage: analyzeCookieStorageSecurity(),
      thirdPartyScripts: analyzeThirdPartyScripts()
    };
  } catch (error) {
    return {
      error: error.message,
      url: window.location.href,
      timestamp: new Date().toISOString(),
      securityHeaders: { present: [], missing: [], details: {} },
      httpProtocols: { protocol: 'unknown', isSecure: false, mixedContent: [], tlsVersion: 'Unknown' },
      malwarePhishing: { suspiciousPatterns: [], externalScripts: [], riskLevel: 'unknown' },
      cookieStorage: { cookies: [], localStorage: { itemCount: 0, items: [] }, sessionStorage: { itemCount: 0, items: [] }, insecureCookies: [] },
      thirdPartyScripts: { thirdPartyScripts: [], inlineScripts: [], totalThirdParty: 0, scriptsWithoutIntegrity: 0 }
    };
  }
}

// Display security analysis results
function displaySecurityResults(data) {
  const results = document.getElementById('results');
  if (!results) return;
  
  let html = '<div class="security-analysis">';
  
  // Security Headers Section
  html += '<div class="security-section">';
  html += '<h3 class="section-title">Security Headers</h3>';
  html += `<div class="header-status">Present: ${data.securityHeaders.present.length} | Missing: ${data.securityHeaders.missing.length}</div>`;
  
  if (data.securityHeaders.missing.length > 0) {
    html += '<div class="missing-headers">';
    data.securityHeaders.missing.forEach(header => {
      // Define security header info inline since securityPatterns is not available here
      const headerInfo = {
        'Content-Security-Policy': { icon: 'CSP' },
        'X-Frame-Options': { icon: 'FRAME' },
        'X-Content-Type-Options': { icon: 'MIME' },
        'Strict-Transport-Security': { icon: 'HSTS' },
        'X-XSS-Protection': { icon: 'XSS' },
        'Referrer-Policy': { icon: 'REF' }
      };
      const info = headerInfo[header] || { icon: 'WARN' };
      html += `<div class="security-item warning">`;
      html += `<span class="item-icon">${info.icon}</span>`;
      html += `<span class="item-name">${header}</span>`;
      html += `<span class="item-status missing">Missing</span>`;
      html += `</div>`;
    });
    html += '</div>';
  }
  html += '</div>';
  
  // HTTP Protocols Section
  html += '<div class="security-section">';
  html += '<h3 class="section-title">HTTP Protocols</h3>';
  html += `<div class="protocol-info">`;
  html += `<div class="security-item ${data.httpProtocols.isSecure ? 'secure' : 'warning'}">`;
  html += `<span class="item-icon">${data.httpProtocols.isSecure ? 'SECURE' : 'WARN'}</span>`;
  html += `<span class="item-name">Protocol: ${data.httpProtocols.protocol.toUpperCase()}</span>`;
  html += `</div>`;
  if (data.httpProtocols.mixedContent.length > 0) {
    html += `<div class="mixed-content-warning">WARNING: ${data.httpProtocols.mixedContent.length} mixed content resources detected</div>`;
  }
  html += `</div>`;
  html += '</div>';
  
  // Malware & Phishing Section
  html += '<div class="security-section">';
  html += '<h3 class="section-title">Malware & Phishing</h3>';
  html += `<div class="risk-level ${data.malwarePhishing.riskLevel}">`;
  html += `Risk Level: ${data.malwarePhishing.riskLevel.toUpperCase()}`;
  html += `</div>`;
  if (data.malwarePhishing.suspiciousPatterns.length > 0) {
    html += '<div class="suspicious-patterns">';
    data.malwarePhishing.suspiciousPatterns.forEach(pattern => {
      html += `<div class="security-item danger">`;
      html += `<span class="item-icon">THREAT</span>`;
      html += `<span class="item-name">${pattern.type}: ${pattern.pattern}</span>`;
      html += `</div>`;
    });
    html += '</div>';
  }
  html += '</div>';
  
  // Cookie & Storage Security Section
  html += '<div class="security-section">';
  html += '<h3 class="section-title">Cookie & Storage Security</h3>';
  html += `<div class="storage-info">`;
  html += `<div class="security-item"><span class="item-icon">COOKIE</span><span class="item-name">Cookies: ${data.cookieStorage.cookies.length}</span></div>`;
  html += `<div class="security-item"><span class="item-icon">LOCAL</span><span class="item-name">LocalStorage Items: ${data.cookieStorage.localStorage.itemCount}</span></div>`;
  html += `<div class="security-item"><span class="item-icon">SESSION</span><span class="item-name">SessionStorage Items: ${data.cookieStorage.sessionStorage.itemCount}</span></div>`;
  if (data.cookieStorage.insecureCookies.length > 0) {
    html += `<div class="security-item warning"><span class="item-icon">WARN</span><span class="item-name">${data.cookieStorage.insecureCookies.length} insecure cookies</span></div>`;
  }
  html += `</div>`;
  html += '</div>';
  
  // Third Party Scripts Section
  html += '<div class="security-section">';
  html += '<h3 class="section-title">Third Party Scripts</h3>';
  html += `<div class="script-info">`;
  html += `<div class="security-item"><span class="item-icon">EXTERN</span><span class="item-name">Third-party scripts: ${data.thirdPartyScripts.totalThirdParty}</span></div>`;
  html += `<div class="security-item"><span class="item-icon">INLINE</span><span class="item-name">Inline scripts: ${data.thirdPartyScripts.inlineScripts.length}</span></div>`;
  if (data.thirdPartyScripts.scriptsWithoutIntegrity > 0) {
    html += `<div class="security-item warning"><span class="item-icon">WARN</span><span class="item-name">${data.thirdPartyScripts.scriptsWithoutIntegrity} scripts without integrity checks</span></div>`;
  }
  html += `</div>`;
  html += '</div>';
  
  html += '</div>';
  results.innerHTML = html;
}