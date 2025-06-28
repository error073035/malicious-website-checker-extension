chrome.runtime.sendMessage({
  type: "scanContent",
  urls: getEmbeddedUrls(),
  contentHash: getContentHash(),
  contentIssues: detectContentIssues()
});

function getEmbeddedUrls() {
  const urls = new Set();
  document.querySelectorAll("a[href]").forEach(a => {
    try {
      const url = new URL(a.href, window.location.href).href;
      if (url.startsWith("http")) urls.add(url);
    } catch (e) {}
  });
  document.querySelectorAll("script[src]").forEach(script => {
    try {
      const url = new URL(script.src, window.location.href).href;
      if (url.startsWith("http")) urls.add(url);
    } catch (e) {}
  });
  document.querySelectorAll("iframe[src]").forEach(iframe => {
    try {
      const url = new URL(iframe.src, window.location.href).href;
      if (url.startsWith("http")) urls.add(url);
    } catch (e) {}
  });
  return Array.from(urls);
}

function getContentHash() {
  const content = document.documentElement.outerHTML;
  return sha256(content);
}

function detectContentIssues() {
  const issues = [];
  document.querySelectorAll("script").forEach(script => {
    const content = script.textContent;
    if (content && (content.includes("eval(") || content.includes("unescape(") || content.includes("String.fromCharCode"))) {
      issues.push("Potential obfuscated JavaScript");
    }
  });
  document.querySelectorAll("form").forEach(form => {
    if (form.querySelector("input[type='password']") && !form.action.startsWith(window.location.origin)) {
      issues.push("Suspicious form with external action");
    }
  });
  document.querySelectorAll("[style*='display: none'], [style*='visibility: hidden']").forEach(elem => {
    if (elem.tagName === "IFRAME" || elem.tagName === "SCRIPT") {
      issues.push("Hidden iframe or script");
    }
  });
  return issues;
}

function sha256(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash.toString(16).padStart(64, "0");
}