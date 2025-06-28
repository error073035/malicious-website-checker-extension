const GS_API_KEY = "[your_api_key]";
const VT_API_KEY = "[your_api_key]";
const GS_API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GS_API_KEY}`;
const VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls";
const VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files";
const VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files";
let lastChecked = {};
const CACHE_TTL = 5 * 60 * 1000;
let debounceTimeout = null;
const MAX_URLS_PER_PAGE = 5;
const VT_REQUEST_INTERVAL = 15000;
const VT_ANALYSIS_WAIT = 10000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "scanContent" && sender.tab?.id) {
    const tabId = sender.tab.id;
    const embeddedUrls = message.urls.slice(0, MAX_URLS_PER_PAGE);
    const contentHash = message.contentHash;
    const contentIssues = message.contentIssues || [];

    checkEmbeddedContent(tabId, embeddedUrls, contentHash, contentIssues, sendResponse);
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url.startsWith("http")) return;

  clearTimeout(debounceTimeout);
  debounceTimeout = setTimeout(() => {
    const now = Date.now();
    if (lastChecked[tab.url] && now - lastChecked[tab.url].timestamp < CACHE_TTL) {
      chrome.storage.local.set({ [`status_${tabId}`]: lastChecked[tab.url].status });
      updateBlockRules(tab.url, lastChecked[tab.url].status.status);
      return;
    }

    checkMainUrl(tabId, tab.url);
  }, 500);
});

async function checkMainUrl(tabId, url) {
  const now = Date.now();
  const requestBody = {
    client: {
      clientId: "malicious-url-checker",
      clientVersion: "1.0.3"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const res = await fetch(GS_API_URL, {
      method: "POST",
      body: JSON.stringify(requestBody)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    const data = await res.json();
    const isUnsafe = data && data.matches && data.matches.length > 0;
    const status = {
      status: isUnsafe ? "unsafe" : "safe",
      url,
      timestamp: now,
      embeddedIssues: [],
      contentIssues: [],
      vtIssues: []
    };
    lastChecked[url] = { status };
    chrome.storage.local.set({ [`status_${tabId}`]: status });
    updateBlockRules(url, status.status);

    if (isUnsafe) {
      chrome.notifications.create({
        type: "basic",
        title: "Unsafe Website Detected (Google Safe Browsing)",
        message: `The website ${url} is unsafe and has been blocked.`,
        priority: 2
      });
    }
  } catch (err) {
    console.error("Google Safe Browsing API error for main URL:", err);
    const errorStatus = {
      status: "error",
      url,
      error: err.message,
      timestamp: now,
      embeddedIssues: [],
      contentIssues: [],
      vtIssues: []
    };
    lastChecked[url] = { status: errorStatus };
    chrome.storage.local.set({ [`status_${tabId}`]: errorStatus });

    chrome.notifications.create({
      type: "basic",
      title: "Error Checking Website",
      message: `Failed to check ${url}: ${err.message}`,
      priority: 1
    });
  }
}

async function checkEmbeddedContent(tabId, urls, contentHash, contentIssues, sendResponse) {
  const now = Date.now();
  let vtIssues = [];

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    if (lastChecked[url] && now - lastChecked[url].timestamp < CACHE_TTL) {
      if (lastChecked[url].status.vtIssues?.length > 0) {
        vtIssues = vtIssues.concat(lastChecked[url].status.vtIssues);
      }
      continue;
    }

    try {
      const urlId = btoa(url).replace(/=/g, "");
      const res = await fetch(`${VT_URL_SCAN_URL}/${urlId}`, {
        method: "GET",
        headers: { "x-apikey": VT_API_KEY }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      const positives = data.data.attributes.last_analysis_stats.malicious || 0;
      if (positives > 0) {
        vtIssues.push(`URL ${url} flagged by ${positives} engines`);
      }
      lastChecked[url] = { status: { vtIssues: positives > 0 ? [`URL ${url} flagged by ${positives} engines`] : [] }, timestamp: now };

      if (i < urls.length - 1) await new Promise(resolve => setTimeout(resolve, VT_REQUEST_INTERVAL));
    } catch (err) {
      console.error(`VirusTotal API error for URL ${url}:`, err);
      vtIssues.push(`Error checking URL ${url}: ${err.message}`);
    }
  }

  if (contentHash) {
    try {
      const res = await fetch(`${VT_FILE_REPORT_URL}/${contentHash}`, {
        method: "GET",
        headers: { "x-apikey": VT_API_KEY }
      });
      if (res.status === 404) {
        // Submit content hash for scanning
        const scanRes = await fetch(VT_FILE_SCAN_URL, {
          method: "POST",
          headers: {
            "x-apikey": VT_API_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url: contentHash })
        });
        if (!scanRes.ok) throw new Error(`HTTP ${scanRes.status}: ${scanRes.statusText}`);
        const scanData = await scanRes.json();
        const analysisId = scanData.data.id;

        // Wait for analysis to complete
        await new Promise(resolve => setTimeout(resolve, VT_ANALYSIS_WAIT));

        // Check analysis results
        const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          method: "GET",
          headers: { "x-apikey": VT_API_KEY }
        });
        if (!analysisRes.ok) throw new Error(`HTTP ${analysisRes.status}: ${analysisRes.statusText}`);
        const analysisData = await analysisRes.json();
        const positives = analysisData.data.attributes.stats.malicious || 0;
        if (positives > 0) {
          vtIssues.push(`Page content flagged by ${positives} engines`);
        } else {
          vtIssues.push("Content scanned by VirusTotal: No threats detected");
        }
      } else if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      } else {
        const data = await res.json();
        const positives = data.data.attributes.last_analysis_stats.malicious || 0;
        if (positives > 0) {
          vtIssues.push(`Page content flagged by ${positives} engines`);
        } else {
          vtIssues.push("Content scanned by VirusTotal: No threats detected");
        }
      }
    } catch (err) {
      console.error("VirusTotal API error for content hash:", err);
      vtIssues.push(`Error checking content: ${err.message}`);
    }
  }

  chrome.storage.local.get(`status_${tabId}`, (data) => {
    const status = data[`status_${tabId}`] || { status: "unknown", url: "", embeddedIssues: [], contentIssues: [], vtIssues: [] };
    status.vtIssues = vtIssues;
    status.contentIssues = contentIssues;
    status.status = vtIssues.length > 0 || contentIssues.length > 0 || status.embeddedIssues.length > 0 || status.status === "unsafe" ? "unsafe" : status.status;
    status.timestamp = now;

    lastChecked[status.url] = { status };
    chrome.storage.local.set({ [`status_${tabId}`]: status });

    if (vtIssues.length > 0 && !vtIssues.every(issue => issue.includes("No threats detected"))) {
      chrome.notifications.create({
        type: "basic",
        title: "Unsafe Content Detected (VirusTotal)",
        message: `The website contains unsafe elements: ${vtIssues.join(", ")}`,
        priority: 2
      });
    }
    if (contentIssues.length > 0) {
      chrome.notifications.create({
        type: "basic",
        title: "Suspicious Content Detected",
        message: `The website contains suspicious elements: ${contentIssues.join(", ")}`,
        priority: 2
      });
    }
    sendResponse({ status: "completed" });
  });
}

function updateBlockRules(url, status) {
  const ruleId = Math.abs(url.hashCode());
  const rules = [];

  if (status === "unsafe") {
    rules.push({
      id: ruleId,
      priority: 1,
      action: { type: "block" },
      condition: { urlFilter: url, resourceTypes: ["main_frame"] }
    });
  }

  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ruleId],
    addRules: rules
  });
}

String.prototype.hashCode = function () {
  let hash =0;
  for (let i = 0; i < this.length; i++) {
    hash = ((hash << 5) - hash + this.charCodeAt(i)) | 0;
  }
  return hash;
};