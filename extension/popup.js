document.addEventListener("DOMContentLoaded", () => {
  const cybersecurityTips = [
    "Avoid clicking links in unsolicited emails; they may lead to phishing sites.",
    "Use strong, unique passwords for each account to prevent credential theft.",
    "Enable two-factor authentication (2FA) for extra account security.",
    "Be cautious of pop-ups asking for personal information; they could be scams.",
    "Regularly update your software to protect against malware vulnerabilities.",
    "Verify website URLs before entering sensitive data to avoid phishing attacks.",
    "Use a reputable antivirus program to detect and remove malicious software.",
    "Avoid downloading files from untrusted sources; they may contain malware.",
    "Check for 'https://' and a padlock icon before entering login credentials.",
    "Beware of social engineering; never share sensitive info over unverified calls."
  ];

  function getRandomTip() {
    return cybersecurityTips[Math.floor(Math.random() * cybersecurityTips.length)];
  }

  function updateUI(status) {
    const statusText = document.getElementById("status");
    const statusIcon = document.getElementById("status-icon");
    const tipText = document.getElementById("cyber-tip");

    if (status.status === "safe") {
      statusText.textContent = "This site is SAFE";
      statusIcon.style.backgroundColor = "green";
    } else if (status.status === "unsafe") {
      let message = "This site is UNSAFE";
      if (status.embeddedIssues?.length > 0) {
        message += `. Unsafe URLs (Google Safe Browsing): ${status.embeddedIssues.join(", ")}`;
      }
      if (status.vtIssues?.length > 0) {
        message += `. Unsafe elements (VirusTotal): ${status.vtIssues.join(", ")}`;
      }
      if (status.contentIssues?.length > 0) {
        message += `. Suspicious elements: ${status.contentIssues.join(", ")}`;
      }
      statusText.textContent = message;
      statusIcon.style.backgroundColor = "red";
    } else if (status.status === "error") {
      statusText.textContent = `Error: ${status.error || "Unknown error"}`;
      statusIcon.style.backgroundColor = "gray";
    } else {
      statusText.textContent = "Checking status...";
      statusIcon.style.backgroundColor = "yellow";
    }

    tipText.textContent = `Tip: ${getRandomTip()}`;
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    if (!tabId) {
      updateUI({ status: "error", error: "No active tab" });
      return;
    }

    chrome.storage.local.get(`status_${tabId}`, (data) => {
      const status = data[`status_${tabId}`] || { status: "unknown", url: "", embeddedIssues: [], contentIssues: [], vtIssues: [] };
      updateUI(status);
    });
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (changes[`status_${tabId}`]) {
        updateUI(changes[`status_${tabId}`].newValue);
      }
    });
  });
});