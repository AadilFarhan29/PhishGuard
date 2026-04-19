const API_BASE_URL = "https://phishguard-7q7y.onrender.com";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scanWithPhishGuard",
    title: "Scan with PhishGuard",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "scanWithPhishGuard" || !info.linkUrl) {
    return;
  }

  const targetUrl = info.linkUrl;

  const pendingResult = {
    status: "loading",
    scannedUrl: targetUrl,
    message: "Scanning link..."
  };

  await chrome.storage.local.set({ phishguardLastScan: pendingResult });

  try {
    const response = await fetch(`${API_BASE_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: targetUrl })
    });

    const data = await response.json();

    const finalPayload = {
      status: response.ok && data.success ? "done" : "error",
      scannedUrl: targetUrl,
      response: data
    };

    await chrome.storage.local.set({ phishguardLastScan: finalPayload });

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon48.png",
      title: "PhishGuard Scan Complete",
      message: response.ok && data.success
        ? `Verdict: ${data.result.result || "Unknown"}`
        : "Scan failed."
    });
  } catch (error) {
    await chrome.storage.local.set({
      phishguardLastScan: {
        status: "error",
        scannedUrl: targetUrl,
        message: error.message
      }
    });

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon48.png",
      title: "PhishGuard Error",
      message: error.message || "Unknown error"
    });
  }
});