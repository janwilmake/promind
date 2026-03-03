// Track active tab and timing
let activeTabId = null;
let startTime = null;
let currentUrl = null;
let currentTitle = null;

// Interval for periodic session saves (to survive service worker suspension)
let saveInterval = null;
const SAVE_INTERVAL_MS = 10000; // Save every 10 seconds

// Save current tracking session to storage
async function saveTrackingSession() {
  if (activeTabId && startTime && currentUrl) {
    await chrome.storage.local.set({
      trackingSession: {
        tabId: activeTabId,
        url: currentUrl,
        title: currentTitle,
        startTime: startTime,
        lastSavedAt: Date.now()
      }
    });
  }
}

// Clear saved tracking session
async function clearTrackingSession() {
  await chrome.storage.local.remove(["trackingSession"]);
}

// Restore tracking session after service worker wake-up
async function restoreTrackingSession() {
  const result = await chrome.storage.local.get(["trackingSession"]);
  const session = result.trackingSession;

  if (session) {
    // Check if the tab still exists and is active
    try {
      const tab = await chrome.tabs.get(session.tabId);
      const [activeTab] = await chrome.tabs.query({
        active: true,
        currentWindow: true
      });

      // If the saved tab is still the active tab with same URL, restore the session
      if (activeTab && activeTab.id === session.tabId) {
        const currentTabUrl = normalizeUrl(activeTab.url);
        if (currentTabUrl === session.url) {
          activeTabId = session.tabId;
          currentUrl = session.url;
          currentTitle = session.title || null;
          startTime = session.startTime;
          console.log(
            `Restored tracking session: ${currentUrl}, elapsed: ${Math.floor((Date.now() - startTime) / 1000)}s`
          );
          startPeriodicSave();
          return true;
        }
      }
    } catch {
      // Tab doesn't exist anymore
    }

    // Session is stale - send accumulated time and clear
    const elapsedMs = session.lastSavedAt - session.startTime;
    const elapsedSeconds = Math.floor(elapsedMs / 1000);
    if (elapsedSeconds >= MIN_DURATION_SECONDS) {
      console.log(
        `Sending orphaned session: ${session.url}, ${elapsedSeconds}s`
      );
      await sendTrackingData(
        session.url,
        elapsedSeconds,
        session.title || "",
        ""
      );
    }
    await clearTrackingSession();
  }
  return false;
}

// Start periodic saving and keepalive alarm
function startPeriodicSave() {
  if (saveInterval) return;
  saveInterval = setInterval(saveTrackingSession, SAVE_INTERVAL_MS);
  // Use chrome.alarms to keep service worker alive
  chrome.alarms.create("keepalive", { periodInMinutes: 0.5 }); // Every 30 seconds
}

// Stop periodic saving and clear alarm
function stopPeriodicSave() {
  if (saveInterval) {
    clearInterval(saveInterval);
    saveInterval = null;
  }
  chrome.alarms.clear("keepalive");
}

// Handle alarm - used to keep service worker alive and save session
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "keepalive") {
    await saveTrackingSession();
    // Also try to restore if we lost state
    if (!activeTabId && !startTime) {
      await restoreTrackingSession();
    }
  }
});

// X Auth Configuration
// IMPORTANT: Update this URL after deploying your Cloudflare Worker
const X_AUTH_WORKER_URL = "https://history.wilmake.com";
const CALLBACK_PATH = "/extension-callback";

// Track login tab to close it after auth
let loginTabId = null;

// Initialize when extension loads
chrome.runtime.onInstalled.addListener(() => {
  console.log("Website Time Tracker installed");
  initializeTracking();
});

// Start tracking when browser starts
chrome.runtime.onStartup.addListener(() => {
  initializeTracking();
});

async function initializeTracking() {
  try {
    // First, try to restore any saved session from before service worker suspension
    const restored = await restoreTrackingSession();
    if (restored) {
      return; // Session restored, no need to start fresh
    }

    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });
    if (tab) {
      startTracking(tab.id, tab.url, tab.title);
    }
  } catch (error) {
    console.error("Error initializing tracking:", error);
  }
}

// Track when user switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  await stopTracking();

  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    startTracking(tab.id, tab.url, tab.title);
  } catch (error) {
    console.error("Error on tab activation:", error);
  }
});

// Track when tab URL changes (navigation within same tab)
// Also handles X OAuth callback interception
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  // Check for X OAuth callback
  if (
    changeInfo.url &&
    changeInfo.url.includes(X_AUTH_WORKER_URL + CALLBACK_PATH)
  ) {
    const url = new URL(changeInfo.url);
    const jwt = url.searchParams.get("jwt");
    const error = url.searchParams.get("error");

    if (jwt) {
      await saveXAuthData({
        jwt: jwt,
        refresh_token: url.searchParams.get("refresh_token"),
        user: url.searchParams.get("user")
      });
      // Close the tab after showing success
      setTimeout(() => {
        chrome.tabs.remove(tabId).catch(() => {});
      }, 1500);
    } else if (error) {
      console.error(
        "X Login error:",
        error,
        url.searchParams.get("error_description")
      );
      setTimeout(() => {
        chrome.tabs.remove(tabId).catch(() => {});
      }, 3000);
    }
    loginTabId = null;
    return;
  }

  // Normal tracking logic
  if (changeInfo.url && tabId === activeTabId) {
    await stopTracking();
    const tab = await chrome.tabs.get(tabId);
    startTracking(tabId, changeInfo.url, tab?.title);
  }
});

// Track when window focus changes
chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    // Browser lost focus
    await stopTracking();
  } else {
    // Browser gained focus or switched to different Chrome window
    await stopTracking();
    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        windowId: windowId
      });
      if (tab) {
        startTracking(tab.id, tab.url, tab.title);
      }
    } catch (error) {
      console.error("Error on window focus change:", error);
    }
  }
});

// Track when tab is closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  if (tabId === activeTabId) {
    await stopTracking();
  }
});

// Minimum duration in seconds to count a visit
const MIN_DURATION_SECONDS = 5;

function isInternalHost(hostname) {
  // localhost
  if (hostname === "localhost") return true;
  // IPv6 localhost
  if (hostname === "[::1]") return true;
  // 127.x.x.x
  if (hostname.startsWith("127.")) return true;
  // 10.x.x.x
  if (hostname.startsWith("10.")) return true;
  // 192.168.x.x
  if (hostname.startsWith("192.168.")) return true;
  // 172.16.x.x - 172.31.x.x
  if (hostname.startsWith("172.")) {
    const secondOctet = parseInt(hostname.split(".")[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  return false;
}

async function getPageMetaDescription(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const meta = document.querySelector('meta[name="description"]');
        return meta ? meta.getAttribute("content") : "";
      }
    });
    return results?.[0]?.result || "";
  } catch {
    return "";
  }
}

function startTracking(tabId, url, title) {
  if (
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://")
  ) {
    return; // Don't track browser internal pages
  }

  // Check for localhost and internal network IPs
  try {
    const urlObj = new URL(url);
    if (isInternalHost(urlObj.hostname)) {
      return; // Don't track internal/local addresses
    }
  } catch {
    // Invalid URL, skip tracking
    return;
  }

  activeTabId = tabId;
  currentUrl = normalizeUrl(url);
  currentTitle = title || null;
  startTime = Date.now();

  // Save session to storage to survive service worker suspension
  saveTrackingSession();
  startPeriodicSave();

  console.log(`Started tracking: ${currentUrl}`);
}

async function stopTracking() {
  stopPeriodicSave();

  if (!activeTabId || !startTime || !currentUrl) {
    await clearTrackingSession();
    return;
  }

  const duration = Date.now() - startTime;
  const durationSeconds = Math.floor(duration / 1000);

  if (durationSeconds >= MIN_DURATION_SECONDS) {
    // Get latest title and meta description before sending
    let title = currentTitle || "";
    let description = "";
    try {
      const tab = await chrome.tabs.get(activeTabId);
      if (tab.title) title = tab.title;
      description = await getPageMetaDescription(activeTabId);
    } catch {}

    await sendTrackingData(currentUrl, durationSeconds, title, description);
    console.log(
      `Stopped tracking: ${currentUrl}, Duration: ${durationSeconds}s`
    );
  } else if (durationSeconds > 0) {
    console.log(
      `Skipped tracking (too short): ${currentUrl}, Duration: ${durationSeconds}s`
    );
  }

  activeTabId = null;
  startTime = null;
  currentUrl = null;
  currentTitle = null;
  await clearTrackingSession();
}

function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);
    // Return full URL without fragment (hash), keep path and query params
    return urlObj.origin + urlObj.pathname + urlObj.search;
  } catch {
    return url;
  }
}

// ===== X Authentication Functions =====

async function startXLogin() {
  const callbackUrl = `${X_AUTH_WORKER_URL}/callback`;
  const loginUrl = `${X_AUTH_WORKER_URL}/login?redirect_uri=${encodeURIComponent(callbackUrl)}`;
  const tab = await chrome.tabs.create({ url: loginUrl });
  loginTabId = tab.id;
  return { success: true, message: "Login started" };
}

async function getXAuthStatus() {
  const result = await chrome.storage.local.get(["xAuth"]);
  if (result.xAuth && result.xAuth.jwt) {
    return {
      isLoggedIn: true,
      user: result.xAuth.user || null
    };
  }
  return { isLoggedIn: false };
}

async function saveXAuthData(data) {
  const authData = {
    jwt: data.jwt,
    refresh_token: data.refresh_token,
    user: data.user ? JSON.parse(data.user) : null
  };
  await chrome.storage.local.set({ xAuth: authData });
  console.log("X Auth saved:", authData.user?.username);
  return authData;
}

async function logoutX() {
  await chrome.storage.local.remove(["xAuth"]);
  return { success: true };
}

async function refreshXToken() {
  const result = await chrome.storage.local.get(["xAuth"]);
  if (!result.xAuth?.refresh_token) {
    return { error: "No refresh token available" };
  }
  try {
    const response = await fetch(`${X_AUTH_WORKER_URL}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: result.xAuth.refresh_token })
    });
    if (!response.ok) {
      const error = await response.json();
      return { error: error.error || "Refresh failed" };
    }
    const tokenData = await response.json();
    const authData = await saveXAuthData({
      jwt: tokenData.jwt,
      refresh_token: tokenData.refresh_token || result.xAuth.refresh_token,
      user: JSON.stringify(tokenData.user)
    });
    return { success: true, auth: authData };
  } catch (error) {
    return { error: error.message };
  }
}

// ===== Server-Side Tracking Functions =====

async function sendTrackingData(domain, durationSeconds, title, description) {
  try {
    const result = await chrome.storage.local.get(["xAuth"]);
    if (!result.xAuth?.jwt) {
      console.log("Not logged in, skipping tracking");
      return;
    }

    const response = await fetch(`${X_AUTH_WORKER_URL}/api/track`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${result.xAuth.jwt}`
      },
      body: JSON.stringify({
        domain: domain,
        duration: durationSeconds,
        title: title || "",
        description: description || ""
      })
    });

    if (response.ok) {
      console.log(
        `Sent tracking data to worker: ${domain}, ${durationSeconds}s`
      );
    } else {
      const error = await response.json();
      console.error("Failed to send tracking data:", error);

      // If unauthorized, try to refresh token
      if (response.status === 401) {
        const refreshResult = await refreshXToken();
        if (refreshResult.success) {
          // Retry sending tracking data
          await sendTrackingData(domain, durationSeconds, title, description);
        }
      }
    }
  } catch (error) {
    console.error("Error sending tracking data:", error);
  }
}

function getStatsUrl() {
  return new Promise(async (resolve) => {
    const result = await chrome.storage.local.get(["xAuth"]);
    if (result.xAuth?.jwt) {
      resolve(
        `${X_AUTH_WORKER_URL}/stats?token=${encodeURIComponent(result.xAuth.jwt)}`
      );
    } else {
      resolve(null);
    }
  });
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.action === "xLogin") {
    startXLogin().then(sendResponse);
    return true;
  } else if (request.action === "xLogout") {
    logoutX().then(sendResponse);
    return true;
  } else if (request.action === "getXAuthStatus") {
    getXAuthStatus().then(sendResponse);
    return true;
  } else if (request.action === "refreshXToken") {
    refreshXToken().then(sendResponse);
    return true;
  } else if (request.action === "getStatsUrl") {
    getStatsUrl().then(sendResponse);
    return true;
  }
});
