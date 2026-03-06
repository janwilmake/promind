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
    try {
      const tab = await chrome.tabs.get(session.tabId);
      const [activeTab] = await chrome.tabs.query({
        active: true,
        currentWindow: true
      });

      if (activeTab && activeTab.id === session.tabId) {
        const currentTabUrl = normalizeUrl(activeTab.url);
        if (currentTabUrl === session.url) {
          activeTabId = session.tabId;
          currentUrl = session.url;
          currentTitle = session.title || null;
          startTime = session.startTime;
          startPeriodicSave();
          return true;
        }
      }
    } catch {
      // Tab doesn't exist anymore
    }

    const elapsedMs = session.lastSavedAt - session.startTime;
    const elapsedSeconds = Math.floor(elapsedMs / 1000);
    if (elapsedSeconds >= MIN_DURATION_SECONDS) {
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

function startPeriodicSave() {
  if (saveInterval) return;
  saveInterval = setInterval(saveTrackingSession, SAVE_INTERVAL_MS);
  chrome.alarms.create("keepalive", { periodInMinutes: 0.5 });
}

function stopPeriodicSave() {
  if (saveInterval) {
    clearInterval(saveInterval);
    saveInterval = null;
  }
  chrome.alarms.clear("keepalive");
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "keepalive") {
    await saveTrackingSession();
    if (!activeTabId && !startTime) {
      await restoreTrackingSession();
    }
  }
});

// ===== Configuration =====
// IMPORTANT: Points to the unified Pro Mind backend
const WORKER_URL = "https://getpromind.com";
const CALLBACK_PATH = "/extension-callback";

let loginTabId = null;

chrome.runtime.onInstalled.addListener(() => {
  initializeTracking();
});

chrome.runtime.onStartup.addListener(() => {
  initializeTracking();
});

async function initializeTracking() {
  try {
    const restored = await restoreTrackingSession();
    if (restored) return;

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

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  await stopTracking();
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    startTracking(tab.id, tab.url, tab.title);
  } catch (error) {
    console.error("Error on tab activation:", error);
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  // Check for OAuth callback
  if (changeInfo.url && changeInfo.url.includes(WORKER_URL + CALLBACK_PATH)) {
    const url = new URL(changeInfo.url);
    const jwt = url.searchParams.get("jwt");
    const error = url.searchParams.get("error");

    if (jwt) {
      await saveAuthData({
        jwt: jwt,
        refresh_token: url.searchParams.get("refresh_token"),
        user: url.searchParams.get("user")
      });
      setTimeout(() => {
        chrome.tabs.remove(tabId).catch(() => {});
      }, 1500);
    } else if (error) {
      console.error("Login error:", error);
      setTimeout(() => {
        chrome.tabs.remove(tabId).catch(() => {});
      }, 3000);
    }
    loginTabId = null;
    return;
  }

  if (changeInfo.url && tabId === activeTabId) {
    await stopTracking();
    const tab = await chrome.tabs.get(tabId);
    startTracking(tabId, changeInfo.url, tab?.title);
  }

  // Update title when the page finishes loading (title is now accurate)
  if (changeInfo.title && tabId === activeTabId) {
    currentTitle = changeInfo.title;
    saveTrackingSession();
  }
});

chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    await stopTracking();
  } else {
    await stopTracking();
    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        windowId: windowId
      });
      if (tab) startTracking(tab.id, tab.url, tab.title);
    } catch (error) {
      console.error("Error on window focus change:", error);
    }
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  if (tabId === activeTabId) await stopTracking();
});

const MIN_DURATION_SECONDS = 5;

function isInternalHost(hostname) {
  if (hostname === "localhost") return true;
  if (hostname === "[::1]") return true;
  if (hostname.startsWith("127.")) return true;
  if (hostname.startsWith("10.")) return true;
  if (hostname.startsWith("192.168.")) return true;
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
  )
    return;
  try {
    const urlObj = new URL(url);
    if (isInternalHost(urlObj.hostname)) return;
  } catch {
    return;
  }

  activeTabId = tabId;
  currentUrl = normalizeUrl(url);
  currentTitle = title || null;
  startTime = Date.now();
  saveTrackingSession();
  startPeriodicSave();
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
    let title = currentTitle || "";
    let description = "";
    try {
      const tab = await chrome.tabs.get(activeTabId);
      if (tab.title) title = tab.title;
      description = await getPageMetaDescription(activeTabId);
    } catch {}

    await sendTrackingData(currentUrl, durationSeconds, title, description);
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
    return urlObj.origin + urlObj.pathname + urlObj.search;
  } catch {
    return url;
  }
}

// ===== Auth Functions =====

async function startLogin() {
  const loginUrl = `${WORKER_URL}/auth/x/extension-login`;
  const tab = await chrome.tabs.create({ url: loginUrl });
  loginTabId = tab.id;
  return { success: true };
}

async function getAuthStatus() {
  const result = await chrome.storage.local.get(["authData"]);
  if (result.authData?.jwt) {
    return { isLoggedIn: true, user: result.authData.user || null };
  }
  return { isLoggedIn: false };
}

async function saveAuthData(data) {
  const authData = {
    jwt: data.jwt,
    refresh_token: data.refresh_token,
    user: data.user ? JSON.parse(data.user) : null
  };
  await chrome.storage.local.set({ authData });
  return authData;
}

async function logout() {
  await chrome.storage.local.remove(["authData"]);
  return { success: true };
}

async function refreshToken() {
  const result = await chrome.storage.local.get(["authData"]);
  if (!result.authData?.refresh_token) return { error: "No refresh token" };

  try {
    const response = await fetch(`${WORKER_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: result.authData.refresh_token })
    });
    if (!response.ok) return { error: "Refresh failed" };

    const tokenData = await response.json();
    const authData = await saveAuthData({
      jwt: tokenData.jwt,
      refresh_token: tokenData.refresh_token || result.authData.refresh_token,
      user: JSON.stringify(tokenData.user)
    });
    return { success: true, auth: authData };
  } catch (error) {
    return { error: error.message };
  }
}

// ===== Tracking =====

async function sendTrackingData(domain, durationSeconds, title, description) {
  try {
    const result = await chrome.storage.local.get(["authData"]);
    if (!result.authData?.jwt) return;

    const response = await fetch(`${WORKER_URL}/api/track`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${result.authData.jwt}`
      },
      body: JSON.stringify({
        domain,
        duration: durationSeconds,
        title: title || "",
        description: description || ""
      })
    });

    if (response.status === 401) {
      const refreshResult = await refreshToken();
      if (refreshResult.success) {
        await sendTrackingData(domain, durationSeconds, title, description);
      }
    }
  } catch (error) {
    console.error("Error sending tracking data:", error);
  }
}

function getStatsUrl() {
  return new Promise(async (resolve) => {
    const result = await chrome.storage.local.get(["authData"]);
    if (result.authData?.jwt) {
      resolve(
        `${WORKER_URL}/stats?token=${encodeURIComponent(result.authData.jwt)}`
      );
    } else {
      resolve(null);
    }
  });
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.action === "xLogin") {
    startLogin().then(sendResponse);
    return true;
  } else if (request.action === "xLogout") {
    logout().then(sendResponse);
    return true;
  } else if (request.action === "getXAuthStatus") {
    getAuthStatus().then(sendResponse);
    return true;
  } else if (request.action === "refreshXToken") {
    refreshToken().then(sendResponse);
    return true;
  } else if (request.action === "getStatsUrl") {
    getStatsUrl().then(sendResponse);
    return true;
  }
});
