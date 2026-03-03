// ===== X Auth UI Functions =====

function updateUserSection(authStatus) {
  const userSection = document.getElementById("userSection");
  const viewStatsBtn = document.getElementById("viewStats");
  const loginPrompt = document.getElementById("loginPrompt");

  if (authStatus.isLoggedIn && authStatus.user) {
    const user = authStatus.user;
    userSection.className = "user-section";
    userSection.innerHTML = `
      <img class="user-avatar" src="${user.profile_image_url || ""}" alt="${user.name}" onerror="this.style.display='none'">
      <div class="user-info">
        <div class="user-name">${user.name}</div>
        <div class="user-handle">@${user.username}</div>
      </div>
      <button id="xLogoutBtn" class="x-logout">Logout</button>
    `;

    document.getElementById("xLogoutBtn").addEventListener("click", handleLogout);
    viewStatsBtn.disabled = false;
    loginPrompt.style.display = "none";
  } else {
    userSection.className = "user-section logged-out";
    userSection.innerHTML = `
      <button id="xLoginBtn" class="x-login">
        <svg class="x-icon" viewBox="0 0 24 24" fill="currentColor">
          <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
        </svg>
        Login with X
      </button>
    `;

    document.getElementById("xLoginBtn").addEventListener("click", handleLogin);
    viewStatsBtn.disabled = true;
    loginPrompt.style.display = "block";
  }
}

async function loadAuthStatus() {
  chrome.runtime.sendMessage({ action: "getXAuthStatus" }, (response) => {
    const authStatus = response || { isLoggedIn: false };
    updateUserSection(authStatus);
  });
}

function handleLogin() {
  chrome.runtime.sendMessage({ action: "xLogin" }, () => {
    window.close();
  });
}

function handleLogout() {
  if (confirm("Are you sure you want to logout from X?")) {
    chrome.runtime.sendMessage({ action: "xLogout" }, () => {
      loadAuthStatus();
    });
  }
}

function openStats() {
  chrome.runtime.sendMessage({ action: "getStatsUrl" }, (url) => {
    if (url) {
      chrome.tabs.create({ url: url });
      window.close();
    }
  });
}

// Event listeners
document.getElementById("viewStats").addEventListener("click", openStats);

// Load auth status when popup opens
loadAuthStatus();
