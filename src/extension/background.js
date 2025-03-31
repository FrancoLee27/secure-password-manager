/**
 * Secure Password Manager - Background Script
 * 
 * Handles communication between the popup, content scripts, and native application.
 * Manages secure vault access and provides password fill functionality.
 */

// Global state
let state = {
  isUnlocked: false,
  vaultKey: null,
  sessionExpiry: null,
  vault: null,
  activeTab: null
};

// Default auto-lock timeout (in milliseconds)
const AUTO_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes

// Native messaging connection
let nativePort = null;

/**
 * Initialize the extension
 */
function init() {
  // Listen for messages from popup and content scripts
  chrome.runtime.onMessage.addListener(handleMessage);
  
  // Listen for tab changes to update active tab info
  chrome.tabs.onActivated.addListener(updateActiveTab);
  chrome.tabs.onUpdated.addListener(handleTabUpdate);
  
  // Set up native messaging (for desktop app integration)
  connectToNativeApp();
  
  // Get current tab
  updateActiveTab();
  
  console.log("Secure Password Manager background script initialized");
}

/**
 * Connect to native messaging host (desktop application)
 */
function connectToNativeApp() {
  try {
    nativePort = chrome.runtime.connectNative("com.securepasswordmanager.app");
    
    nativePort.onMessage.addListener((message) => {
      console.log("Received message from native app:", message);
      
      if (message.type === "vault_data") {
        // Handle vault data from native app
        handleVaultData(message.data);
      }
    });
    
    nativePort.onDisconnect.addListener(() => {
      console.log("Disconnected from native app:", chrome.runtime.lastError);
      nativePort = null;
    });
    
    console.log("Connected to native app");
  } catch (error) {
    console.error("Failed to connect to native app:", error);
    nativePort = null;
  }
}

/**
 * Handle incoming messages from popup or content scripts
 */
function handleMessage(message, sender, sendResponse) {
  console.log("Received message:", message.action);
  
  switch (message.action) {
    case "unlock":
      unlockVault(message.masterPassword)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Indicates async response
      
    case "lock":
      lockVault();
      sendResponse({ success: true });
      break;
      
    case "getStatus":
      sendResponse({
        isUnlocked: state.isUnlocked,
        hasVault: !!state.vault,
        sessionExpiry: state.sessionExpiry
      });
      break;
      
    case "getPasswords":
      if (!state.isUnlocked) {
        sendResponse({ success: false, error: "Vault is locked" });
        break;
      }
      
      sendResponse({
        success: true,
        passwords: state.vault ? state.vault.entries : []
      });
      break;
      
    case "getPasswordsForDomain":
      if (!state.isUnlocked) {
        sendResponse({ success: false, error: "Vault is locked" });
        break;
      }
      
      const domain = message.domain;
      const passwordsForDomain = findPasswordsForDomain(domain);
      sendResponse({
        success: true,
        domain: domain,
        entries: passwordsForDomain
      });
      break;
      
    case "fillPassword":
      fillPassword(message.entryId)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Indicates async response
      
    case "addPassword":
      addPassword(message.entry)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Indicates async response
      
    default:
      sendResponse({ success: false, error: "Unknown action" });
  }
}

/**
 * Update the active tab information
 */
function updateActiveTab(activeInfo) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs.length > 0) {
      state.activeTab = tabs[0];
    }
  });
}

/**
 * Handle tab updates
 */
function handleTabUpdate(tabId, changeInfo, tab) {
  // If the active tab URL changed, update active tab
  if (state.activeTab && state.activeTab.id === tabId && changeInfo.url) {
    state.activeTab = tab;
  }
}

/**
 * Unlock the vault with the master password
 */
async function unlockVault(masterPassword) {
  try {
    // In a real implementation, this would communicate with the native app
    // to unlock the vault using the master password
    
    if (nativePort) {
      // Send unlock request to native app
      nativePort.postMessage({
        action: "unlock",
        masterPassword: masterPassword
      });
      
      // This is a simplified version; normally we'd wait for a response
      // For now, simulate a successful unlock
      state.isUnlocked = true;
      state.sessionExpiry = Date.now() + AUTO_LOCK_TIMEOUT;
      
      // Simulate vault data (would actually come from native app)
      state.vault = {
        entries: [
          {
            id: "1",
            title: "Example Account",
            username: "user@example.com",
            password: "SecurePassword123!",
            url: "https://example.com",
            notes: "This is an example account",
            category: "Personal",
            lastModified: Date.now()
          }
        ]
      };
      
      return { success: true };
    } else {
      // If native app is not connected, use a simplified in-memory approach
      // THIS IS NOT SECURE and is only for demo purposes
      
      // In a real implementation, we'd derive the vault key from the master password
      // and decrypt the vault data
      
      // Simulate successful unlock
      state.isUnlocked = true;
      state.sessionExpiry = Date.now() + AUTO_LOCK_TIMEOUT;
      
      // Sample vault data
      state.vault = {
        entries: [
          {
            id: "1",
            title: "Example Account",
            username: "user@example.com",
            password: "SecurePassword123!",
            url: "https://example.com",
            notes: "This is an example account",
            category: "Personal",
            lastModified: Date.now()
          }
        ]
      };
      
      return { success: true };
    }
  } catch (error) {
    console.error("Error unlocking vault:", error);
    return { success: false, error: error.message };
  }
}

/**
 * Lock the vault
 */
function lockVault() {
  state.isUnlocked = false;
  state.vaultKey = null;
  state.sessionExpiry = null;
  state.vault = null;
  
  if (nativePort) {
    nativePort.postMessage({ action: "lock" });
  }
  
  console.log("Vault locked");
}

/**
 * Find passwords for a specific domain
 */
function findPasswordsForDomain(domain) {
  if (!state.isUnlocked || !state.vault) {
    return [];
  }
  
  // Simple domain matching (in a real implementation, this would be more sophisticated)
  return state.vault.entries.filter(entry => {
    try {
      const entryUrl = new URL(entry.url);
      const entryDomain = entryUrl.hostname;
      
      return entryDomain.includes(domain) || domain.includes(entryDomain);
    } catch (e) {
      // If URL parsing fails, try simple string matching
      return entry.url.includes(domain);
    }
  });
}

/**
 * Fill a password in the active tab
 */
async function fillPassword(entryId) {
  if (!state.isUnlocked || !state.vault) {
    return { success: false, error: "Vault is locked" };
  }
  
  const entry = state.vault.entries.find(e => e.id === entryId);
  if (!entry) {
    return { success: false, error: "Entry not found" };
  }
  
  // Send message to content script to fill the password
  try {
    const result = await chrome.tabs.sendMessage(state.activeTab.id, {
      action: "fillForm",
      username: entry.username,
      password: entry.password
    });
    
    return { success: true, result };
  } catch (error) {
    console.error("Error filling password:", error);
    return { success: false, error: error.message };
  }
}

/**
 * Add a new password to the vault
 */
async function addPassword(entry) {
  if (!state.isUnlocked) {
    return { success: false, error: "Vault is locked" };
  }
  
  try {
    // Generate a new ID for the entry
    entry.id = Date.now().toString();
    entry.lastModified = Date.now();
    
    // Add to local vault
    state.vault.entries.push(entry);
    
    // If native app is connected, send update
    if (nativePort) {
      nativePort.postMessage({
        action: "addPassword",
        entry: entry
      });
    }
    
    return { success: true, entryId: entry.id };
  } catch (error) {
    console.error("Error adding password:", error);
    return { success: false, error: error.message };
  }
}

/**
 * Handle vault data from native app
 */
function handleVaultData(vaultData) {
  state.vault = vaultData;
  console.log("Vault data updated from native app");
}

// Initialize the extension
init(); 