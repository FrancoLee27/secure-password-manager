/**
 * Secure Password Manager - Popup Script
 * 
 * Handles the extension popup UI and communicates with the background script.
 */

// DOM elements
const lockedView = document.getElementById('locked-view');
const unlockButton = document.getElementById('unlock-button');
const masterPasswordInput = document.getElementById('master-password');
const unlockError = document.getElementById('unlock-error');

const loadingView = document.getElementById('loading-view');

const unlockedView = document.getElementById('unlocked-view');
const lockButton = document.getElementById('lock-button');
const addPasswordButton = document.getElementById('add-password-button');
const sitePasswordList = document.getElementById('site-password-list');
const allPasswordList = document.getElementById('all-password-list');
const siteNoPasswords = document.getElementById('site-no-passwords');
const statusMessage = document.getElementById('status-message');

const addPasswordView = document.getElementById('add-password-view');
const savePasswordButton = document.getElementById('save-password-button');
const cancelAddButton = document.getElementById('cancel-add-button');
const titleInput = document.getElementById('title');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const urlInput = document.getElementById('url');
const notesInput = document.getElementById('notes');
const addError = document.getElementById('add-error');

// Current active tab info
let activeTab = null;

/**
 * Initialize the popup
 */
function init() {
  // Set up event listeners
  unlockButton.addEventListener('click', handleUnlock);
  masterPasswordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });
  
  lockButton.addEventListener('click', handleLock);
  addPasswordButton.addEventListener('click', showAddPasswordView);
  savePasswordButton.addEventListener('click', handleSavePassword);
  cancelAddButton.addEventListener('click', hideAddPasswordView);
  
  // Get the current tab
  getCurrentTab().then(tab => {
    activeTab = tab;
    
    // Pre-fill the URL field on the add password form
    if (tab && tab.url) {
      urlInput.value = tab.url;
    }
    
    // Check if the vault is unlocked
    checkVaultStatus();
  });
}

/**
 * Show loading state
 */
function showLoading() {
  lockedView.classList.remove('show');
  unlockedView.classList.remove('show');
  addPasswordView.classList.remove('show');
  loadingView.classList.add('show');
}

/**
 * Hide loading state
 */
function hideLoading() {
  loadingView.classList.remove('show');
}

/**
 * Show error message in the unlock view
 */
function showUnlockError(message) {
  unlockError.textContent = message;
  unlockError.style.display = 'block';
}

/**
 * Hide error message in the unlock view
 */
function hideUnlockError() {
  unlockError.style.display = 'none';
}

/**
 * Show error message in the add password view
 */
function showAddError(message) {
  addError.textContent = message;
  addError.style.display = 'block';
}

/**
 * Hide error message in the add password view
 */
function hideAddError() {
  addError.style.display = 'none';
}

/**
 * Show the locked view
 */
function showLockedView() {
  lockedView.classList.add('show');
  unlockedView.classList.remove('show');
  addPasswordView.classList.remove('show');
  loadingView.classList.remove('show');
  
  // Clear master password field
  masterPasswordInput.value = '';
  hideUnlockError();
  
  // Focus on the master password field
  setTimeout(() => masterPasswordInput.focus(), 100);
}

/**
 * Show the unlocked view
 */
function showUnlockedView() {
  lockedView.classList.remove('show');
  unlockedView.classList.add('show');
  addPasswordView.classList.remove('show');
  loadingView.classList.remove('show');
  
  // Load passwords
  loadPasswords();
}

/**
 * Show the add password view
 */
function showAddPasswordView() {
  lockedView.classList.remove('show');
  unlockedView.classList.remove('show');
  addPasswordView.classList.add('show');
  loadingView.classList.remove('show');
  
  // Focus on the title field
  setTimeout(() => titleInput.focus(), 100);
  
  // Clear error messages
  hideAddError();
}

/**
 * Hide the add password view
 */
function hideAddPasswordView() {
  showUnlockedView();
  
  // Clear form fields
  titleInput.value = '';
  usernameInput.value = '';
  passwordInput.value = '';
  
  // Preserve the URL from the active tab
  if (activeTab && activeTab.url) {
    urlInput.value = activeTab.url;
  } else {
    urlInput.value = '';
  }
  
  notesInput.value = '';
}

/**
 * Get the current active tab
 */
async function getCurrentTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0) {
        resolve(tabs[0]);
      } else {
        resolve(null);
      }
    });
  });
}

/**
 * Check the vault status
 */
async function checkVaultStatus() {
  showLoading();
  
  try {
    const status = await sendMessage({ action: 'getStatus' });
    
    if (status.isUnlocked) {
      showUnlockedView();
    } else {
      showLockedView();
    }
    
    // Update status message
    if (status.sessionExpiry) {
      const expiryDate = new Date(status.sessionExpiry);
      const now = new Date();
      const minutesRemaining = Math.round((expiryDate - now) / 60000);
      
      if (minutesRemaining > 0) {
        statusMessage.textContent = `Session expires in ${minutesRemaining} minute(s)`;
      } else {
        statusMessage.textContent = 'Session expires soon';
      }
    }
  } catch (error) {
    console.error('Error checking vault status:', error);
    showLockedView();
  }
}

/**
 * Handle unlock button click
 */
async function handleUnlock() {
  const masterPassword = masterPasswordInput.value;
  
  if (!masterPassword) {
    showUnlockError('Please enter your master password');
    return;
  }
  
  showLoading();
  
  try {
    const result = await sendMessage({
      action: 'unlock',
      masterPassword: masterPassword
    });
    
    if (result.success) {
      showUnlockedView();
    } else {
      showLockedView();
      showUnlockError(result.error || 'Failed to unlock vault');
    }
  } catch (error) {
    console.error('Error unlocking vault:', error);
    showLockedView();
    showUnlockError('An error occurred while unlocking');
  }
}

/**
 * Handle lock button click
 */
async function handleLock() {
  showLoading();
  
  try {
    await sendMessage({ action: 'lock' });
    showLockedView();
  } catch (error) {
    console.error('Error locking vault:', error);
    showLockedView();
  }
}

/**
 * Load passwords
 */
async function loadPasswords() {
  try {
    // Load site-specific passwords
    if (activeTab && activeTab.url) {
      try {
        const domain = new URL(activeTab.url).hostname;
        const result = await sendMessage({
          action: 'getPasswordsForDomain',
          domain: domain
        });
        
        if (result.success && result.entries && result.entries.length > 0) {
          renderPasswordList(result.entries, sitePasswordList, true);
          siteNoPasswords.style.display = 'none';
        } else {
          sitePasswordList.innerHTML = '';
          siteNoPasswords.style.display = 'block';
        }
      } catch (error) {
        console.error('Error loading site passwords:', error);
        sitePasswordList.innerHTML = '';
        siteNoPasswords.style.display = 'block';
      }
    } else {
      sitePasswordList.innerHTML = '';
      siteNoPasswords.style.display = 'block';
    }
    
    // Load all passwords
    const result = await sendMessage({ action: 'getPasswords' });
    
    if (result.success && result.passwords && result.passwords.length > 0) {
      renderPasswordList(result.passwords, allPasswordList, false);
    } else {
      allPasswordList.innerHTML = '';
    }
  } catch (error) {
    console.error('Error loading passwords:', error);
    sitePasswordList.innerHTML = '';
    allPasswordList.innerHTML = '';
    siteNoPasswords.style.display = 'block';
  }
}

/**
 * Render a list of passwords
 */
function renderPasswordList(passwords, container, withActions = true) {
  container.innerHTML = '';
  
  passwords.forEach(entry => {
    const listItem = document.createElement('li');
    listItem.className = 'password-item';
    
    const title = document.createElement('h3');
    title.textContent = entry.title;
    
    const username = document.createElement('p');
    username.textContent = `Username: ${entry.username}`;
    
    const url = document.createElement('p');
    url.textContent = `URL: ${truncateUrl(entry.url)}`;
    
    listItem.appendChild(title);
    listItem.appendChild(username);
    listItem.appendChild(url);
    
    if (withActions) {
      const actions = document.createElement('div');
      actions.className = 'password-actions';
      
      const fillButton = document.createElement('button');
      fillButton.textContent = 'Fill';
      fillButton.addEventListener('click', () => handleFillPassword(entry.id));
      
      const copyUsername = document.createElement('button');
      copyUsername.textContent = 'Copy Username';
      copyUsername.addEventListener('click', () => copyToClipboard(entry.username));
      
      const copyPassword = document.createElement('button');
      copyPassword.textContent = 'Copy Password';
      copyPassword.addEventListener('click', () => copyToClipboard(entry.password));
      
      actions.appendChild(fillButton);
      actions.appendChild(copyUsername);
      actions.appendChild(copyPassword);
      
      listItem.appendChild(actions);
    }
    
    container.appendChild(listItem);
  });
}

/**
 * Truncate a URL for display
 */
function truncateUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (e) {
    return url.length > 30 ? url.substring(0, 27) + '...' : url;
  }
}

/**
 * Handle fill password button click
 */
async function handleFillPassword(entryId) {
  try {
    const result = await sendMessage({
      action: 'fillPassword',
      entryId: entryId
    });
    
    if (result.success) {
      window.close(); // Close the popup after filling
    } else {
      alert(`Failed to fill password: ${result.error}`);
    }
  } catch (error) {
    console.error('Error filling password:', error);
    alert('An error occurred while filling the password');
  }
}

/**
 * Handle save password button click
 */
async function handleSavePassword() {
  // Validate form
  const title = titleInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const url = urlInput.value.trim();
  const notes = notesInput.value.trim();
  
  if (!title) {
    showAddError('Title is required');
    return;
  }
  
  if (!username) {
    showAddError('Username is required');
    return;
  }
  
  if (!password) {
    showAddError('Password is required');
    return;
  }
  
  showLoading();
  
  try {
    const result = await sendMessage({
      action: 'addPassword',
      entry: {
        title,
        username,
        password,
        url,
        notes,
        category: 'Uncategorized'
      }
    });
    
    if (result.success) {
      hideAddPasswordView();
      loadPasswords();
    } else {
      hideLoading();
      showAddPasswordView();
      showAddError(result.error || 'Failed to save password');
    }
  } catch (error) {
    console.error('Error saving password:', error);
    hideLoading();
    showAddPasswordView();
    showAddError('An error occurred while saving the password');
  }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    
    // Show confirmation
    const original = statusMessage.textContent;
    statusMessage.textContent = 'Copied to clipboard!';
    
    // Reset after 2 seconds
    setTimeout(() => {
      statusMessage.textContent = original;
    }, 2000);
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    statusMessage.textContent = 'Failed to copy to clipboard';
  }
}

/**
 * Send a message to the background script
 */
function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(response);
      }
    });
  });
}

// Initialize the popup
document.addEventListener('DOMContentLoaded', init); 