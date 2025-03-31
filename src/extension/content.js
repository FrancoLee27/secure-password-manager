/**
 * Secure Password Manager - Content Script
 * 
 * Handles interaction with web pages, including form detection and password filling.
 */

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Content script received message:", message.action);
  
  switch (message.action) {
    case "fillForm":
      fillForm(message.username, message.password)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Indicates async response
      
    case "detectForms":
      const forms = detectForms();
      sendResponse({ success: true, forms: forms });
      break;
      
    default:
      sendResponse({ success: false, error: "Unknown action" });
  }
});

/**
 * Detect login forms on the page
 */
function detectForms() {
  const forms = [];
  
  // Find forms
  document.querySelectorAll('form').forEach((form, formIndex) => {
    const formData = {
      index: formIndex,
      action: form.action || window.location.href,
      hasPasswordField: false,
      fields: []
    };
    
    // Find fields in the form
    const inputs = form.querySelectorAll('input');
    inputs.forEach((input, inputIndex) => {
      const type = input.type.toLowerCase();
      
      if (type === 'password') {
        formData.hasPasswordField = true;
        formData.fields.push({
          index: inputIndex,
          type: 'password',
          id: input.id,
          name: input.name
        });
      } else if (type === 'text' || type === 'email' || type === '') {
        formData.fields.push({
          index: inputIndex,
          type: type || 'text',
          id: input.id,
          name: input.name
        });
      }
    });
    
    // Only add forms with password fields
    if (formData.hasPasswordField) {
      forms.push(formData);
    }
  });
  
  return forms;
}

/**
 * Fill a form with username and password
 */
async function fillForm(username, password) {
  try {
    // Try to find the login form
    const forms = detectForms();
    
    if (forms.length === 0) {
      return { success: false, error: "No login form found" };
    }
    
    // Use the first form with password field
    const form = forms[0];
    
    // Find username and password fields
    let usernameField = null;
    let passwordField = null;
    
    const formElement = document.querySelectorAll('form')[form.index];
    
    // Find password field first
    for (const field of form.fields) {
      if (field.type === 'password') {
        passwordField = formElement.querySelectorAll('input')[field.index];
        break;
      }
    }
    
    // Then find a username field (usually comes before password)
    for (const field of form.fields) {
      if (field.type === 'text' || field.type === 'email') {
        usernameField = formElement.querySelectorAll('input')[field.index];
        break;
      }
    }
    
    // Fill the fields
    if (usernameField && passwordField) {
      // Fill username field
      usernameField.value = username;
      usernameField.dispatchEvent(new Event('input', { bubbles: true }));
      usernameField.dispatchEvent(new Event('change', { bubbles: true }));
      
      // Fill password field
      passwordField.value = password;
      passwordField.dispatchEvent(new Event('input', { bubbles: true }));
      passwordField.dispatchEvent(new Event('change', { bubbles: true }));
      
      return {
        success: true,
        message: "Form filled successfully"
      };
    } else {
      return {
        success: false,
        error: "Could not find appropriate fields"
      };
    }
  } catch (error) {
    console.error("Error filling form:", error);
    return { success: false, error: error.message };
  }
}

/**
 * Detect page load and notify background script
 */
function notifyPageLoad() {
  // Get domain from current URL
  const domain = window.location.hostname;
  
  // Notify background script about the page
  chrome.runtime.sendMessage({
    action: "pageLoaded",
    url: window.location.href,
    domain: domain,
    forms: detectForms()
  });
}

// Execute when loaded
window.addEventListener('load', notifyPageLoad);

// Also notify on initial content script load (for already loaded pages)
notifyPageLoad(); 