const path = require('path');
const express = require('express');
const vaultManager = require('./core/password/vault');

// Initialize the application
async function initializeApp() {
  console.log('Initializing Secure Password Manager...');
  
  // Database path
  const dbPath = path.join(process.env.HOME || process.env.USERPROFILE, '.securepm', 'vault.db');
  
  // Initialize vault manager
  const initialized = await vaultManager.initialize(dbPath);
  if (!initialized) {
    console.error('Failed to initialize vault manager');
    process.exit(1);
  }
  
  console.log('Vault manager initialized successfully');
  
  // Create Express app
  const app = express();
  app.use(express.json());
  
  // API routes
  setupRoutes(app);
  
  // Start server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Set up API routes
function setupRoutes(app) {
  // Status endpoint
  app.get('/api/status', (req, res) => {
    res.json({
      status: 'ok',
      locked: vaultManager.isLocked,
      initialized: vaultManager.isInitialized
    });
  });
  
  // Create vault
  app.post('/api/vault/create', async (req, res) => {
    const { masterPassword } = req.body;
    
    if (!masterPassword) {
      return res.status(400).json({
        success: false,
        error: 'Master password is required'
      });
    }
    
    const result = await vaultManager.createVault(masterPassword);
    res.json(result);
  });
  
  // Unlock vault
  app.post('/api/vault/unlock', async (req, res) => {
    const { masterPassword } = req.body;
    
    if (!masterPassword) {
      return res.status(400).json({
        success: false,
        error: 'Master password is required'
      });
    }
    
    const result = await vaultManager.unlockVault(masterPassword);
    res.json(result);
  });
  
  // Lock vault
  app.post('/api/vault/lock', (req, res) => {
    const result = vaultManager.lockVault();
    res.json(result);
  });
  
  // Change master password
  app.post('/api/vault/change-master-password', async (req, res) => {
    const { currentMasterPassword, newMasterPassword } = req.body;
    
    if (!currentMasterPassword || !newMasterPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current and new master passwords are required'
      });
    }
    
    const result = await vaultManager.changeMasterPassword(currentMasterPassword, newMasterPassword);
    res.json(result);
  });
  
  // Recover vault
  app.post('/api/vault/recover', async (req, res) => {
    const { recoveryKey, newMasterPassword } = req.body;
    
    if (!recoveryKey || !newMasterPassword) {
      return res.status(400).json({
        success: false,
        error: 'Recovery key and new master password are required'
      });
    }
    
    const result = await vaultManager.recoverVault(recoveryKey, newMasterPassword);
    res.json(result);
  });
  
  // Password management endpoints
  app.get('/api/passwords', async (req, res) => {
    const result = await vaultManager.getAllPasswords();
    res.json(result);
  });
  
  app.post('/api/passwords', async (req, res) => {
    const passwordEntry = req.body;
    const result = await vaultManager.addPassword(passwordEntry);
    res.json(result);
  });
  
  app.put('/api/passwords/:id', async (req, res) => {
    const passwordEntry = {
      id: parseInt(req.params.id, 10),
      ...req.body
    };
    
    const result = await vaultManager.updatePassword(passwordEntry);
    res.json(result);
  });
  
  app.delete('/api/passwords/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const result = await vaultManager.deletePassword(id);
    res.json(result);
  });
  
  // Password generator endpoints
  app.post('/api/generator/password', (req, res) => {
    const options = req.body;
    const result = vaultManager.generatePassword(options);
    res.json(result);
  });
  
  app.post('/api/generator/passphrase', (req, res) => {
    const options = req.body;
    const result = vaultManager.generatePassphrase(options);
    res.json(result);
  });
  
  // Password strength analyzer
  app.post('/api/strength', (req, res) => {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Password is required'
      });
    }
    
    const strengthAnalyzer = require('./core/password/strength');
    const result = strengthAnalyzer.analyzePassword(password);
    
    res.json({
      success: true,
      strength: result
    });
  });
  
  // Breach checker endpoints
  app.post('/api/breach-check', async (req, res) => {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Password is required'
      });
    }
    
    const result = await vaultManager.checkPasswordBreach(password);
    res.json(result);
  });
  
  app.get('/api/breach-check/all', async (req, res) => {
    const result = await vaultManager.checkAllPasswordBreaches();
    res.json(result);
  });
  
  // Error handler
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  });
}

// Start the application
initializeApp().catch(err => {
  console.error('Failed to start application:', err);
  process.exit(1);
}); 