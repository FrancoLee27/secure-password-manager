# Setting Up Your GitHub Repository

Follow these steps to create a repository on GitHub and push your code:

## 1. Create a Repository on GitHub

1. Go to [https://github.com/new](https://github.com/new)
2. Enter a name for your repository (e.g., "password-manager")
3. Add an optional description
4. Choose Public or Private visibility
5. **DO NOT** initialize with README, .gitignore, or license (we already have these files)
6. Click "Create repository"

## 2. Push Your Code to GitHub

After creating the repository, GitHub will display commands to push an existing repository. Use these commands:

```bash
# If you want to use HTTPS (requires username and password/token for each push):
git remote set-url origin https://github.com/YourUsername/password-manager.git
git push -u origin main

# If you want to use SSH (requires SSH key setup but no password afterward):
git remote set-url origin git@github.com:YourUsername/password-manager.git
git push -u origin main
```

## 3. Authentication

### For HTTPS Authentication:
1. When prompted for a password, use a personal access token, not your GitHub password
2. To create a token:
   - Go to GitHub → Settings → Developer settings → Personal access tokens → Generate new token
   - Give it a name, set an expiration, and select the "repo" scope
   - Copy the token and use it as your password when pushing

### For SSH Authentication:
1. Check if you have SSH keys: `ls -al ~/.ssh`
2. Generate a key if needed: `ssh-keygen -t ed25519 -C "your_email@example.com"`
3. Add to SSH agent: `eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519`
4. Add to GitHub:
   - Copy key: `cat ~/.ssh/id_ed25519.pub`
   - Go to GitHub → Settings → SSH and GPG keys → New SSH key
   - Paste the key and save

## Future Pushes

After the initial setup, you can commit and push changes with:

```bash
git add .
git commit -m "Your commit message"
git push
```
