#!/bin/bash

# Create a ZIP archive of the current repository
echo "Creating ZIP archive of the repository..."
zip -r password-manager-export.zip . -x "*.git*" -x "*__pycache__*" -x "*.DS_Store" -x "*.pyc" -x "*.pyo" -x "*/.venv/*" -x "*.egg-info/*"

echo ""
echo "ZIP archive created: password-manager-export.zip"
echo ""
echo "To upload to GitHub:"
echo "1. Go to https://github.com/new"
echo "2. Create a new repository (with the same name as in your README.md)"
echo "3. After creating the repository, click on 'uploading an existing file'"
echo "4. Drag and drop the password-manager-export.zip file"
echo "5. Click 'Commit changes'"
echo ""
echo "This will give you a starting point on GitHub, and you can clone it"
echo "to continue development with proper Git workflow." 