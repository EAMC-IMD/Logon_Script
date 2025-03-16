#!/bin/bash

# Define the target file path
HOOK_FILE=".git/hooks/pre-commit"

# Ensure the hooks directory exists
mkdir -p "$(dirname "$HOOK_FILE")"

# Write the pre-commit script
cat > "$HOOK_FILE" << 'EOF'
#!/bin/sh
exec "$(dirname "$0")/../../PreCommit Script/pre-commit" "$@"
EOF

# Make it executable
chmod +x "$HOOK_FILE"

echo "Pre-commit hook installed and made executable."