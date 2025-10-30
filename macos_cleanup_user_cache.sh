#!/bin/bash
# macos_cleanup_user_caches.sh - safely clean user cache folders

CACHE_DIR="$HOME/Library/Caches"

echo "Cleaning user cache directory: $CACHE_DIR"
echo "This may take a few minutes..."

# Ensure the folder exists
if [ -d "$CACHE_DIR" ]; then
  find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  echo "✅ Caches cleaned successfully."
else
  echo "⚠️ Cache directory not found: $CACHE_DIR"
fi
