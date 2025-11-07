#!/bin/bash
#
# Git Push Helper Script
# Automates committing and pushing changes to GitHub
#

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${BLUE}=========================================="
echo "Git Push Helper"
echo "==========================================${NC}"
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}Git repository not initialized. Initializing...${NC}"
    git init
    echo -e "${GREEN}✓ Git repository initialized${NC}"
fi

# Check if remote is set
if ! git remote | grep -q "^origin$"; then
    echo -e "${YELLOW}No remote 'origin' found.${NC}"
    echo "Please add your GitHub repository:"
    echo "  git remote add origin https://github.com/Gamechiefx/DNS-Automator.git"
    echo ""
    read -p "Enter GitHub repository URL (or press Enter to skip): " REPO_URL
    if [ ! -z "$REPO_URL" ]; then
        git remote add origin "$REPO_URL"
        echo -e "${GREEN}✓ Remote added${NC}"
    else
        echo -e "${YELLOW}⚠ Skipping remote setup. Run manually:${NC}"
        echo "  git remote add origin https://github.com/Gamechiefx/DNS-Automator.git"
    fi
fi

# Show current status
echo ""
echo -e "${BLUE}Current git status:${NC}"
git status --short

# Check if there are changes
if git diff --quiet && git diff --cached --quiet; then
    echo -e "${YELLOW}No changes to commit.${NC}"
    exit 0
fi

# Ask for commit message
echo ""
if [ -z "$1" ]; then
    read -p "Enter commit message (or press Enter for default): " COMMIT_MSG
    if [ -z "$COMMIT_MSG" ]; then
        COMMIT_MSG="Update DNS analyzer files - $(date '+%Y-%m-%d %H:%M:%S')"
    fi
else
    COMMIT_MSG="$1"
fi

# Add all changes
echo ""
echo -e "${BLUE}Staging changes...${NC}"
git add .

# Commit
echo -e "${BLUE}Committing changes...${NC}"
git commit -m "$COMMIT_MSG"
echo -e "${GREEN}✓ Changes committed${NC}"

# Get current branch
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "main")

# Check if branch exists on remote
if git ls-remote --heads origin "$CURRENT_BRANCH" | grep -q "$CURRENT_BRANCH"; then
    echo ""
    echo -e "${BLUE}Pushing to origin/$CURRENT_BRANCH...${NC}"
    git push origin "$CURRENT_BRANCH"
else
    echo ""
    echo -e "${BLUE}Setting upstream and pushing to origin/$CURRENT_BRANCH...${NC}"
    git push -u origin "$CURRENT_BRANCH"
fi

echo ""
echo -e "${GREEN}=========================================="
echo "✓ Successfully pushed to GitHub!"
echo "==========================================${NC}"
echo ""

