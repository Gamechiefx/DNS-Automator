# Git Setup and Regular Pushing Guide

This guide will help you set up git for regular pushes to your GitHub repository.

## Initial Setup (One-time)

### 1. Initialize Git Repository

If you haven't already initialized git locally:

```bash
git init
git branch -M main  # Rename default branch to 'main' (if needed)
```

### 2. Add Remote Repository

Connect your local repository to GitHub:

```bash
git remote add origin https://github.com/Gamechiefx/DNS-Automator.git
```

Verify the remote:
```bash
git remote -v
```

### 3. Initial Commit and Push

```bash
# Add all files
git add .

# Commit
git commit -m "Initial commit - DNS Packet Analyzer"

# Push to GitHub
git push -u origin main
```

## Regular Pushing Methods

### Method 1: Using the Git Push Helper Script (Recommended)

The `git_push.sh` script automates the process:

```bash
# Push with automatic commit message
./git_push.sh

# Or provide a custom commit message
./git_push.sh "Your custom commit message"
```

The script will:
- Check git status
- Stage all changes
- Commit with your message (or auto-generate one)
- Push to GitHub

### Method 2: Manual Git Commands

For regular pushes, use these commands:

```bash
# 1. Check what changed
git status

# 2. Add all changes
git add .

# 3. Commit with a message
git commit -m "Update: description of changes"

# 4. Push to GitHub
git push origin main
```

### Method 3: Automated Daily Push (Cron Job)

To automatically push changes daily, add a cron job:

```bash
# Edit crontab
crontab -e

# Add this line to push daily at 2 AM
0 2 * * * cd /path/to/DNS-Automator && ./git_push.sh "Daily update - $(date '+%Y-%m-%d')" >> /tmp/git_push.log 2>&1
```

Or create a systemd timer (Linux) or launchd plist (macOS) for more control.

## What Gets Committed

The `.gitignore` file excludes:
- `venv/` - Virtual environment
- `output/` - Generated CSV and JSON files
- `*.log` - Log files
- `__pycache__/` - Python cache files
- `.DS_Store` - macOS system files

**Important**: Output files (CSVs, JSONs) are excluded by default. If you want to commit them, modify `.gitignore`.

## Troubleshooting

### Authentication Issues

If you get authentication errors, you may need to:

1. **Use Personal Access Token** (recommended):
   - Go to GitHub → Settings → Developer settings → Personal access tokens
   - Generate a token with `repo` permissions
   - Use token as password when pushing

2. **Use SSH instead of HTTPS**:
   ```bash
   git remote set-url origin git@github.com:Gamechiefx/DNS-Automator.git
   ```

### Branch Name Mismatch

If your default branch is `master` instead of `main`:
```bash
git branch -M main
git push -u origin main
```

### Updating from Remote

To pull latest changes from GitHub:
```bash
git pull origin main
```

## Best Practices

1. **Commit frequently**: Push changes regularly, not just at the end of the day
2. **Use descriptive messages**: Write clear commit messages
3. **Review before pushing**: Check `git status` and `git diff` before committing
4. **Keep output files local**: Don't commit large CSV/JSON files unless necessary

