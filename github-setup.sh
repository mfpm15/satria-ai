#!/bin/bash
# GitHub Setup Script for SATRIA AI

echo "🚀 SATRIA AI GitHub Setup Script"
echo "================================"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

echo "📋 Current git status:"
git status --short

echo ""
echo "📝 Please follow these steps:"
echo ""
echo "1. Create a new repository on GitHub.com:"
echo "   - Go to https://github.com/new"
echo "   - Repository name: satria-ai"
echo "   - Description: SATRIA AI - Smart Autonomous Threat Response & Intelligence Agent"
echo "   - Make it Public or Private (your choice)"
echo "   - DO NOT initialize with README (we already have code)"
echo ""
echo "2. After creating the repository, copy the repository URL"
echo "   (should look like: https://github.com/yourusername/satria-ai.git)"
echo ""
echo "3. Run this command to add remote origin:"
echo "   git remote add origin https://github.com/yourusername/satria-ai.git"
echo ""
echo "4. Push to GitHub:"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "🎯 After setup, your repository will be available at:"
echo "   https://github.com/yourusername/satria-ai"
echo ""
echo "✅ Repository includes:"
echo "   - Complete Phase 1 & 2 source code"
echo "   - Comprehensive documentation"
echo "   - CI/CD pipelines"
echo "   - Unit tests"
echo "   - Docker configuration"
echo "   - Security configurations"

echo ""
echo "📊 Current repository stats:"
echo "Files: $(find . -name "*.py" | wc -l) Python files"
echo "Lines of code: $(find . -name "*.py" -exec cat {} \; | wc -l) lines"
echo "Documentation: $(find docs -name "*.md" | wc -l) markdown files"
echo "Tests: $(find tests -name "*.py" | wc -l) test files"