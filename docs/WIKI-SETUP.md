# Wiki Setup Instructions

Hướng dẫn tạo GitHub wiki pages từ documentation files đã tạo.

## 📚 Wiki Pages Created

Các wiki pages đã được tạo trong `docs/wiki/`:

1. **Architecture.md** - System architecture và technical design
2. **Deployment-Guide.md** - Complete production deployment guide  
3. **Certificate-Management.md** - mTLS certificate management
4. **Agent-Management.md** - Windows agent deployment và management
5. **Troubleshooting.md** - Comprehensive troubleshooting guide

## 🚀 GitHub Wiki Setup

### Method 1: Manual Upload (Recommended)

1. **Enable Wiki trên GitHub repository:**
   ```
   https://github.com/vdnamliv/Workstation-Audit/settings
   -> Features section
   -> Check "Wikis"
   ```

2. **Access Wiki section:**
   ```
   https://github.com/vdnamliv/Workstation-Audit/wiki
   ```

3. **Create pages manually:**
   - Click "Create the first page" or "New Page"
   - Copy content từ `docs/wiki/*.md` files
   - Paste vào wiki editor
   - Save với tên file tương ứng (without .md extension)

### Method 2: Git Clone Wiki Repository

```bash
# Clone wiki repository
git clone https://github.com/vdnamliv/Workstation-Audit.wiki.git

# Copy wiki files
cp docs/wiki/*.md Workstation-Audit.wiki/

# Commit và push
cd Workstation-Audit.wiki
git add .
git commit -m "Add comprehensive documentation wiki pages"
git push origin master
```

### Method 3: Automated Script

```powershell
# upload-wiki.ps1
param(
    [string]$WikiRepoUrl = "https://github.com/vdnamliv/Workstation-Audit.wiki.git",
    [string]$WikiDir = "wiki-temp"
)

try {
    # Clone wiki repository
    if (Test-Path $WikiDir) {
        Remove-Item -Recurse -Force $WikiDir
    }
    
    git clone $WikiRepoUrl $WikiDir
    
    # Copy wiki files
    $wikiFiles = Get-ChildItem "docs\wiki\*.md"
    foreach ($file in $wikiFiles) {
        $destName = $file.BaseName + ".md"
        Copy-Item $file.FullName "$WikiDir\$destName" -Force
        Write-Host "✅ Copied $($file.Name) -> $destName"
    }
    
    # Create Home page
    @"
# VT-Audit Documentation Wiki

Welcome to VT-Audit comprehensive documentation wiki.

## 📖 Documentation Pages

### Architecture & Design
- **[Architecture](Architecture)** - System architecture và technical design
- **[API Reference](API-Reference)** - Complete API documentation

### Deployment & Setup  
- **[Deployment Guide](Deployment-Guide)** - Production deployment guide
- **[Agent Management](Agent-Management)** - Windows agent deployment
- **[Certificate Management](Certificate-Management)** - mTLS certificates

### Operations & Maintenance
- **[Policy Management](Policy-Management)** - Compliance rules management
- **[Troubleshooting](Troubleshooting)** - Issues và solutions
- **[Maintenance Tasks](Maintenance-Tasks)** - Regular operations

### Quick Start
- **[Production Setup](Production-Setup)** - Complete production workflow
- **[Development Environment](Development-Environment)** - Local testing

## 🚀 Quick Links

- [GitHub Repository](https://github.com/vdnamliv/Workstation-Audit)
- [Latest Releases](https://github.com/vdnamliv/Workstation-Audit/releases)
- [Issue Tracker](https://github.com/vdnamliv/Workstation-Audit/issues)

## 💡 Getting Started

1. Start với [Deployment Guide](Deployment-Guide) cho production setup
2. Check [Agent Management](Agent-Management) cho Windows deployment
3. Use [Troubleshooting](Troubleshooting) khi gặp issues
"@ | Out-File "$WikiDir\Home.md" -Encoding UTF8
    
    # Commit và push changes
    Push-Location $WikiDir
    git add .
    git commit -m "Add VT-Audit comprehensive documentation wiki

- System architecture và technical design
- Complete deployment guides 
- Certificate management procedures
- Agent deployment và management
- Comprehensive troubleshooting guide
- API reference documentation"
    
    git push origin master
    Pop-Location
    
    Write-Host "✅ Wiki pages uploaded successfully!"
    Write-Host "🌐 Access wiki at: https://github.com/vdnamliv/Workstation-Audit/wiki"
    
    # Cleanup
    Remove-Item -Recurse -Force $WikiDir
    
} catch {
    Write-Error "❌ Failed to upload wiki: $_"
}
```

## 📋 Wiki Page Structure

### Recommended Wiki Organization

```
Home.md                     # Wiki homepage với navigation
├── Architecture.md         # System design
├── Deployment-Guide.md     # Production deployment 
├── Agent-Management.md     # Windows agents
├── Certificate-Management.md # mTLS certificates
├── Troubleshooting.md      # Issues và fixes
├── API-Reference.md        # API documentation (to be created)
├── Policy-Management.md    # Compliance policies (to be created)
├── Production-Setup.md     # Complete workflow (to be created)
├── Development-Environment.md # Local setup (to be created)
└── Maintenance-Tasks.md    # Operations (to be created)
```

### Wiki Navigation Setup

Add navigation sidebar trong wiki settings:

```markdown
**📖 Documentation**
* [Home](Home)
* [Architecture](Architecture)

**🚀 Deployment**  
* [Deployment Guide](Deployment-Guide)
* [Agent Management](Agent-Management)
* [Certificate Management](Certificate-Management)

**🔧 Operations**
* [Policy Management](Policy-Management)
* [Troubleshooting](Troubleshooting)
* [Maintenance Tasks](Maintenance-Tasks)

**🔗 Quick Links**
* [GitHub Repo](https://github.com/vdnamliv/Workstation-Audit)
* [Issues](https://github.com/vdnamliv/Workstation-Audit/issues)
```

## ✅ Validation Checklist

After uploading wiki pages:

- [ ] All wiki pages accessible via URLs
- [ ] Internal links between pages work correctly
- [ ] Code blocks render properly với syntax highlighting
- [ ] Images và diagrams display correctly
- [ ] Navigation sidebar configured
- [ ] Home page provides good overview
- [ ] Links to GitHub repository work
- [ ] Search functionality works for wiki content

## 📝 Additional Pages to Create

Based on current documentation, consider adding:

1. **API-Reference.md** - Complete API endpoints documentation
2. **Policy-Management.md** - Compliance policy creation và management
3. **Production-Setup.md** - Step-by-step production deployment workflow
4. **Development-Environment.md** - Local development setup
5. **Maintenance-Tasks.md** - Regular operational procedures
6. **FAQ.md** - Frequently asked questions
7. **Changelog.md** - Version history và updates

## 🎯 Next Steps

1. **Upload wiki pages** using one of the methods above
2. **Test all links** trong wiki để ensure proper navigation
3. **Add missing pages** như API Reference và Policy Management
4. **Update README.md links** to point to wiki pages  
5. **Configure wiki sidebar** for better navigation
6. **Set up wiki notifications** cho updates