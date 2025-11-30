# Valkyrie Dashboard - Quick Start Guide

## 🚀 Starting the Dashboard

```bash
# From the project root
python gui/backend/app.py
```

**URL**: http://127.0.0.1:5000

---

## ✨ Key Features

### 1. **Real-Time Monitoring**
- Dashboard auto-updates when new files are scanned
- No need to refresh manually
- Live indicator shows connection status

### 2. **Search & Filter**

**Search Box**:
- Search by file name
- Search by SHA256 hash prefix
- Search by YARA rule name
- Instant results (200ms debounce)

**Verdict Filter**:
- All (default)
- Quarantine (threats detected)
- Review (suspicious)
- Allow (clean files)

### 3. **Sorting**

Click the "Sort by" dropdown:
- **Time**: Most recent scans first
- **Name**: Alphabetical order
- **Score**: Highest risk first
- **Verdict**: By severity

### 4. **Risk Score Display**

| Score Range | Verdict | Color | Action |
|------------|---------|-------|--------|
| 80-100 | QUARANTINE | Red 🔴 | Immediate threat |
| 40-79 | REVIEW | Orange 🟡 | Manual inspection |
| 0-39 | ALLOW | Green 🟢 | Likely safe |

### 5. **Detailed Report View**

Click the **"Details"** button on any report to see:

#### File Information
- Full file name
- Complete SHA256 hash
- MIME type
- File size
- Scan timestamp

#### Risk Assessment
- Visual score gauge (circular progress)
- Verdict
- Total score (0-100)

#### Detection Factors
- ClamAV results
- YARA matches
- Heuristic analysis
- Score breakdown

#### Technical Details
- Full ClamAV output
- YARA rule hits
- Analysis execution time

---

## 📊 Dashboard Layout

```
┌─────────────────────────────────────────┐
│  🛡️ Valkyrie Dashboard                  │
│  [Refresh Button]     🔴 Live      │
├─────────────────────────────────────────┤
│  📊 Statistics Cards                     │
│  ┌──────┐ ┌────────┐ ┌────────┐ ┌────┐  │
│  │ Total│ │Quarantine│ │Review │ │Allow│  │
│  │  42  │ │    3   │ │   5   │ │ 34 │  │
│  └──────┘ └────────┘ └────────┘ └────┘  │
├─────────────────────────────────────────┤
│  🔍 Search Box                          │
│  [All] [Sort by Time ▼]                 │
├─────────────────────────────────────────┤
│  📋 Reports Table                       │
│  ┌────────┬────────┬─────┬─────┬────┐   │
│  │ SHA256 │  File  │MIME │Score│... │   │
│  │ abc123 │file.pdf│pdf  │ 85  │Det │   │
│  └────────┴────────┴─────┴─────┴────┘   │
└─────────────────────────────────────────┘
```

---

## 🎯 Common Tasks

### Find a Specific File
1. Type the file name in the search box
2. Results appear instantly
3. Click "Details" for full information

### Find Files by Hash
1. Paste the SHA256 hash (or first 12 characters)
2. Matching files will appear

### See All Threats
1. Set verdict filter to "Quarantine"
2. See only detected threats

### Sort by Risk
1. Open "Sort by" dropdown
2. Select "Score"
3. Highest threats first

### Check Recent Activity
1. Keep dashboard open
2. Watch the "Updated" timestamp
3. See new scans appear automatically

### Export Report Data
1. Click "Details" on a report
2. Or click "JSON" for raw data
3. Save or copy as needed

---

## 🔍 Understanding the Data

### Score Breakdown

**Where scores come from**:
- ClamAV detection: +100 points
- YARA critical rule: +90 points
- YARA high rule: +70 points
- YARA medium rule: +40 points
- High entropy: +30 points
- Packer detected: +25 points
- File type anomaly: +20 points

### Verdict Logic

```
Score ≥ 80  → QUARANTINE (automatic)
Score 40-79 → REVIEW (manual check)
Score < 40  → ALLOW (automatic)
```

### YARA Hits

**What they mean**:
- Each hit is a malware signature match
- More hits = higher confidence
- Check details for rule names
- Use for threat hunting

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl/Cmd + F` | Focus search box |
| `Esc` | Close modal |
| `Enter` | Apply search (if focused) |
| `F5` | Manual refresh |

---

## 🐛 Troubleshooting

### Dashboard Won't Load
```bash
# Check if port 5000 is available
netstat -an | grep 5000

# Try a different port (edit app.py)
app.run(host="127.0.0.1", port=5001)
```

### Real-Time Updates Not Working
- Check browser console for errors
- Ensure `/api/stream` endpoint is accessible
- Try refreshing the page

### No Data Showing
- Verify files are in the watch directory
- Check that reports are being generated
- Look at console logs for errors

### Modal Won't Open
- Check JavaScript is enabled
- Try a different browser
- Check browser console for errors

---

## 📱 Mobile Usage

**Responsive Design**:
- Table scrolls horizontally on small screens
- Touch-friendly buttons
- Optimized layout for mobile
- Same features as desktop

**Tips**:
- Rotate phone for wider table view
- Tap "Details" for full information
- Pinch to zoom if needed

---

## 🎨 Customization

### Change Theme (Future Feature)
Currently using dark theme. Light theme coming soon!

### Adjust Page Size
Edit in `gui/backend/app.py`:
```python
REPORTS_PER_PAGE = 15  # Change this number
```

### Update Colors
Edit CSS variables in `app.py`:
```css
--accent: #3bd5c7;        /* Main color */
--accent-2: #ffb454;      /* Secondary */
```

---

## 📞 Support

**Issues?** Check:
1. Browser console for errors
2. Flask server logs
3. Report files exist in `reports/`
4. File permissions

**Need Help?**
- See `DASHBOARD_ENHANCEMENTS.md` for technical details
- Check `README.md` for general info
- Review `ROADMAP.md` for planned features

---

## 🚀 Pro Tips

1. **Keep it open**: Leave dashboard open during scanning sessions
2. **Sort by score**: Find threats quickly
3. **Use search**: Find specific files fast
4. **Check details**: Understand why files were flagged
5. **Monitor stats**: Watch for trends in detection rates
6. **Export JSON**: For external analysis tools

---

**Happy Scanning! 🛡️**
