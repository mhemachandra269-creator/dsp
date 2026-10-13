# Sentinel — Digital Risk Protection Platform

A responsive front-end cybersecurity project using HTML5, CSS3, Vanilla JavaScript, LocalStorage, and Chart.js.

## Run locally
1. Extract the ZIP file.
2. Open the `digital-risk-protection-platform` folder in Visual Studio Code.
3. Open `index.html` in a browser, or install the VS Code **Live Server** extension and choose **Open with Live Server**.
4. Internet access is needed to load Google Fonts and Chart.js from their CDNs. Most non-chart features work without those assets.

## Included modules
- Overview dashboard and charts
- URL scanner using transparent educational heuristics
- Sample threat intelligence center
- Local risk self-assessment
- Security alerts with read/dismiss controls
- Scan history and CSV export
- Security recommendations checklist
- Settings, profile display preferences, and theme toggle

## Important limitations
This is a demonstration project. It does not perform live malware analysis, check real breach databases, verify phishing reports, or provide secure user authentication. Results are illustrative and must not be used to decide whether a real website is safe. No submitted URL is automatically opened by the scanner. Do not enter real passwords or sensitive information.

## Project structure
- `index.html` — application layout
- `css/style.css` — responsive styling and theme
- `js/app.js` — app navigation, demo data, interactions, charts, storage, scanner, alerts, and reports
- `assets/images/` — reserved for optional images
