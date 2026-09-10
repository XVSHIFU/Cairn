# Cairn research workbench prototype

A local-only, Chinese-first interactive prototype using the existing vendored Alpine.js. No package installation or bundler is required. The copied Alpine vendor is byte-identical to Cairn's existing static asset.

## Run on Kali

    cd /home/kali/work/Cairn
    python3 -m http.server 8011 --bind 192.168.61.129 --directory prototypes/research-workbench

Open http://192.168.61.129:8011/ . The server serves only this prototype directory, not repository files or the production database. Use another explicit port if 8011 is already occupied.

The delivery process is detached, with PID recorded in /tmp/cairn-workbench-preview.pid and output at /tmp/cairn-workbench-preview.log. It is a temporary preview, not a startup service.

## Data

All three example projects and their evidence are fictional. Actions affect only in-memory page state; reload or Reset restores fixtures. There are no API calls, model calls, external fonts, analytics, browser credential storage or real target requests.

Do not enter credentials into this prototype. Target/environment inputs are presentation-only and are never fetched.

## Check

    node --check prototypes/research-workbench/app.js
    cairn/.venv/bin/python prototypes/qa/workbench_browser.py

Browser checks run Chromium on Kali and write screenshots, report and result JSON to /tmp/cairn-workbench-qa. They exercise the isolated prototype, not Cairn's production services.

Product authority: ../../docs/development-charter.md
