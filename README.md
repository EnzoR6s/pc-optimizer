# PC Optimizer

Dark neon Windows optimizer app (network, cleanup, GPU presets, tools).

## Install
1. Download this repo as a ZIP (green **Code** button > **Download ZIP**) and unzip it.
2. Double-click **Install PC Optimizer.bat** and click **Yes** on the admin prompt.

## Auto-updates
Every copy checks this repo when it opens and installs new versions by itself
(turn it off in Settings). The app checks this repo for a newer `version.json`. Every file is verified against
its SHA-256 hash in `version.json` before anything is installed.

To publish a new version: replace the files, bump `version` in `version.json`,
then run `Make-Version.ps1` to refresh the hashes.
