# ZTA Guard visual dashboard

This directory contains the static GitHub Pages front end for the synthetic contractor and delivery-partner prototype.

Preview locally from the repository root:

```bash
python3 -m http.server 4173 --directory site
```

Then open `http://localhost:4173`.

The page has no runtime dependencies. It contains the verified sample results and can visualize a JSON report produced by either `zta partner evaluate --output json` or `zta partner audit --output json`. Uploaded files are parsed locally in the browser.
