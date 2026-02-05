# 📝 Darkelf Scribe — Interactive Prompt Guide

This guide explains **each prompt shown during the Darkelf Scribe workflow**, what it does, and what happens behind the scenes.

Darkelf Scribe uses **local AI only** via Ollama.  
No data leaves your system.

---

## 1. Paste investigator notes or working summary

You will be prompted to paste your investigation notes.

### What to paste
- OSINT findings
- timelines
- logs
- extracted indicators
- working summaries or hypotheses

### How to finish input
- **Linux / macOS:** `CTRL+D`
- **Windows:** `CTRL+Z` then `Enter`

Nothing is saved or processed yet.

---

## 2. Redaction Preview (automatic)

After input, Darkelf displays a **Redaction Preview**.

### What is redacted
- Email addresses → `[REDACTED_EMAIL]`
- IPv4 addresses → `[REDACTED_IP]`

### Important notes
- This is a preview only
- Your original notes are not modified
- The **redacted version** is what the AI uses

---

## 3. Proceed with these notes?

```
Proceed with these notes? (Y/n)
```

### Yes
- Continues to AI drafting

### No
- Cancels Scribe
- No AI run
- No files created

This is the **final approval step** before AI execution.

---

## 4. Model selection

```
Model [auto / mistral / mixtral]
```

### auto (default — recommended)
- Automatically selects a model based on system RAM
- Uses:
  - `mixtral` if sufficient memory is available
  - `mistral` otherwise

### mistral
- Faster
- Lower memory usage
- Best for short drafts and quick summaries

### mixtral
- Larger model
- Better structured writing
- Best for long reports or TraceLabs-style submissions

---

## 5. Run AI in background (non-blocking)?

```
Run AI in background (non-blocking)? (y/N)
```

### No (default)
- Runs immediately
- Terminal waits for output

### Yes
- AI task is queued
- You may continue using Darkelf
- Output appears when ready

Both modes are fully local.

---

## 6. Draft Submission

After processing, Darkelf displays the **Draft Submission**.

### What the AI used
- Redacted investigator notes
- Extracted indicators:
  - emails
  - usernames
  - domains
  - IP addresses
  - hashes
  - phone numbers

### AI rules
- Uses only provided data
- No speculation or invented facts
- Neutral, professional tone
- Draft only — human review required

---

## 7. Export this draft?

```
Export this draft? (y/N)
```

### No
- Draft remains in memory only
- Nothing saved to disk

### Yes
- Choose an export format

---

## 8. Export format

```
Export format [json / md]
```

### json (default)
Creates a structured file containing:
- summary
- evidence list
- sources list
- raw AI output

Schema:
```
darkelf.scribe.v1
```

### md
- Plain Markdown
- Easy to edit, review, or submit

> PDF export is **not supported** in the current version.

---
## 📂 Output locations (corrected)

All Darkelf Scribe exports are saved inside your **Documents** folder, under a dedicated **Darkelf** directory.

**Windows:** `C:\Users\<username>\Documents\Darkelf\`  
**macOS / Linux:** `~/Documents/Darkelf/`

Darkelf creates this directory automatically if it does not exist.

After saving, Darkelf automatically opens the **local Scribe viewer**.

---

## Kyber Vault (separate from Scribe)

Scribe exports are **not automatically stored** in Kyber Vault.

Kyber Vault is used for:
- encrypted storage
- sensitive investigation artifacts
- long-term case material

Typical layout:
```
darkelf/
└── vault/
    ├── *.vault
    ├── kyber_private.key
```

⚠️ If the vault key is lost, encrypted data cannot be recovered.

---

## Mental model

**Scribe drafts reports.  
Exports go to `Darkelf/`.  
Kyber Vault is encrypted storage.  
Everything stays local.**
