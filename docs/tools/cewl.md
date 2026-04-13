# CeWL Wordlist Generator

**Module ID:** `cewl` | **Category:** Recon | **Binary:** `cewl`
**Source:** `src/tools/cewl.rs`

## Overview

CeWL (Custom Word List Generator) is a tool that spiders a target website and extracts unique words to build a custom wordlist. ScorchKit wraps CeWL to generate target-specific wordlists from website content. These wordlists contain organization-specific terminology, product names, and jargon that are far more likely to succeed in password attacks or directory brute-forcing than generic wordlists.

## Installation

```bash
# Debian / Ubuntu
sudo apt install cewl

# Ruby gem
gem install cewl

# macOS
brew install cewl

# From source
git clone https://github.com/digininja/CeWL.git
cd CeWL
bundle install
```

## How ScorchKit Uses It

**Command:** `cewl <target> -d 2 -m 5 --with-numbers`
**Output format:** Plain text (one word per line)
**Timeout:** 120s (2 minutes)

Key flags:
- `-d 2` -- spider depth of 2 levels
- `-m 5` -- minimum word length of 5 characters
- `--with-numbers` -- include words that contain numbers

## What Gets Parsed

The output is simple: one word per line. The parser collects all non-empty lines as unique words. A sample of the first 20 words is included as evidence in the finding.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| {count} Words Extracted from Target | Info | At least one word extracted |

The finding includes:
- **Description:** Notes that extracted words can be used for targeted password attacks
- **Evidence:** Sample of the first 20 extracted words

No findings are produced if the target yields no words.

## Configuration

```toml
[tools]
cewl = "/custom/path/to/cewl"
```

## Standalone Usage

```bash
# Basic wordlist generation
cewl https://example.com -d 2 -m 5 --with-numbers

# Save to file
cewl https://example.com -w wordlist.txt

# Include email addresses
cewl https://example.com -e --email_file emails.txt

# Deeper spider with longer words
cewl https://example.com -d 5 -m 8

# Include metadata from documents
cewl https://example.com -d 2 -m 5 --meta

# Authentication
cewl https://example.com --auth_type basic --auth_user admin --auth_pass password

# Custom User-Agent
cewl https://example.com -u "Mozilla/5.0 (compatible; ScorchKit)"

# Output with word count
cewl https://example.com -c
```
