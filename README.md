# Stripe Auth Checker

A professional Stripe authentication and card validation tool

## Key Features

- Stripe payment method creation and WooCommerce nonce confirmation logic
- Background service thread launched before card input processing
- Multi-threaded card checking via `ThreadPoolExecutor`
- Dependencies isolated in `requirements.txt`

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Execute the main script:

```bash
python auth.py
```

Enter card data one line at a time. End input with `CTRL+D` on Linux or `CTRL+Z` then `Enter` on Windows.

## Files

- `au.py` — Primary Stripe authentication checker
- `requirements.txt` — Runtime dependencies
- `README.md` — GitHub repository documentation
