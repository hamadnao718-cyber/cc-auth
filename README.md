# Stripe Auth Checker
<a href="https://ibb.co/HDn2B5jy"><img src="https://i.ibb.co/8D6BN1Hw/Resized-Image-2026-04-25-10-09-18-2272.jpg" alt="Resized-Image-2026-04-25-10-09-18-2272" border="0"></a>
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

- `auth.py` — Primary Stripe authentication checker
- `requirements.txt` — Runtime dependencies
- `README.md` — GitHub repository documentation
