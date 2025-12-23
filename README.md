# Secret Image Message Bot

Telegram bot that ties hidden messages to an image's perceptual hash. The same image is recognized even if it is renamed or re-uploaded, and the associated secret is stored encrypted in MongoDB.

## How it works
- Compute a pHash (`imagehash.phash`) of any received photo; this depends on visual content, not filename or metadata.
- Look up `image_hash` in MongoDB:
  - If found → decrypt and return the saved secret.
  - If new → prompt the user for the secret, ask for an optional password, then encrypt and store `{image_hash, message, image, owner_id, password_hash, created_at}` where `image` is the raw image bytes.

## Setup
1) Install Python 3.10+ and MongoDB.
2) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3) Create a `.env` file:
   ```
   BOT_TOKEN=your_telegram_bot_token
   MONGODB_URI=mongodb://localhost:27017
   DB_NAME=secret_image_bot
   COLLECTION_NAME=images
   SECRET_KEY=your_base64_fernet_key
   ```
   - Generate `SECRET_KEY`: `python - <<'PY'\nfrom cryptography.fernet import Fernet\nprint(Fernet.generate_key().decode())\nPY`
4) Run the bot:
   ```bash
   python main.py
   ```

## Commands & flow
- `/start` — intro message.
- Send an image:
  - New image → bot asks for the secret text, then an optional password, and stores the encrypted text plus image bytes.
  - Known image → bot replies with the decrypted secret. If a password was set, the user must provide it first.
  - If you are the owner of the image (same Telegram user who stored it), you can update the secret and password by sending a new image and then replying with the new secret.

## Notes and limitations
- pHash survives renaming and minor recompression; heavy edits (crop/resize/filters) will change the hash.
- Screenshots can alter the hash; to handle near-matches later, add Hamming-distance tolerance.
- Store `SECRET_KEY` securely (env/secret manager in production).
- Each user session currently holds only one pending hash at a time (per Telegram user_data).

