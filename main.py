import logging
import os
from datetime import datetime
from io import BytesIO
from typing import Optional

import imagehash
import bcrypt
from bson.binary import Binary
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from PIL import Image
from pymongo import MongoClient
from pymongo.collection import Collection
from telegram import Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


load_dotenv()

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


BOT_TOKEN = get_env("BOT_TOKEN")
MONGODB_URI = get_env("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = get_env("DB_NAME", "secret_image_bot")
COLLECTION_NAME = get_env("COLLECTION_NAME", "images")
SECRET_KEY = get_env("SECRET_KEY")

cipher = Fernet(SECRET_KEY)


def encrypt(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    return cipher.decrypt(token.encode()).decode()


def compute_image_hash(image_bytes: bytes) -> str:
    """Compute a perceptual hash that survives renames and minor compression."""
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    return str(imagehash.phash(img))


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def get_collection() -> Collection:
    client = MongoClient(MONGODB_URI)
    db = client[DB_NAME]
    return db[COLLECTION_NAME]


collection = get_collection()


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🖼️ Send me an image.\n"
        "• If it's new → I'll hide a message\n"
        "• If it already exists → I'll reveal the secret 😌"
    )


async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.photo:
        return

    photo = update.message.photo[-1]
    tg_file = await photo.get_file()

    image_bytes = await tg_file.download_as_bytearray()
    image_hash = compute_image_hash(image_bytes)

    record = collection.find_one({"image_hash": image_hash})

    if record:
        context.user_data.pop("pending_new", None)
        context.user_data.pop("pending_new_password", None)
        context.user_data.pop("pending_update", None)
        context.user_data.pop("pending_update_password", None)

        # Reveal flow
        reply_lines = []
        if record.get("password_hash"):
            context.user_data["pending_reveal"] = record
            reply_lines.append("🔒 This image is protected. Send the password to reveal the message.")
        else:
            try:
                secret = decrypt(record["message"])
            except (KeyError, InvalidToken):
                await update.message.reply_text(
                    "⚠️ Found a message but failed to decrypt it. "
                    "Please verify the SECRET_KEY."
                )
                return
            reply_lines.append(f"🔓 Hidden message:\n\n{secret}")

        # Owner edit prompt
        user_id = update.message.from_user.id if update.message.from_user else None
        if user_id and record.get("owner_id") == user_id:
            context.user_data["pending_update"] = record
            reply_lines.append("✏️ You own this image. Send a new secret to update it, or /skip.")

        if reply_lines:
            await update.message.reply_text("\n".join(reply_lines))
    else:
        context.user_data["pending_new"] = {
            "hash": image_hash,
            "image": bytes(image_bytes),
            "owner_id": update.message.from_user.id if update.message.from_user else None,
        }
        await update.message.reply_text(
            "📝 What message do you want to hide in this image?\n"
            "You can /cancel anytime."
        )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    text = update.message.text

    # Cancel command
    if text.strip().lower() == "/cancel":
        context.user_data.clear()
        await update.message.reply_text("❌ Cancelled.")
        return

    # Reveal with password
    if "pending_reveal" in context.user_data:
        record = context.user_data.pop("pending_reveal")
        password_hash = record.get("password_hash")
        if password_hash and not verify_password(text, password_hash):
            await update.message.reply_text("❌ Wrong password. Try again or /cancel.")
            context.user_data["pending_reveal"] = record
            return
        try:
            secret = decrypt(record["message"])
        except (KeyError, InvalidToken):
            await update.message.reply_text(
                "⚠️ Found a message but failed to decrypt it. Please verify the SECRET_KEY."
            )
            return
        await update.message.reply_text(f"🔓 Hidden message:\n\n{secret}")
        return

    # Update flow (owner)
    if "pending_update_password" in context.user_data:
        payload = context.user_data.pop("pending_update_password")
        new_password_raw = text.strip()
        password_hash = (
            hash_password(new_password_raw) if new_password_raw and new_password_raw != "-" else None
        )
        collection.update_one(
            {"_id": payload["record_id"]},
            {
                "$set": {
                    "message": payload["encrypted"],
                    "password_hash": password_hash,
                    "updated_at": datetime.utcnow(),
                }
            },
        )
        await update.message.reply_text("✅ Secret updated for this image.")
        return

    if "pending_update" in context.user_data:
        record = context.user_data["pending_update"]
        user_id = update.message.from_user.id if update.message.from_user else None
        if user_id and record.get("owner_id") == user_id:
            new_secret = text
            encrypted = encrypt(new_secret)
            context.user_data["pending_update_password"] = {
                "record_id": record["_id"],
                "encrypted": encrypted,
            }
            await update.message.reply_text(
                "🔐 Set a password for this image (send '-' for none):"
            )
        else:
            await update.message.reply_text("⚠️ Only the owner can update this secret.")
        return

    # New image flow
    if "pending_new_password" in context.user_data:
        payload = context.user_data.pop("pending_new_password")
        password_raw = text.strip()
        password_hash = hash_password(password_raw) if password_raw and password_raw != "-" else None
        collection.insert_one(
            {
                "image_hash": payload["hash"],
                "message": payload["encrypted"],
                "image": Binary(payload["image"]),
                "owner_id": payload["owner_id"],
                "password_hash": password_hash,
                "created_at": datetime.utcnow(),
            }
        )
        await update.message.reply_text(
            "✅ Secret saved!\nSend this image again anytime to reveal it."
        )
        return

    if "pending_new" in context.user_data:
        pending = context.user_data.pop("pending_new")
        secret = text
        encrypted = encrypt(secret)
        context.user_data["pending_new_password"] = {
            "hash": pending["hash"],
            "image": pending["image"],
            "owner_id": pending["owner_id"],
            "encrypted": encrypted,
        }
        await update.message.reply_text(
            "🔐 Set a password for this image (send '-' for none):"
        )
        return

    # Otherwise ignore text
    return


def build_app() -> Application:
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .rate_limiter(None)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.PHOTO, handle_image))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    return app


def main() -> None:
    app = build_app()
    logger.info("Bot is starting...")
    app.run_polling()


if __name__ == "__main__":
    main()

