from __future__ import annotations

import asyncio

import httpx

from sentinel.config import Settings


COMMAND = {
    "name": "sentinel",
    "description": "Run a fixed SENTINEL security macro.",
    "options": [
        {
            "name": "query",
            "description": "Security question, mapped to a fixed macro view.",
            "type": 3,
            "required": True,
        }
    ],
}


async def main() -> None:
    settings = Settings.from_env()
    if not settings.discord_application_id or not settings.discord_bot_token:
        raise SystemExit("DISCORD_APPLICATION_ID and DISCORD_BOT_TOKEN are required")
    if settings.discord_guild_id:
        path = f"/applications/{settings.discord_application_id}/guilds/{settings.discord_guild_id}/commands"
    else:
        path = f"/applications/{settings.discord_application_id}/commands"
    async with httpx.AsyncClient(
        base_url="https://discord.com/api/v10",
        headers={"Authorization": f"Bot {settings.discord_bot_token}"},
        timeout=20,
    ) as client:
        response = await client.post(path, json=COMMAND)
        response.raise_for_status()
        payload = response.json()
    print(f"registered /sentinel command id={payload.get('id')}")


if __name__ == "__main__":
    asyncio.run(main())
