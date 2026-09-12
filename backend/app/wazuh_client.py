import os

import httpx
from dotenv import load_dotenv


load_dotenv()


class WazuhClient:
    def __init__(self):
        self.base_url = os.getenv(
            "WAZUH_API_URL",
            "https://127.0.0.1:55000",
        ).rstrip("/")

        self.username = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASSWORD")
        self.verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

        if not self.username or not self.password:
            raise RuntimeError(
                "WAZUH_API_USER and WAZUH_API_PASSWORD must be configured"
            )

    async def authenticate(self) -> str:
        url = f"{self.base_url}/security/user/authenticate"

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=10.0,
        ) as client:
            response = await client.post(
                url,
                auth=(self.username, self.password),
                params={"raw": "true"},
            )

        response.raise_for_status()
        return response.text.strip()

    async def get_api_info(self) -> dict:
        token = await self.authenticate()

        url = f"{self.base_url}/"

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=10.0,
        ) as client:
            response = await client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
            )

        response.raise_for_status()
        return response.json()

    async def get_manager_info(self) -> dict:
        token = await self.authenticate()

        url = f"{self.base_url}/manager/info"

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=10.0,
        ) as client:
            response = await client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
            )

        response.raise_for_status()
        return response.json()