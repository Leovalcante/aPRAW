import asyncio
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Callable, Any, Awaitable, Optional

from multidict import CIMultiDictProxy

from .const import BASE_URL
from .models import User


class RequestHandler:

    def __init__(self, user: User):
        self.user = user
        self.queue = []

    async def get_request_headers(self) -> Dict:
        if self.user.token_expires <= datetime.now():
            url = "https://www.reddit.com/api/v1/access_token"
            session = await self.user.auth_session()

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.user.user_agent
            }

            resp = await session.post(url, data=self.user.password_grant, headers=headers)

            async with resp:
                if resp.status == 200:
                    response_data = await resp.json()
                    # Check if response does not contains any error
                    if response_data.get("error") is not None:
                        raise Exception("Invalid user data.")

                    self.user.access_data = response_data
                    self.user.token_expires = datetime.now(
                    ) + timedelta(seconds=self.user.access_data.get("expires_in"))
                else:
                    raise Exception("Invalid user data.")

        return {
            "Authorization": f"{self.user.access_data.get('token_type')} {self.user.access_data.get('access_token')}",
            "User-Agent": self.user.user_agent
        }

    def update(self, data: CIMultiDictProxy):
        if "x-ratelimit-remaining" in data:
            self.user.ratelimit_remaining = int(float(data["x-ratelimit-remaining"]))
        if "x-ratelimit-used" in data:
            self.user.ratelimit_used = int(data["x-ratelimit-used"])
        if "x-ratelimit-reset" in data:
            self.user.ratelimit_reset = datetime.now() + timedelta(seconds=int(data["x-ratelimit-reset"]))

    async def close(self):
        await self.user.close()

    class Decorators:
        @classmethod
        def check_ratelimit(
                cls, func: Callable[[Any, Any], Awaitable[Any]]) -> Callable[[Any, Any], Awaitable[Any]]:
            @wraps(func)
            async def execute_request(self, *args, **kwargs) -> Any:
                id_ = datetime.now().strftime('%Y%m%d%H%M%S')
                self.queue.append(id_)

                if self.user.ratelimit_remaining < 1:
                    execution_time = self.user.ratelimit_reset + timedelta(seconds=len(self.queue))
                    wait_time = (execution_time - datetime.now()).total_seconds()
                    await asyncio.sleep(wait_time)

                result = await func(self, *args, **kwargs)
                self.queue.remove(id_)
                return result

            return execute_request

    @Decorators.check_ratelimit
    async def get(self, endpoint: Optional[str] = "", url: Optional[str] = "", **kwargs) -> Any:
        if endpoint:
            url = BASE_URL.format(endpoint)
        elif not url:
            raise ValueError("One of endpoint or url must be specified.")

        return await self.request(method="get", url=url, **kwargs)

    @Decorators.check_ratelimit
    async def delete(self, endpoint: str, **kwargs) -> Any:
        url = BASE_URL.format(endpoint)
        return await self.request(method="delete", url=url, **kwargs)

    @Decorators.check_ratelimit
    async def put(self, endpoint: str, data: Dict = None, **kwargs) -> Any:
        url = BASE_URL.format(endpoint)
        return await self.request(method="put", url=url, data=data, **kwargs)

    @Decorators.check_ratelimit
    async def post(self, endpoint: str = "", url: str = "", data: Dict = None, **kwargs) -> Any:
        if endpoint:
            url = BASE_URL.format(endpoint)
        elif not url:
            raise ValueError("One of endpoint or url must be specified.")

        return await self.request(method="post", url=url, data=data, **kwargs)

    @Decorators.check_ratelimit
    async def request(self, method: str, url: str, data: Dict = None, **kwargs) -> Any:
        # Build query arguments
        kwargs = {"raw_json": 1, "api_type": "json", **kwargs}
        params = [f"{k}={kwargs[k]}" for k in kwargs]

        # Update url
        url += f"?{'&'.join(params)}"

        # Get authorization header
        headers = await self.get_request_headers()

        # Get session
        session = await self.user.client_session()

        # Retrieve request function according to desire method
        req = getattr(session, method)

        # Fire the request and return data
        resp = req(url, data=data, headers=headers)
        async with resp:
            self.update(resp.headers)
            return await resp.json()
