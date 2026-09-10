from __future__ import annotations

import asyncio
from collections.abc import Awaitable


async def cancel_and_join(*tasks: asyncio.Task) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_pair(first: Awaitable, second: Awaitable, *, half_close: bool = False) -> None:
    tasks = [asyncio.create_task(first), asyncio.create_task(second)]
    try:
        done, _ = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_EXCEPTION if half_close else asyncio.FIRST_COMPLETED,
        )
        for task in done:
            task.result()
    finally:
        await cancel_and_join(*tasks)


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except (OSError, asyncio.TimeoutError):
        pass
