import asyncio
from backend.utils.events_repo import get_latest_events


async def main():
    events = await get_latest_events(5)
    print(f"got {len(events)} events\n")

    for e in events:
        print(
            f"{e.get('ts')} | {e.get('event_type')} | "
            f"pod={e.get('pod')} | comm={e.get('comm')} | pid={e.get('pid')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
