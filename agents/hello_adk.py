"""
ADK Hello World Agent — Day 0 verification check.

Runs a simple Google ADK agent that answers a greeting.
Requires GOOGLE_API_KEY in .env
"""

import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

# google-adk uses GOOGLE_API_KEY from env automatically
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


def create_hello_agent() -> Agent:
    """Create a minimal ADK hello-world agent."""
    return Agent(
        name="hello_agent",
        model="gemini-2.5-flash",
        description="A simple hello-world agent for Day 0 verification.",
        instruction="You are a helpful assistant. Answer concisely.",
    )


async def _run_hello_world_async():
    """Run the hello-world agent and print the response (async — matches current ADK API)."""
    print("=== ADK Hello World Agent ===")

    agent = create_hello_agent()
    session_service = InMemorySessionService()

    runner = Runner(
        agent=agent,
        app_name="hello_world",
        session_service=session_service,
    )

    session = await session_service.create_session(
        app_name="hello_world",
        user_id="day0_user",
    )

    message = types.Content(
        role="user",
        parts=[types.Part(text="Hello! What can you help me with today?")],
    )

    print("Sending message to ADK agent...")
    response_text = ""
    async for event in runner.run_async(
        user_id="day0_user",
        session_id=session.id,
        new_message=message,
    ):
        if event.is_final_response():
            response_text = event.content.parts[0].text
            break

    print(f"Agent response: {response_text}")
    print("✅ ADK hello world: PASSED")
    return response_text


def run_hello_world():
    """Sync entry point — wraps the async ADK call for callers (e.g. verify_day0.py) that expect a plain function call."""
    return asyncio.run(_run_hello_world_async())


if __name__ == "__main__":
    run_hello_world()
