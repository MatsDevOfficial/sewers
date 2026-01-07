import os
import requests
from typing import Optional, Dict, Any

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")


def format_hours(hours: float) -> str:
    if not hours or hours <= 0:
        return "0h 0m"

    h = int(hours)
    m = round((hours - h) * 60)

    return f"{h}h {m}m"


def send_dm(user_slack_id: str, blocks: list) -> bool:
    if not SLACK_BOT_TOKEN:
        print("Error: SLACK_BOT_TOKEN not set")
        return False

    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json",
    }

    payload = {"channel": user_slack_id, "blocks": blocks}

    try:
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()

        if not data.get("ok"):
            print(f"Slack API error: {data.get('error')}")
            return False

        return True
    except Exception as e:
        print(f"Failed to send Slack DM: {e}")
        return False


def send_channel_message(channel: str, blocks: list) -> bool:

    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json",
    }

    payload = {"channel": channel, "blocks": blocks}

    try:
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()

        if not data.get("ok"):
            print(f"Slack API error: {data.get('error')}")
            return False

        return True
    except Exception as e:
        print(f"Failed to send Slack channel message: {e}")
        return False


def project_shipped(project):
    blocks = [
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🚢 *Your project has been approved and therefore shipped!*",
                }
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{project['title']}* by _user_"},
        },
        {
            "type": "section",
            "text": {
                "type": "plain_text",
                "text": f"{project['description']}",
                "emoji": True,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"<{project['demo_link']}|Demo> | {format_hours(project['hours'])} | <{project['github_link']}|GitHub>",
                }
            ],
        },
    ]

    send_dm(project["slack_id"], blocks)

    blocks = [
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "🚢 *A project has shipped!*"}],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{project['title']}*"},
        },
        {
            "type": "section",
            "text": {
                "type": "plain_text",
                "text": f"{project['description']}",
                "emoji": True,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"<{project['demo_link']}|Demo> | {format_hours(project['hours'])} | <{project['github_link']}|GitHub>",
                }
            ],
        },
    ]

    send_channel_message("C09U5BFU3GA", blocks)


def project_rejected(project, reason):
    blocks = [
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Your project has been rejected during the review stage.",
                }
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{project['title']}* has been rejected with the reason: *{reason}*.",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "_Please fix these issues and then resubmit!_",
            },
        },
    ]

    send_dm(project["slack_id"], blocks)


def project_created(project):
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🆕 New Project Submitted"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Project:* {project['title']}\n*Owner:* <@{project['slack_id']}>",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"> {project['description']}"},
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review Project"},
                    "url": "https://sewers.hackclub.com/reviewer",
                }
            ],
        },
    ]

    send_channel_message("C09U5BFU3GA", blocks)
