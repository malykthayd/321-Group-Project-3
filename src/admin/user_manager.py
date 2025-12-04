"""
Slack User ID Management and Heroku Configuration Automation

This module provides tools to:
1. Fetch Slack user IDs from channel members
2. Automatically update Heroku config vars (ALLOWED_USERS)
3. List and manage authorized users

Usage:
    # List current authorized users
    python -m src.admin.user_manager list
    
    # Fetch members from a Slack channel and show their IDs
    python -m src.admin.user_manager fetch-channel C01234ABCDE
    
    # Sync channel members to Heroku ALLOWED_USERS (adds new members)
    python -m src.admin.user_manager sync-channel C01234ABCDE --app your-heroku-app
    
    # Add specific user(s) to Heroku ALLOWED_USERS
    python -m src.admin.user_manager add-user U01234ABC U56789DEF --app your-heroku-app
    
    # Remove specific user(s) from ALLOWED_USERS  
    python -m src.admin.user_manager remove-user U01234ABC --app your-heroku-app

Environment Variables Required:
    - SLACK_BOT_TOKEN: Slack bot token with users:read and conversations:members scopes
    - HEROKU_API_KEY: Heroku API key (for config var updates)
    
Optional:
    - HEROKU_APP_NAME: Default Heroku app name (can also be passed via --app flag)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def load_env() -> None:
    """Load environment variables from .env file if present."""
    if os.environ.get("ENV_READY"):
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        pass
    else:
        env_path = Path(__file__).resolve().parents[2] / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    os.environ["ENV_READY"] = "1"


class SlackUserManager:
    """Manages Slack user ID retrieval and operations."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("SLACK_BOT_TOKEN")
        if not self.token:
            raise ValueError("SLACK_BOT_TOKEN is required")
        self.base_url = "https://slack.com/api"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_channel_members(self, channel_id: str) -> List[str]:
        """
        Get all member IDs from a Slack channel.
        
        Args:
            channel_id: Slack channel ID (e.g., C01234ABCDE)
            
        Returns:
            List of user IDs in the channel
        """
        members = []
        cursor = None
        
        while True:
            params = {"channel": channel_id, "limit": 200}
            if cursor:
                params["cursor"] = cursor
            
            response = requests.get(
                f"{self.base_url}/conversations.members",
                headers=self.headers,
                params=params
            )
            data = response.json()
            
            if not data.get("ok"):
                error = data.get("error", "Unknown error")
                raise RuntimeError(f"Failed to get channel members: {error}")
            
            members.extend(data.get("members", []))
            
            # Handle pagination
            cursor = data.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
        
        return members
    
    def get_user_info(self, user_id: str) -> Dict:
        """
        Get detailed user information from Slack.
        
        Args:
            user_id: Slack user ID
            
        Returns:
            User info dictionary with name, email, etc.
        """
        response = requests.get(
            f"{self.base_url}/users.info",
            headers=self.headers,
            params={"user": user_id}
        )
        data = response.json()
        
        if not data.get("ok"):
            error = data.get("error", "Unknown error")
            raise RuntimeError(f"Failed to get user info: {error}")
        
        return data.get("user", {})
    
    def get_user_details_batch(self, user_ids: List[str]) -> List[Dict]:
        """
        Get detailed information for multiple users.
        
        Args:
            user_ids: List of Slack user IDs
            
        Returns:
            List of user info dictionaries
        """
        users = []
        for user_id in user_ids:
            try:
                info = self.get_user_info(user_id)
                users.append({
                    "id": user_id,
                    "name": info.get("real_name") or info.get("name", "Unknown"),
                    "email": info.get("profile", {}).get("email", "N/A"),
                    "display_name": info.get("profile", {}).get("display_name", ""),
                    "is_bot": info.get("is_bot", False),
                    "is_admin": info.get("is_admin", False)
                })
            except Exception as e:
                users.append({
                    "id": user_id,
                    "name": "Unknown",
                    "email": "N/A",
                    "error": str(e)
                })
        return users
    
    def find_user_by_email(self, email: str) -> Optional[Dict]:
        """
        Find a Slack user by their email address.
        
        Args:
            email: User's email address
            
        Returns:
            User info dictionary or None if not found
        """
        response = requests.get(
            f"{self.base_url}/users.lookupByEmail",
            headers=self.headers,
            params={"email": email}
        )
        data = response.json()
        
        if not data.get("ok"):
            return None
        
        return data.get("user")


class HerokuConfigManager:
    """Manages Heroku config var updates."""
    
    def __init__(self, api_key: Optional[str] = None, app_name: Optional[str] = None):
        self.api_key = api_key or os.environ.get("HEROKU_API_KEY")
        self.app_name = app_name or os.environ.get("HEROKU_APP_NAME")
        
        if not self.api_key:
            raise ValueError("HEROKU_API_KEY is required")
        
        self.base_url = "https://api.heroku.com"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/vnd.heroku+json; version=3",
            "Content-Type": "application/json"
        }
    
    def get_config_vars(self, app_name: Optional[str] = None) -> Dict[str, str]:
        """
        Get all config vars for a Heroku app.
        
        Args:
            app_name: Heroku app name (uses default if not provided)
            
        Returns:
            Dictionary of config var names to values
        """
        app = app_name or self.app_name
        if not app:
            raise ValueError("App name is required")
        
        response = requests.get(
            f"{self.base_url}/apps/{app}/config-vars",
            headers=self.headers
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"Failed to get config vars: {response.text}")
        
        return response.json()
    
    def set_config_vars(self, config: Dict[str, str], app_name: Optional[str] = None) -> Dict[str, str]:
        """
        Update config vars for a Heroku app.
        
        Args:
            config: Dictionary of config var names to values
            app_name: Heroku app name (uses default if not provided)
            
        Returns:
            Updated config vars
        """
        app = app_name or self.app_name
        if not app:
            raise ValueError("App name is required")
        
        response = requests.patch(
            f"{self.base_url}/apps/{app}/config-vars",
            headers=self.headers,
            json=config
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"Failed to set config vars: {response.text}")
        
        return response.json()
    
    def get_allowed_users(self, app_name: Optional[str] = None) -> Set[str]:
        """
        Get current ALLOWED_USERS from Heroku config.
        
        Args:
            app_name: Heroku app name
            
        Returns:
            Set of user IDs currently in ALLOWED_USERS
        """
        config = self.get_config_vars(app_name)
        allowed = config.get("ALLOWED_USERS", "")
        return set(u.strip() for u in allowed.split(",") if u.strip())
    
    def add_allowed_users(self, user_ids: List[str], app_name: Optional[str] = None) -> Set[str]:
        """
        Add user IDs to ALLOWED_USERS config var.
        
        Args:
            user_ids: List of Slack user IDs to add
            app_name: Heroku app name
            
        Returns:
            Updated set of allowed user IDs
        """
        current = self.get_allowed_users(app_name)
        updated = current | set(user_ids)
        
        self.set_config_vars(
            {"ALLOWED_USERS": ",".join(sorted(updated))},
            app_name
        )
        
        return updated
    
    def remove_allowed_users(self, user_ids: List[str], app_name: Optional[str] = None) -> Set[str]:
        """
        Remove user IDs from ALLOWED_USERS config var.
        
        Args:
            user_ids: List of Slack user IDs to remove
            app_name: Heroku app name
            
        Returns:
            Updated set of allowed user IDs
        """
        current = self.get_allowed_users(app_name)
        updated = current - set(user_ids)
        
        self.set_config_vars(
            {"ALLOWED_USERS": ",".join(sorted(updated))},
            app_name
        )
        
        return updated
    
    def sync_channel_members(
        self, 
        channel_members: List[str], 
        app_name: Optional[str] = None,
        replace: bool = False
    ) -> tuple[Set[str], Set[str]]:
        """
        Sync channel members to ALLOWED_USERS.
        
        Args:
            channel_members: List of Slack user IDs from channel
            app_name: Heroku app name
            replace: If True, replace all users; if False, add new users
            
        Returns:
            Tuple of (added_users, final_users)
        """
        current = self.get_allowed_users(app_name)
        new_members = set(channel_members)
        
        if replace:
            added = new_members - current
            final = new_members
        else:
            added = new_members - current
            final = current | new_members
        
        if added or replace:
            self.set_config_vars(
                {"ALLOWED_USERS": ",".join(sorted(final))},
                app_name
            )
        
        return added, final


def cmd_list(args):
    """List current authorized users."""
    load_env()
    
    # Try to get from Heroku if API key is available
    heroku_key = os.environ.get("HEROKU_API_KEY")
    app_name = args.app or os.environ.get("HEROKU_APP_NAME")
    
    if heroku_key and app_name:
        try:
            heroku = HerokuConfigManager(heroku_key, app_name)
            users = heroku.get_allowed_users()
            
            print(f"\n{'='*60}")
            print(f"ALLOWED_USERS on Heroku app: {app_name}")
            print(f"{'='*60}")
            
            if not users:
                print("\nNo users in ALLOWED_USERS (all users allowed)")
            else:
                # Get user details from Slack if token available
                slack_token = os.environ.get("SLACK_BOT_TOKEN")
                if slack_token:
                    try:
                        slack = SlackUserManager(slack_token)
                        details = slack.get_user_details_batch(list(users))
                        
                        print(f"\n{'ID':<15} {'Name':<25} {'Email':<30}")
                        print("-" * 70)
                        for u in details:
                            print(f"{u['id']:<15} {u['name']:<25} {u.get('email', 'N/A'):<30}")
                    except Exception as e:
                        print(f"\nUser IDs (could not fetch details: {e}):")
                        for uid in sorted(users):
                            print(f"  - {uid}")
                else:
                    print("\nUser IDs (set SLACK_BOT_TOKEN for more details):")
                    for uid in sorted(users):
                        print(f"  - {uid}")
            
            print(f"\nTotal: {len(users)} users")
            return
        except Exception as e:
            print(f"Warning: Could not fetch from Heroku ({e})")
    
    # Fallback to local env
    allowed = os.environ.get("ALLOWED_USERS", "")
    users = [u.strip() for u in allowed.split(",") if u.strip()]
    
    print(f"\n{'='*60}")
    print("ALLOWED_USERS (from local environment)")
    print(f"{'='*60}")
    
    if not users:
        print("\nNo users in ALLOWED_USERS (all users allowed)")
    else:
        for uid in users:
            print(f"  - {uid}")
    
    print(f"\nTotal: {len(users)} users")


def cmd_fetch_channel(args):
    """Fetch and display members from a Slack channel."""
    load_env()
    
    slack = SlackUserManager()
    
    print(f"\n{'='*60}")
    print(f"Fetching members from channel: {args.channel}")
    print(f"{'='*60}\n")
    
    try:
        member_ids = slack.get_channel_members(args.channel)
        
        if args.details:
            details = slack.get_user_details_batch(member_ids)
            
            # Filter out bots unless --include-bots
            if not args.include_bots:
                details = [u for u in details if not u.get("is_bot")]
            
            print(f"{'ID':<15} {'Name':<25} {'Email':<35} {'Bot?'}")
            print("-" * 85)
            
            for u in details:
                bot_flag = "🤖" if u.get("is_bot") else ""
                print(f"{u['id']:<15} {u['name']:<25} {u.get('email', 'N/A'):<35} {bot_flag}")
            
            print(f"\nTotal: {len(details)} members")
            
            # Show copy-paste ready format
            user_ids = [u["id"] for u in details]
            print(f"\n📋 Copy-paste ready (comma-separated):")
            print(",".join(user_ids))
        else:
            # Filter bots if we can
            if not args.include_bots:
                try:
                    details = slack.get_user_details_batch(member_ids)
                    member_ids = [u["id"] for u in details if not u.get("is_bot")]
                except Exception:
                    pass
            
            for uid in member_ids:
                print(f"  - {uid}")
            
            print(f"\nTotal: {len(member_ids)} members")
            print(f"\n📋 Copy-paste ready (comma-separated):")
            print(",".join(member_ids))
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_sync_channel(args):
    """Sync channel members to Heroku ALLOWED_USERS."""
    load_env()
    
    app_name = args.app or os.environ.get("HEROKU_APP_NAME")
    if not app_name:
        print("Error: Heroku app name required (--app or HEROKU_APP_NAME env var)")
        sys.exit(1)
    
    slack = SlackUserManager()
    heroku = HerokuConfigManager(app_name=app_name)
    
    print(f"\n{'='*60}")
    print(f"Syncing channel {args.channel} to Heroku app: {app_name}")
    print(f"{'='*60}\n")
    
    try:
        # Fetch channel members
        print("📥 Fetching channel members...")
        member_ids = slack.get_channel_members(args.channel)
        
        # Filter out bots
        if not args.include_bots:
            details = slack.get_user_details_batch(member_ids)
            member_ids = [u["id"] for u in details if not u.get("is_bot")]
        
        print(f"   Found {len(member_ids)} members (excluding bots)")
        
        # Sync to Heroku
        print(f"\n{'📤' if args.replace else '➕'} {'Replacing' if args.replace else 'Adding to'} ALLOWED_USERS...")
        added, final = heroku.sync_channel_members(member_ids, replace=args.replace)
        
        if added:
            print(f"   Added {len(added)} new users:")
            for uid in sorted(added):
                print(f"     + {uid}")
        else:
            print("   No new users to add")
        
        print(f"\n✅ ALLOWED_USERS now has {len(final)} users")
        print(f"\n⚡ Heroku will automatically restart the bot with the new configuration")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_add_user(args):
    """Add specific user(s) to ALLOWED_USERS."""
    load_env()
    
    app_name = args.app or os.environ.get("HEROKU_APP_NAME")
    if not app_name:
        print("Error: Heroku app name required (--app or HEROKU_APP_NAME env var)")
        sys.exit(1)
    
    heroku = HerokuConfigManager(app_name=app_name)
    
    print(f"\n{'='*60}")
    print(f"Adding users to Heroku app: {app_name}")
    print(f"{'='*60}\n")
    
    try:
        updated = heroku.add_allowed_users(args.user_ids)
        
        print(f"✅ Added {len(args.user_ids)} user(s):")
        for uid in args.user_ids:
            print(f"   + {uid}")
        
        print(f"\nALLOWED_USERS now has {len(updated)} users")
        print(f"\n⚡ Heroku will automatically restart the bot with the new configuration")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_remove_user(args):
    """Remove specific user(s) from ALLOWED_USERS."""
    load_env()
    
    app_name = args.app or os.environ.get("HEROKU_APP_NAME")
    if not app_name:
        print("Error: Heroku app name required (--app or HEROKU_APP_NAME env var)")
        sys.exit(1)
    
    heroku = HerokuConfigManager(app_name=app_name)
    
    print(f"\n{'='*60}")
    print(f"Removing users from Heroku app: {app_name}")
    print(f"{'='*60}\n")
    
    try:
        updated = heroku.remove_allowed_users(args.user_ids)
        
        print(f"✅ Removed {len(args.user_ids)} user(s):")
        for uid in args.user_ids:
            print(f"   - {uid}")
        
        print(f"\nALLOWED_USERS now has {len(updated)} users")
        print(f"\n⚡ Heroku will automatically restart the bot with the new configuration")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_find_email(args):
    """Find a Slack user by email address."""
    load_env()
    
    slack = SlackUserManager()
    
    print(f"\n{'='*60}")
    print(f"Looking up Slack user by email: {args.email}")
    print(f"{'='*60}\n")
    
    try:
        user = slack.find_user_by_email(args.email)
        
        if user:
            print(f"✅ Found user:")
            print(f"   ID:           {user.get('id')}")
            print(f"   Name:         {user.get('real_name', user.get('name', 'N/A'))}")
            print(f"   Display Name: {user.get('profile', {}).get('display_name', 'N/A')}")
            print(f"   Email:        {user.get('profile', {}).get('email', 'N/A')}")
            print(f"\n📋 Copy-paste the user ID: {user.get('id')}")
        else:
            print(f"❌ No user found with email: {args.email}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Bio-ISAC User Management - Automate Slack ID collection and Heroku config updates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List current authorized users
  python -m src.admin.user_manager list --app bioisac-bot
  
  # Fetch members from a Slack channel with details
  python -m src.admin.user_manager fetch-channel C01234ABCDE --details
  
  # Sync channel members to Heroku (adds new members)
  python -m src.admin.user_manager sync-channel C01234ABCDE --app bioisac-bot
  
  # Add specific users to Heroku config
  python -m src.admin.user_manager add-user U01234ABC U56789DEF --app bioisac-bot
  
  # Find user by email
  python -m src.admin.user_manager find-email user@example.com

Environment Variables:
  SLACK_BOT_TOKEN   - Required for Slack operations
  HEROKU_API_KEY    - Required for Heroku operations
  HEROKU_APP_NAME   - Default Heroku app name
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List current authorized users")
    list_parser.add_argument("--app", help="Heroku app name")
    list_parser.set_defaults(func=cmd_list)
    
    # Fetch channel command
    fetch_parser = subparsers.add_parser("fetch-channel", help="Fetch members from a Slack channel")
    fetch_parser.add_argument("channel", help="Slack channel ID (e.g., C01234ABCDE)")
    fetch_parser.add_argument("--details", "-d", action="store_true", help="Show detailed user info")
    fetch_parser.add_argument("--include-bots", action="store_true", help="Include bot users")
    fetch_parser.set_defaults(func=cmd_fetch_channel)
    
    # Sync channel command
    sync_parser = subparsers.add_parser("sync-channel", help="Sync channel members to Heroku ALLOWED_USERS")
    sync_parser.add_argument("channel", help="Slack channel ID")
    sync_parser.add_argument("--app", help="Heroku app name (required)")
    sync_parser.add_argument("--replace", action="store_true", help="Replace all users (default: add new)")
    sync_parser.add_argument("--include-bots", action="store_true", help="Include bot users")
    sync_parser.set_defaults(func=cmd_sync_channel)
    
    # Add user command
    add_parser = subparsers.add_parser("add-user", help="Add user(s) to ALLOWED_USERS")
    add_parser.add_argument("user_ids", nargs="+", help="Slack user ID(s) to add")
    add_parser.add_argument("--app", help="Heroku app name (required)")
    add_parser.set_defaults(func=cmd_add_user)
    
    # Remove user command
    remove_parser = subparsers.add_parser("remove-user", help="Remove user(s) from ALLOWED_USERS")
    remove_parser.add_argument("user_ids", nargs="+", help="Slack user ID(s) to remove")
    remove_parser.add_argument("--app", help="Heroku app name (required)")
    remove_parser.set_defaults(func=cmd_remove_user)
    
    # Find email command
    email_parser = subparsers.add_parser("find-email", help="Find Slack user by email")
    email_parser.add_argument("email", help="Email address to look up")
    email_parser.set_defaults(func=cmd_find_email)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == "__main__":
    main()

