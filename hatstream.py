from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import prompt
from datetime import datetime
import urllib.parse
import aes as AES
import requests
import socketio
import tabulate
import logging
import getpass
import random
import json
import os

# Constants
COMMANDS = {
    "add <URL>": "Add a new user",
    "status <URL>": "Check status of a user",
    "list": "List all users",
    "chat <ID>": "Start chat with user",
    "block <ID>": "Block a user",
    "unblock <ID>": "Unblock a user",
    "clear_messages <ID>": "Clear messages with a user",
    "download_messages <ID>": "Download messages with a user",
    "help": "Show this help menu",
    "exit": "Exit the program"
}

logging.basicConfig(
    format='[%(asctime)s] %(levelname)s %(message)s', 
    datefmt='%H:%M:%S', 
    level=logging.INFO
)

# Global state
STATE = {
    "PHRASE_1": None,
    "PHRASE_2": None,
    "currentUser": None,
    "users": []
}

# Socket.IO client
SIO = socketio.Client()

def current_time():
    return datetime.now().strftime("%H:%M:%S")

def send_secure_request(json_data):
    """Send a secure request to the server."""
    try:
        response = requests.post(f"{URL}/api/client", files={
            "enc": ("enc.bin", AES.encrypt(json_data, STATE.get("PHRASE_2")), "application/octet-stream")
        })
        response.raise_for_status()
        decrypted = AES.decrypt(response.content, STATE.get("PHRASE_1"))
        if "error" in decrypted:
            logging.error(decrypted["error"])
            return None
        return decrypted
    except Exception as e:
        logging.error(f"Request failed: {e}")
        return None

def print_help():
    """Print the help menu."""
    commands = [[cmd, desc] for cmd, desc in COMMANDS.items()]
    headers = ["Command", "Description"]
    print(f"\n{tabulate.tabulate(commands, headers)}\n")

@SIO.on("connect")
def on_connect():
    logging.info("Socket connected...")

@SIO.on("disconnect")
def on_disconnect():
    with patch_stdout():
        logging.info("Socket disconnected...")

@SIO.on("data")
def on_message(response):
    """Handle incoming messages."""
    try:
        if "error" in response:
            logging.error(response["error"])
            return
        message_obj = AES.decrypt(response["data"], STATE["PHRASE_1"])
        if message_obj["type"] != "text":
            return
        
        with patch_stdout():
            print(f"> RMT [{current_time()}] {message_obj['data']}")
    except Exception as e:
        logging.error(f"Failed to process message: {e}")

def validate_url(url):
    """Validate a URL."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        logging.error("Invalid URL format.")
        return None
    return f"{parsed.scheme}://{parsed.netloc}"

def fetch_users():
    """Fetch the list of users from the server."""
    logging.info("Fetching users...")
    response = send_secure_request({"action": "GET_USERS"})
    if response:
        STATE["users"] = [user["userAddress"] for user in response["data"]]
        logging.info(f"Fetched {len(STATE['users'])} users.")
    else:
        logging.error("Failed to fetch users.")
        exit(1)

def handle_chat(user_id):
    """Handle the chat session with a user."""
    try:
        user_address = STATE["users"][int(user_id)]
        STATE["currentUser"] = user_address
        logging.info(f"Connecting to ({user_address})...")
        
        while True:
            try:
                message = prompt(f"< YOU [{current_time()}] ")
                if not message:
                    continue
                    
                send_secure_request({
                    "action": "MESSAGE_TO_REMOTE",
                    "type": "text",
                    "time": current_time(),
                    "data": message,
                    "userAddress": STATE['currentUser'],
                    "thisUserAddress": URL
                })
            except KeyboardInterrupt:
                logging.info(f"{STATE['currentUser']} Exiting chat...")
                break
    except (IndexError, ValueError):
        logging.error("Invalid user ID.")

def main():
    global URL
    
    # Input server address
    URL = validate_url(input(f"[{current_time()}] [SERVER_ADDRESS]> ").strip())
    if not URL:
        logging.error("Invalid server address.")
        return

    logging.info(f"Connecting to {URL}...")

    # Input phrases
    STATE["PHRASE_1"] = getpass.getpass(f"[{current_time()}] [PHRASE_1]> ").strip()
    STATE["PHRASE_2"] = getpass.getpass(f"[{current_time()}] [PHRASE_2]> ").strip()
    if not STATE["PHRASE_1"] or not STATE["PHRASE_2"]:
        logging.error("Invalid phrases.")
        return

    logging.info("Authenticating...")
    # Authenticate
    response = send_secure_request({
        "action": "AUTH",
        "phrase1": STATE["PHRASE_1"]
    })
    if not response or response.get("data") != "OK":
        logging.error("Authentication failed.")
        return

    # Connect to Socket.IO
    SIO.connect(URL, wait_timeout=10, headers={"User-Agent": "HatStreamChatClient"})

    # Fetch users
    fetch_users()

    # Main loop
    while True:
        try:
            user_input = input(f"[{current_time()}] [/]> ").strip().lower()
            if user_input in ["exit", "quit"]:
                logging.info("Exiting...")
                break

            elif user_input == "help":
                print_help()

            elif user_input.startswith("status "):
                url = validate_url(user_input.split("status ")[1])
                if url == URL:
                    logging.error("Same server URL.")
                    continue

                if not url:
                    logging.error("Invalid URL.")
                    continue
                
                logging.info(f"Checking status: {url}")
                response = send_secure_request({
                    "action": "USER_STATUS",
                    "userAddress": url,
                    "thisUserAddress": URL
                })

                if response:
                    logging.info(response["data"])

            elif user_input.startswith("add "):
                url = validate_url(user_input.split("add ")[1])
                if url == URL:
                    logging.error("Same server URL.")
                    continue

                if not url:
                    logging.error("Invalid URL.")
                    continue

                logging.info(f"Add user: {url}")
                response = send_secure_request({
                    "action": "ADD_USER",
                    "userAddress": url,
                    "thisUserAddress": URL
                })

                if response:
                    logging.info(response["data"])
                    fetch_users()

            elif user_input.startswith("block "):
                user_id = user_input.split("block ")[1]
                confirm = input(f"[{current_time()}] Are you sure you want to block user {user_id}? (y/n): ").strip().lower()
                if confirm == "y":
                    response = send_secure_request({
                        "action": "BLOCK_USER",
                        "userAddress": STATE["users"][int(user_id)],
                        "thisUserAddress": URL
                    })

                    if response:
                        logging.info(response["data"])

            elif user_input.startswith("unblock "):
                user_id = user_input.split("unblock ")[1]
                confirm = input(f"[{current_time()}] Are you sure you want to unblock user {user_id}? (y/n): ").strip().lower()
                if confirm == "y":
                    response = send_secure_request({
                        "action": "BLOCK_USER",
                        "userAddress": STATE["users"][int(user_id)],
                        "thisUserAddress": URL
                    })

                    if response:
                        logging.info(response["data"])

            elif user_input.startswith("chat "):
                handle_chat(user_input.split("chat ")[1])

            elif user_input == "list":
                users = [[i, user] for i, user in enumerate(STATE["users"])]
                headers = ["ID", "USERS"]
                print(f"\n{tabulate.tabulate(users, headers)}\n")

            elif user_input.startswith("clear_messages "):
                user_id = user_input.split("clear_messages ")[1]
                confirm = input(f"[{current_time()}] Are you sure you want to clear messages with user {user_id}? (y/n): ").strip().lower()
                if confirm == "y":
                    response = send_secure_request({
                        "action": "CLEAR_MESSAGES",
                        "userAddress": STATE["users"][int(user_id)],
                        "thisUserAddress": URL
                    })

                    if response:
                        logging.info(response["data"])

            elif user_input.startswith("download_messages "):
                user_id = user_input.split("download_messages ")[1]
                response = send_secure_request({
                    "action": "DOWNLOAD_MESSAGES",
                    "userAddress": STATE["users"][int(user_id)],
                    "thisUserAddress": URL
                })

                if response:
                    msgPath = os.path.join(os.path.expanduser("~"), "Downloads", f"{random.randint(3**15, 3**16-1)}.json")
                    with open(msgPath, "w") as f:
                        json.dump(response["data"], f)
                        logging.info(f"saved: '{msgPath}'")

            else:
                logging.error("Unknown command. Type 'help' for a list of commands.")

        except (IndexError, ValueError):
            logging.error("Invalid input or ID.")
        
        except KeyboardInterrupt:
            logging.info("Exiting hatstream...")
            exit(0)

if __name__ == "__main__":
    main()