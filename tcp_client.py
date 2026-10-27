"""
TCP Client - לקוח סימולציה המשתמש ב-MySocket
מתחבר לשרת, מקבל הודעת ברכה, שולח הודעות ומקבל תגובות לפי הפרוטוקול
"""

import sys
from my_socket import MySocket

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9050

def main():
    client = MySocket()
    print(f"=== לקוח TCP - התחברות לשרת {SERVER_HOST}:{SERVER_PORT} ===")

    if not client.connect(SERVER_HOST, SERVER_PORT):
        print("לא ניתן להתחבר לשרת. ודא ש-tcp_server.py פועל.")
        return

    # קבלת הודעת הברכה הראשונית מהשרת
    welcome = client.receive_message()
    print(f"[מהשרת]: {welcome}")

    try:
        while True:
            msg = input("\nהזן הודעה לשליחה (או 'exit' ליציאה): ").strip()
            if not msg:
                continue

            # שליחת ההודעה לפי הפרוטוקול
            if not client.send_message(msg):
                print("שגיאה בשליחת ההודעה.")
                break

            if msg.lower() == "exit":
                break

            # קבלת תגובה מהשרת
            response = client.receive_message()
            if response is None:
                print("השרת סגר את החיבור.")
                break

            print(f"[תגובת השרת]: {response}")

    except KeyboardInterrupt:
        print("\nהתוכנית נעצרה.")
    finally:
        client.close()

if __name__ == "__main__":
    main()
