"""
TCP Server - שרת בדיקה וסימולציה המשתמש ב-MySocket
מאזין לחיבורים נכנסים, מקבל הודעות לפי הפרוטוקול ומחזיר מענה (Echo/Response)
"""

import threading
from my_socket import MySocket

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9050

def handle_client(client_sock: MySocket, address):
    print(f"[Server Thread] מטפל בלקוח {address}...")
    try:
        # שליחת הודעת ברכה ללקוח החדש
        client_sock.send_message("ברוך הבא לשרת TCP (מופעל באמצעות MySocket)!")

        while True:
            msg = client_sock.receive_message()
            if msg is None:
                print(f"[Server Thread] הלקוח {address} התנתק.")
                break
            
            print(f"[Server Thread] התקבלה הודעה מ-{address}: {msg}")

            if msg.strip().lower() == "exit":
                client_sock.send_message("להתראות! סוגר את החיבור.")
                break

            # שליחת תגובה חוזרת ללקוח
            response = f"[Echo מהשרת]: {msg}"
            client_sock.send_message(response)
    finally:
        client_sock.close()

def main():
    server = MySocket()
    if not server.bind(SERVER_HOST, SERVER_PORT):
        return

    if not server.listen(5):
        return

    print(f"=== שרת TCP פועל ומאזין על {SERVER_HOST}:{SERVER_PORT} ===")
    print("הקש Ctrl+C לעצירת השרת.")

    try:
        while True:
            client_sock, address = server.accept()
            if client_sock:
                thread = threading.Thread(target=handle_client, args=(client_sock, address), daemon=True)
                thread.start()
    except KeyboardInterrupt:
        print("\n[Server] השרת נעצר על ידי המשתמש.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
