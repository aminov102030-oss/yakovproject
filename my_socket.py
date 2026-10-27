"""
MySocket - מימוש מחלקת Socket עצמאית ופרוטוקול תקשורת מעל TCP
מבוסס על ארכיטקטורת הפרויקט: Application -> Protocol -> MySocket -> Windows API -> TCP -> Network
"""

import socket
import struct
import sys

class MySocket:
    """
    מחלקת Socket עצמאית האחראית על:
    1. יצירת Socket והגדרות רשת (Windows API / Winsock)
    2. חיבור לשרת (Connect) או האזנה (Bind/Listen/Accept)
    3. שכבת פרוטוקול (Framing עם 4-byte Length-Prefix)
    4. שליחה בטוחה (SendAll)
    5. קבלה מנוהלת ומניעת חיתוך חבילות (Receive Exact)
    6. טיפול מקיף בשגיאות וסגירת משאבים
    """

    def __init__(self, sock=None):
        if sock is None:
            # יצירת Socket מסוג IPv4 (AF_INET) ופרוטוקול TCP (SOCK_STREAM)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # אפשרות לשימוש חוזר בפורט מיד לאחר סגירה (SO_REUSEADDR)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            self.sock = sock

    # --- פעולות צד לקוח ---

    def connect(self, host: str, port: int, timeout: float = 10.0):
        """חיבור אל שרת מרוחק עם הגדרת Timeout"""
        try:
            self.sock.settimeout(timeout)
            print(f"[MySocket] מתחבר אל {host}:{port}...")
            self.sock.connect((host, port))
            print(f"[MySocket] החיבור בוצע בהצלחה!")
            return True
        except socket.timeout:
            print(f"[MySocket שגיאה] תם הזמן הקצוב לחיבור אל {host}:{port}")
            return False
        except socket.error as err:
            print(f"[MySocket שגיאה] שגיאת חיבור: {err}")
            return False

    # --- פעולות צד שרת ---

    def bind(self, host: str, port: int):
        """שיוך ה-Socket לכתובת ופורט"""
        try:
            self.sock.bind((host, port))
            print(f"[MySocket Server] ה-Socket שויך בהצלחה אל {host}:{port}")
            return True
        except socket.error as err:
            print(f"[MySocket Server שגיאה] שגיאת Bind: {err}")
            return False

    def listen(self, backlog: int = 5):
        """התחלת האזנה לחיבורים נכנסים"""
        try:
            self.sock.listen(backlog)
            print(f"[MySocket Server] מאזין לחיבורים (Queue: {backlog})...")
            return True
        except socket.error as err:
            print(f"[MySocket Server שגיאה] שגיאת Listen: {err}")
            return False

    def accept(self):
        """קבלת חיבור חדש מלקוח והחזרת מופע MySocket עבורו"""
        try:
            client_raw_sock, address = self.sock.accept()
            print(f"[MySocket Server] לקוח חדש התחבר מכתובת {address[0]}:{address[1]}")
            return MySocket(client_raw_sock), address
        except socket.error as err:
            print(f"[MySocket Server שגיאה] שגיאת Accept: {err}")
            return None, None

    # --- שכבת פרוטוקול: שליחה וקבלה של הודעות (Protocol Framing) ---

    def send_message(self, message: str) -> bool:
        """
        שליחת הודעה לפי פרוטוקול Length-Prefixed:
        [ 4 Bytes: אורך ההודעה ] + [ תוכן ההודעה מקודד ב-UTF-8 ]
        מנגנון זה פותר לחלוטין את בעיית Packet Fragmentation ב-TCP.
        """
        try:
            data_bytes = message.encode('utf-8')
            # קידוד 4 בתים המייצגים את אורך המידע (Big-Endian integer)
            header = struct.pack('!I', len(data_bytes))
            packet = header + data_bytes
            
            # שליחה מבוקרת של כל הבתים
            self.sock.sendall(packet)
            return True
        except socket.error as err:
            print(f"[MySocket שגיאה] שגיאה בשליחת הודעה: {err}")
            return False

    def receive_message(self) -> str | None:
        """
        קבלת הודעה לפי הפרוטוקול:
        1. קריאת 4 בתים של ה-Header לחילוץ אורך ההודעה.
        2. קריאת כל בתי המידע בדיוק לפי האורך שחולץ.
        """
        try:
            # שלב א': קריאת ה-Header (4 בתים)
            header = self._recv_exact(4)
            if not header:
                return None  # הלקוח/השרת סגר את החיבור
            
            message_len = struct.unpack('!I', header)[0]

            # שלב ב': קריאת תוכן ההודעה
            data = self._recv_exact(message_len)
            if not data:
                return None
            
            return data.decode('utf-8')
        except socket.error as err:
            print(f"[MySocket שגיאה] שגיאה בקבלת הודעה: {err}")
            return None

    def _recv_exact(self, num_bytes: int) -> bytes | None:
        """פונקציית עזר: קוראת בדיוק את מספר הבתים המבוקש מתוך ה-Stream של TCP"""
        buffer = bytearray()
        while len(buffer) < num_bytes:
            packet = self.sock.recv(num_bytes - len(buffer))
            if not packet:
                return None  # Connection closed
            buffer.extend(packet)
        return bytes(buffer)

    # --- סגירה ושחרור משאבים ---

    def close(self):
        """סגירה מסודרת של ה-Socket"""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            self.sock.close()
            print("[MySocket] ה-Socket נסגר בהצלחה.")
        except Exception as err:
            print(f"[MySocket שגיאה] שגיאה בסגירת ה-Socket: {err}")
