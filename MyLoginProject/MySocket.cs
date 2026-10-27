using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MyLoginProject;

/// <summary>
/// MySocket - מחלקת Socket עצמאית ב-C#
/// מממשת את ארכיטקטורת התקשורת בפרויקט:
/// Application -> Protocol -> MySocket -> Windows API (Winsock) -> TCP -> Network
/// </summary>
public class MySocket : IDisposable
{
    private Socket? _socket;
    private bool _isDisposed;

    public Socket? UnderlyingSocket => _socket;
    public bool Connected => _socket != null && _socket.Connected;
    public EndPoint? RemoteEndPoint => _socket?.RemoteEndPoint;

    /// <summary>
    /// בנאי ראשי: יוצר Socket חדש מעל ה-API של מערכת ההפעלה (Windows Sockets / Winsock)
    /// </summary>
    public MySocket()
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
    }

    /// <summary>
    /// בנאי עזר: עוטף Socket קיים (למשל לאחר פעולת Accept בשרת)
    /// </summary>
    public MySocket(Socket socket)
    {
        _socket = socket;
    }

    // ──────────────────────────────────────────────
    //  פעולות צד לקוח (Client Side)
    // ──────────────────────────────────────────────

    /// <summary>
    /// התחברות אל שרת מרוחק באמצעות כתובת IP / Hostname ומספר Port
    /// </summary>
    public bool Connect(string host, int port, int timeoutMs = 5000)
    {
        try
        {
            if (_socket == null) return false;

            IPAddress ip = host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
            var endPoint = new IPEndPoint(ip, port);

            var asyncResult = _socket.BeginConnect(endPoint, null, null);
            bool success = asyncResult.AsyncWaitHandle.WaitOne(timeoutMs, true);

            if (!success)
            {
                _socket.Close();
                Console.WriteLine($"[MySocket שגיאה] תם הזמן הקצוב לחיבור אל {host}:{port}");
                return false;
            }

            _socket.EndConnect(asyncResult);
            Console.WriteLine($"[MySocket] החיבור אל {host}:{port} בוצע בהצלחה!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket שגיאה] שגיאת חיבור: {ex.Message}");
            return false;
        }
    }

    // ──────────────────────────────────────────────
    //  פעולות צד שרת (Server Side)
    // ──────────────────────────────────────────────

    /// <summary>
    /// שיוך (Bind) של ה-Socket לכתובת מקומית ופורט
    /// </summary>
    public bool Bind(string host, int port)
    {
        try
        {
            if (_socket == null) return false;

            IPAddress ip = (host == "0.0.0.0" || host == "localhost") ? IPAddress.Any : IPAddress.Parse(host);
            var endPoint = new IPEndPoint(ip, port);
            _socket.Bind(endPoint);
            Console.WriteLine($"[MySocket Server] שויך בהצלחה ל-{host}:{port}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket Server שגיאה] שגיאת Bind: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// כניסה למצב האזנה לחיבורים נכנסים (Listen)
    /// </summary>
    public bool Listen(int backlog = 5)
    {
        try
        {
            if (_socket == null) return false;

            _socket.Listen(backlog);
            Console.WriteLine($"[MySocket Server] מאזין לחיבורים (Queue: {backlog})...");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket Server שגיאה] שגיאת Listen: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// קבלת חיבור נכנס מלקוח והחזרת מופע MySocket חדש עבורו
    /// </summary>
    public MySocket? Accept()
    {
        try
        {
            if (_socket == null) return null;

            Socket clientSocket = _socket.Accept();
            Console.WriteLine($"[MySocket Server] לקוח חדש התחבר מ-{clientSocket.RemoteEndPoint}");
            return new MySocket(clientSocket);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket Server שגיאה] שגיאת Accept: {ex.Message}");
            return null;
        }
    }

    // ──────────────────────────────────────────────
    //  שכבת פרוטוקול: שליחה וקבלה מבוקרת (Framing)
    // ──────────────────────────────────────────────

    /// <summary>
    /// שליחת הודעה לפי פרוטוקול Length-Prefixed:
    /// [ 4 בתים: אורך המידע (Big Endian) ] + [ תוכן המידע מקודד ב-UTF8 ]
    /// פותר לחלוטין את בעיית Packet Fragmentation / Framing ב-TCP.
    /// </summary>
    public bool SendMessage(string message)
    {
        try
        {
            if (_socket == null || !_socket.Connected) return false;

            byte[] dataBytes = Encoding.UTF8.GetBytes(message);
            // המרת האורך ל-Network Byte Order (Big Endian)
            byte[] lengthBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(dataBytes.Length));

            // יצירת חבילה שלמה: Header + Payload
            byte[] packet = new byte[4 + dataBytes.Length];
            Buffer.BlockCopy(lengthBytes, 0, packet, 0, 4);
            Buffer.BlockCopy(dataBytes, 0, packet, 4, dataBytes.Length);

            int sent = 0;
            while (sent < packet.Length)
            {
                int n = _socket.Send(packet, sent, packet.Length - sent, SocketFlags.None);
                if (n == 0) return false;
                sent += n;
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket שגיאה] שגיאה בשליחה: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// קבלת הודעה לפי הפרוטוקול:
    /// 1. קריאת בדיוק 4 בתים של ה-Header
    /// 2. חילוץ האורך המדויק של ההודעה
    /// 3. קריאת כל בתי המידע בדיוק לפי האורך שחולץ
    /// </summary>
    public string? ReceiveMessage()
    {
        try
        {
            if (_socket == null) return null;

            // שלב 1: קריאת 4 בתים של ה-Header
            byte[]? lengthBytes = ReceiveExact(4);
            if (lengthBytes == null || lengthBytes.Length < 4)
                return null;

            int messageLength = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lengthBytes, 0));
            if (messageLength <= 0 || messageLength > 10 * 1024 * 1024) // הגנה עד 10MB
                return null;

            // שלב 2: קריאת תוכן ההודעה המלא
            byte[]? dataBytes = ReceiveExact(messageLength);
            if (dataBytes == null || dataBytes.Length < messageLength)
                return null;

            return Encoding.UTF8.GetString(dataBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MySocket שגיאה] שגיאה בקבלה: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// קריאת בדיוק מספר בתים מבוקש מתוך ה-TCP Stream
    /// </summary>
    private byte[]? ReceiveExact(int totalBytes)
    {
        if (_socket == null) return null;

        byte[] buffer = new byte[totalBytes];
        int bytesRead = 0;

        while (bytesRead < totalBytes)
        {
            int read = _socket.Receive(buffer, bytesRead, totalBytes - bytesRead, SocketFlags.None);
            if (read == 0) // החיבור נסגר על ידי הצד השני
                return null;

            bytesRead += read;
        }

        return buffer;
    }

    // ──────────────────────────────────────────────
    //  סגירה ושחרור משאבים
    // ──────────────────────────────────────────────

    public void Close()
    {
        try
        {
            if (_socket != null)
            {
                if (_socket.Connected)
                {
                    _socket.Shutdown(SocketShutdown.Both);
                }
                _socket.Close();
                _socket = null;
                Console.WriteLine("[MySocket] ה-Socket נסגר בהצלחה.");
            }
        }
        catch { }
    }

    public void Dispose()
    {
        if (!_isDisposed)
        {
            Close();
            _isDisposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
