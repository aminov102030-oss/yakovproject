using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Collections.Concurrent;
using Npgsql;
using Microsoft.AspNetCore.SignalR;
using BCrypt.Net;
using MyLoginProject;

var builder = WebApplication.CreateBuilder(args);

// הגדרת CORS שמאפשרת פניות מכל מקור, כולל תמיכה ב-SignalR WebSockets ו-Credentials
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// הוספת שירותי SignalR עם תמיכה ב-WebSockets, SSE ו-LongPolling
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.MaximumReceiveMessageSize = 102400;
});

// רישום שירות ה-TCP כ-Singleton וכ-Background Service
builder.Services.AddSingleton<TcpServerService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TcpServerService>());

var app = builder.Build();

// WebSockets חייב להיות לפני CORS ו-SignalR
app.UseWebSockets();
app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// משיכת נתונים רגישים מתוך User Secrets / appsettings.json
string connString = app.Configuration["DbConnectionString"] 
    ?? "Host=localhost; Port=5432; Database=postgres; Username=postgres; Password=12345654321;"; // Fallback למקרה שהסודות לא הוגדרו

// אתחול מסד הנתונים בעת הפעלת השרת
InitDatabase(connString);

#region --- פונקציות עזר (הצפנה ושליחת מייל) ---

// הצפנת סיסמה מאובטחת באמצעות BCrypt (מייצר Salt אוטומטית)
string HashPassword(string password)
{
    return BCrypt.Net.BCrypt.HashPassword(password);
}

// בדיקת התאמת סיסמה ל-Hash שנשמר במסד הנתונים
bool VerifyPassword(string password, string hashedPassword)
{
    if (string.IsNullOrEmpty(hashedPassword)) return false;

    // בדיקה אם ה-Hash נוצר ב-BCrypt
    if (hashedPassword.StartsWith("$2a$") || hashedPassword.StartsWith("$2b$") || hashedPassword.StartsWith("$2y$") || hashedPassword.StartsWith("$2x$"))
    {
        try { return BCrypt.Net.BCrypt.Verify(password, hashedPassword); }
        catch { return false; }
    }

    // תמיכה לאחור ב-SHA256 עבור משתמשים שנרשמו קודם
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    var shaHash = Convert.ToHexString(bytes).ToLower();
    return shaHash.Equals(hashedPassword, StringComparison.OrdinalIgnoreCase);
}

// שליחת מייל אימות דרך Brevo SMTP עם הסתרת מפתחות
void SendEmail(string toEmail, string code, string subjectTitle, string purposeTitle)
{
    try
    {
        var smtpEmail = app.Configuration["BrevoEmail"];
        var smtpKey = app.Configuration["BrevoApiKey"];

        if (string.IsNullOrEmpty(smtpEmail) || string.IsNullOrEmpty(smtpKey))
        {
            Console.WriteLine("[BREVO ERROR]: SMTP Credentials are missing in configuration.");
            return;
        }

        using var smtpClient = new SmtpClient("smtp-relay.brevo.com", 587)
        {
            Credentials = new NetworkCredential(smtpEmail, smtpKey),
            EnableSsl = true,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress("aminov102030@gmail.com", "OSI Simulator"),
            Subject = $"{subjectTitle} - OSI Simulator",
            Body = $@"
                <div dir='rtl' style='font-family: Arial, sans-serif; padding: 25px; border: 1px solid #e0e0e0; border-radius: 12px; max-width: 500px; margin: 0 auto; box-shadow: 0 4px 10px rgba(0,0,0,0.05);'>
                    <h2 style='color: #4f46e5; text-align: center; margin-top: 0;'>OSI Simulator</h2>
                    <h3 style='color: #333;'>שלום,</h3>
                    <p style='font-size: 16px; color: #555;'>קוד האימות שלך עבור {purposeTitle} הוא:</p>
                    <div style='background: #f4f4f9; text-align: center; padding: 15px 25px; border-radius: 8px; margin: 15px 0;'>
                        <span style='font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #4f46e5;'>{code}</span>
                    </div>
                    <p style='color: #888; font-size: 13px; text-align: center;'>אם לא ביצעת פעולה זו, ניתן להתעלם מהודעה זו בבטחה.</p>
                </div>",
            IsBodyHtml = true
        };

        mailMessage.To.Add(toEmail);

        smtpClient.Send(mailMessage);
        Console.WriteLine($"[BREVO SUCCESS] Email sent to {toEmail} for {purposeTitle} with code {code}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[BREVO ERROR]: {ex.Message}");
    }
}

#endregion

#region --- נתיבי API (Endpoints) ---

// 1. הרשמה
app.MapPost("/api/auth/register", async (RegisterRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

    string cleanEmail = req.Email.Trim().ToLower();
    string passwordHash = HashPassword(req.Password);
    string code = Random.Shared.Next(1000, 10000).ToString();

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var checkCmd = connection.CreateCommand();
    checkCmd.CommandText = "SELECT Id, IsVerified FROM Users WHERE LOWER(TRIM(Email)) = @email;";
    checkCmd.Parameters.AddWithValue("@email", cleanEmail);

    using (var reader = await checkCmd.ExecuteReaderAsync())
    {
        if (await reader.ReadAsync())
        {
            bool isVerified = !reader.IsDBNull(1) && reader.GetBoolean(1);
            if (isVerified)
            {
                return Results.BadRequest(new { success = false, message = "כתובת האימייל כבר קיימת ומאומתת במערכת." });
            }
        }
    }

    var upsertCmd = connection.CreateCommand();
    upsertCmd.CommandText = @"
        INSERT INTO Users (Fullname, Email, Password, IsVerified, VerificationCode) 
        VALUES (@fullname, @email, @password, FALSE, @code)
        ON CONFLICT (Email) DO UPDATE 
        SET Fullname = @fullname, Password = @password, IsVerified = FALSE, VerificationCode = @code;
    ";
    upsertCmd.Parameters.AddWithValue("@fullname", req.Fullname ?? "");
    upsertCmd.Parameters.AddWithValue("@email", cleanEmail);
    upsertCmd.Parameters.AddWithValue("@password", passwordHash);
    upsertCmd.Parameters.AddWithValue("@code", code);

    try
    {
        await upsertCmd.ExecuteNonQueryAsync();
        SendEmail(cleanEmail, code, "קוד אימות להרשמה", "הפעלת החשבון");
        return Results.Ok(new { success = true, message = "קוד אימות בן 4 ספרות נשלח למייל שלך! אנא הזן אותו להפעלת החשבון." });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { success = false, message = $"שגיאה: {ex.Message}" });
    }
});

// 2. אימות קוד הרשמה
app.MapPost("/api/auth/verify-registration", async (VerifyRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
        return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

    string cleanEmail = req.Email.Trim().ToLower();

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = @"
        UPDATE Users 
        SET IsVerified = TRUE, VerificationCode = NULL 
        WHERE LOWER(TRIM(Email)) = @email AND VerificationCode = @code;
    ";
    command.Parameters.AddWithValue("@email", cleanEmail);
    command.Parameters.AddWithValue("@code", req.Code.Trim());

    int rowsAffected = await command.ExecuteNonQueryAsync();

    if (rowsAffected > 0)
        return Results.Ok(new { success = true, message = "האימות הושלם בהצלחה! החשבון הופעל וכעת ניתן להתחבר." });

    return Results.BadRequest(new { success = false, message = "קוד אימות שגוי. נסה שוב." });
});

// 3. שליחה חוזרת של קוד
app.MapPost("/api/auth/resend-code", async (ResendCodeRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email))
        return Results.BadRequest(new { success = false, message = "נא להזין כתובת אימייל." });

    string cleanEmail = req.Email.Trim().ToLower();
    string code = Random.Shared.Next(1000, 10000).ToString();

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var cmd = connection.CreateCommand();
    cmd.CommandText = @"
        UPDATE Users 
        SET VerificationCode = @code 
        WHERE LOWER(TRIM(Email)) = @email AND IsVerified = FALSE;
    ";
    cmd.Parameters.AddWithValue("@email", cleanEmail);
    cmd.Parameters.AddWithValue("@code", code);

    int rows = await cmd.ExecuteNonQueryAsync();
    if (rows > 0)
    {
        SendEmail(cleanEmail, code, "קוד אימות חדש להרשמה", "הפעלת החשבון");
        return Results.Ok(new { success = true, message = "קוד אימות חדש נשלח למייל שלך." });
    }

    return Results.BadRequest(new { success = false, message = "האימייל לא נמצא או שכבר אומת במערכת." });
});

// 4. התחברות (מעודכן ל-BCrypt)
app.MapPost("/api/auth/login", async (LoginRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    // שליפת הסיסמה המוצפנת מהמסד לצורך השוואה
    command.CommandText = "SELECT Fullname, IsVerified, Password FROM Users WHERE LOWER(TRIM(Email)) = LOWER(TRIM(@email));";
    command.Parameters.AddWithValue("@email", req.Email);

    using var reader = await command.ExecuteReaderAsync();
    if (await reader.ReadAsync())
    {
        string dbPasswordHash = reader.IsDBNull(2) ? "" : reader.GetString(2);
        
        // בדיקה האם הסיסמה שהוזנה תואמת ל-Hash
        if (!VerifyPassword(req.Password, dbPasswordHash))
        {
            return Results.BadRequest(new { success = false, message = "אימייל או סיסמה שגויים." });
        }

        bool isVerified = !reader.IsDBNull(1) && reader.GetBoolean(1);
        if (!isVerified)
        {
            return Results.BadRequest(new { success = false, message = "החשבון טרם אומת במייל. אנא הזן את קוד האימות שנשלח אליך." });
        }

        string fullname = reader.IsDBNull(0) ? "" : reader.GetString(0);
        return Results.Ok(new { success = true, message = $"ברוך הבא {fullname}!" });
    }

    return Results.BadRequest(new { success = false, message = "אימייל או סיסמה שגויים." });
});

// 5. שכחתי סיסמה
app.MapPost("/api/auth/forgot-password", async (ForgotPasswordRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email))
        return Results.BadRequest(new { success = false, message = "נא להזין כתובת אימייל." });

    string cleanEmail = req.Email.Trim().ToLower();

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var checkCmd = connection.CreateCommand();
    checkCmd.CommandText = "SELECT Id FROM Users WHERE LOWER(TRIM(Email)) = @email;";
    checkCmd.Parameters.AddWithValue("@email", cleanEmail);

    var userId = await checkCmd.ExecuteScalarAsync();
    if (userId == null)
        return Results.BadRequest(new { success = false, message = "כתובת האימייל לא נמצאה במערכת." });

    string code = Random.Shared.Next(1000, 10000).ToString();

    var updateCmd = connection.CreateCommand();
    updateCmd.CommandText = "UPDATE Users SET VerificationCode = @code WHERE LOWER(TRIM(Email)) = @email;";
    updateCmd.Parameters.AddWithValue("@code", code);
    updateCmd.Parameters.AddWithValue("@email", cleanEmail);
    await updateCmd.ExecuteNonQueryAsync();

    SendEmail(cleanEmail, code, "קוד אימות לשחזור סיסמה", "שחזור הסיסמה");

    return Results.Ok(new { success = true, message = "קוד אימות בן 4 ספרות נשלח לכתובת האימייל שלך!" });
});

// 6. אימות קוד שחזור סיסמה
app.MapPost("/api/auth/verify-reset-code", async (VerifyResetCodeRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
        return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = "SELECT Id FROM Users WHERE LOWER(TRIM(Email)) = LOWER(TRIM(@email)) AND VerificationCode = @code;";
    command.Parameters.AddWithValue("@email", req.Email);
    command.Parameters.AddWithValue("@code", req.Code.Trim());

    var result = await command.ExecuteScalarAsync();
    if (result != null)
        return Results.Ok(new { success = true, message = "קוד האימות תקין!" });

    return Results.BadRequest(new { success = false, message = "קוד האימות שגוי או פג תוקף." });
});

// 7. איפוס סיסמה
app.MapPost("/api/auth/reset-password", async (ResetPasswordRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
        return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

    if (string.IsNullOrWhiteSpace(req.NewPassword))
        return Results.BadRequest(new { success = false, message = "נא להזין סיסמה חדשה." });

    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    string newPasswordHash = HashPassword(req.NewPassword);

    var command = connection.CreateCommand();
    command.CommandText = @"
        UPDATE Users 
        SET Password = @newPassword, VerificationCode = NULL 
        WHERE LOWER(TRIM(Email)) = LOWER(TRIM(@email)) AND VerificationCode = @code;
    ";
    command.Parameters.AddWithValue("@newPassword", newPasswordHash);
    command.Parameters.AddWithValue("@email", req.Email);
    command.Parameters.AddWithValue("@code", req.Code.Trim());

    int rowsAffected = await command.ExecuteNonQueryAsync();

    if (rowsAffected > 0)
        return Results.Ok(new { success = true, message = "הסיסמה עודכנה בהצלחה! כעת ניתן להתחבר." });

    return Results.BadRequest(new { success = false, message = "קוד אימות לא נכון או שהאימייל שגוי." });
});

// 8. שליפת משתמשים
app.MapGet("/api/admin/users", async () =>
{
    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = "SELECT Id, Fullname, Email, Password, IsVerified FROM Users ORDER BY Id;";

    using var reader = await command.ExecuteReaderAsync();
    var users = new List<object>();

    while (await reader.ReadAsync())
    {
        users.Add(new
        {
            id = reader.GetInt32(0),
            fullname = reader.IsDBNull(1) ? "" : reader.GetString(1),
            email = reader.GetString(2),
            passwordHash = reader.IsDBNull(3) ? "" : reader.GetString(3),
            isVerified = !reader.IsDBNull(4) && reader.GetBoolean(4)
        });
    }

    return Results.Ok(users);
});

// 9. מחיקת משתמש
app.MapDelete("/api/admin/users/{id:int}", async (int id) =>
{
    using var connection = new NpgsqlConnection(connString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = "DELETE FROM Users WHERE Id = @id;";
    command.Parameters.AddWithValue("@id", id);

    int rowsAffected = await command.ExecuteNonQueryAsync();

    if (rowsAffected > 0)
        return Results.Ok(new { success = true, message = "המשתמש נמחק בהצלחה." });

    return Results.NotFound(new { success = false, message = "המשתמש לא נמצא." });
});

// ────────────────────────────────────────────────
// 10. TCP Server – סטטוס
// ────────────────────────────────────────────────
app.MapGet("/api/tcp/status", (TcpServerService tcpService) =>
{
    return Results.Ok(new
    {
        running = tcpService.IsRunning,
        port    = tcpService.Port,
        clients = tcpService.ConnectedClients,
        log     = tcpService.GetLog()
    });
});

// 11. TCP Server – הפעלה
app.MapPost("/api/tcp/start", (TcpServerService tcpService) =>
{
    if (tcpService.IsRunning)
        return Results.BadRequest(new { success = false, message = "שרת ה-TCP כבר פועל." });

    tcpService.Start();
    return Results.Ok(new { success = true, message = $"שרת TCP הופעל על פורט {tcpService.Port}." });
});

// 12. TCP Server – עצירה
app.MapPost("/api/tcp/stop", (TcpServerService tcpService) =>
{
    if (!tcpService.IsRunning)
        return Results.BadRequest(new { success = false, message = "שרת ה-TCP אינו פועל." });

    tcpService.Stop();
    return Results.Ok(new { success = true, message = "שרת ה-TCP נעצר." });
});

// 13. TCP Server – שליחת הודעה לכל הלקוחות המחוברים
app.MapPost("/api/tcp/send", async (TcpSendRequest req, TcpServerService tcpService) =>
{
    if (!tcpService.IsRunning)
        return Results.BadRequest(new { success = false, message = "שרת ה-TCP אינו פועל." });

    if (string.IsNullOrWhiteSpace(req.Message))
        return Results.BadRequest(new { success = false, message = "ההודעה ריקה." });

    int sent = await tcpService.BroadcastAsync(req.Message);
    return Results.Ok(new { success = true, message = $"ההודעה נשלחה ל-{sent} לקוח/לקוחות." });
});

// 14. TCP Client Simulator (MySocket) – חיבור לקוח לבדיקה בלחיצת כפתור בדפדפן
MySocket? simulatedClient = null;

app.MapGet("/api/tcp/client/status", () =>
{
    bool isConnected = simulatedClient != null && simulatedClient.Connected;
    return Results.Ok(new { connected = isConnected });
});

app.MapPost("/api/tcp/client/connect", () =>
{
    if (simulatedClient != null && simulatedClient.Connected)
        return Results.Ok(new { success = true, message = "לקוח TCP כבר מחובר לשרת." });

    simulatedClient?.Dispose();
    simulatedClient = new MySocket();
    bool ok = simulatedClient.Connect("127.0.0.1", 9000);
    if (ok)
        return Results.Ok(new { success = true, message = "לקוח TCP (MySocket) התחבר בהצלחה לשרת בפורט 9000!" });

    return Results.BadRequest(new { success = false, message = "לא ניתן להתחבר לשרת TCP. ודא ששרת ה-TCP פועל." });
});

app.MapPost("/api/tcp/client/disconnect", () =>
{
    if (simulatedClient != null)
    {
        simulatedClient.Dispose();
        simulatedClient = null;
        return Results.Ok(new { success = true, message = "לקוח ה-TCP נותק בהצלחה מהשרת." });
    }
    return Results.Ok(new { success = true, message = "אין לקוח מחובר כרגע." });
});

app.MapPost("/api/tcp/client/send", (TcpSendRequest req) =>
{
    if (simulatedClient == null || !simulatedClient.Connected)
        return Results.BadRequest(new { success = false, message = "לקוח ה-TCP אינו מחובר. לחץ על 'חבר לקוח' תחילה." });

    if (string.IsNullOrWhiteSpace(req.Message))
        return Results.BadRequest(new { success = false, message = "ההודעה ריקה." });

    byte[] bytes = Encoding.UTF8.GetBytes(req.Message + "\n");
    simulatedClient.UnderlyingSocket?.Send(bytes);

    return Results.Ok(new { success = true, message = $"ההודעה נשלחה בהצלחה מהלקוח לשרת: {req.Message}" });
});

// 15. System Status – מידע מערכתי מקיף לדאשבורד (תואם לתמונה)
app.MapGet("/api/system/status", async (TcpServerService tcpService) =>
{
    bool dbConnected = false;
    try
    {
        using var connection = new NpgsqlConnection(connString);
        await connection.OpenAsync();
        dbConnected = true;
    }
    catch
    {
        dbConnected = false;
    }

    return Results.Ok(new
    {
        socketRunning = tcpService.IsRunning,
        socketStatus = tcpService.IsRunning ? "השרת פעיל ומאזין" : "השרת מנותק",
        protocol = "WebSocket (TCP)",
        dbType = "PostgreSQL",
        dbConnected = dbConnected,
        dbStatus = dbConnected ? "מחובר ותקין" : "שגיאת חיבור למסד",
        listenPort = "5025",
        tcpPort = tcpService.Port,
        connectedClients = tcpService.ConnectedClients
    });
});

// ניתוב ישיר לנתיב /dashboard שמגיש את dashboard.html
app.MapGet("/dashboard", () => Results.Redirect("/dashboard.html"));

#endregion

// הגדרת נתיב (Endpoint) לסוקטים של סימולטור ה-OSI
app.MapHub<OsiHub>("/osihub");

// הזרקת HubContext לשירות ה-TCP כדי שיוכל לשדר ל-WebSocket
var tcpService = app.Services.GetRequiredService<TcpServerService>();
var hubContext = app.Services.GetRequiredService<IHubContext<OsiHub>>();
tcpService.SetHubContext(hubContext);

app.Run();

#region --- יצירת טבלה במסד הנתונים ---

void InitDatabase(string cs)
{
    try
    {
        using var connection = new NpgsqlConnection(cs);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                Id SERIAL PRIMARY KEY,
                Fullname TEXT,
                Email TEXT UNIQUE,
                Password TEXT,
                IsVerified BOOLEAN DEFAULT FALSE,
                VerificationCode TEXT
            );
            ALTER TABLE Users ADD COLUMN IF NOT EXISTS IsVerified BOOLEAN DEFAULT FALSE;
            ALTER TABLE Users ADD COLUMN IF NOT EXISTS VerificationCode TEXT;
        ";
        command.ExecuteNonQuery();
        Console.WriteLine("[DB SUCCESS] Database connected and initialized.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DB ERROR]: {ex.Message}");
    }
}

#endregion

#region --- SignalR Hub (WebSocket) ---

/// <summary>
/// Hub ראשי לסימולטור OSI – מאפשר תקשורת WebSocket דו-כיוונית עם הדפדפן.
/// גם מגשר בין הדפדפן לשרת ה-TCP הפנימי.
/// </summary>
public class OsiHub : Hub
{
    private readonly TcpServerService _tcpService;

    public OsiHub(TcpServerService tcpService)
    {
        _tcpService = tcpService;
    }

    // שידור חבילת OSI לכל הדפדפנים המחוברים
    public async Task SendPacket(string layerName, string data)
    {
        await Clients.All.SendAsync("ReceivePacket", layerName, data);
    }

    // שליחת הודעה מהדפדפן אל שרת ה-TCP, ובחזרה לכל הדפדפנים
    public async Task SendToTcp(string message)
    {
        string timestamp = DateTime.Now.ToString("HH:mm:ss");
        // שולח לשרת TCP
        if (_tcpService.IsRunning)
        {
            int sent = await _tcpService.BroadcastAsync(message);
            await Clients.All.SendAsync("TcpLog", $"[{timestamp}] [SERVER→TCP] שלחתי ל-{sent} לקוח/לקוחות: {message}");
        }
        else
        {
            await Clients.Caller.SendAsync("TcpLog", $"[{timestamp}] [שגיאה] שרת ה-TCP אינו פועל.");
        }
    }
}

#endregion

#region --- TCP Server Service (Background) ---

/// <summary>
/// שירות רקע שמפעיל TcpListener על פורט 9000.
/// כל לקוח TCP שמתחבר מוצג בדף tcp.html דרך SignalR.
/// </summary>
public class TcpServerService : BackgroundService
{
    private TcpListener? _listener;
    private readonly ConcurrentDictionary<string, TcpClient> _clients = new();
    private readonly List<string> _log = new();
    private readonly object _logLock = new();
    private IHubContext<OsiHub>? _hubContext;
    private bool _isRunning;

    public int Port { get; } = 9000;
    public bool IsRunning => _isRunning;
    public int ConnectedClients => _clients.Count;

    public void SetHubContext(IHubContext<OsiHub> hubContext) => _hubContext = hubContext;

    public List<string> GetLog()
    {
        lock (_logLock) return _log.TakeLast(50).ToList();
    }

    private void AddLog(string entry)
    {
        string line = $"[{DateTime.Now:HH:mm:ss}] {entry}";
        lock (_logLock) { _log.Add(line); }
        _hubContext?.Clients.All.SendAsync("TcpLog", line);
        Console.WriteLine($"[TCP] {line}");
    }

    public void Start()
    {
        if (_isRunning) return;
        _listener = new TcpListener(IPAddress.Any, Port);
        _listener.Start();
        _isRunning = true;
        AddLog($"שרת TCP הופעל ומאזין על פורט {Port}.");
        _ = AcceptLoopAsync();
    }

    public void Stop()
    {
        _isRunning = false;
        _listener?.Stop();
        foreach (var (id, client) in _clients)
        {
            client.Close();
        }
        _clients.Clear();
        AddLog("שרת TCP נעצר. כל החיבורים נסגרו.");
    }

    private async Task AcceptLoopAsync()
    {
        while (_isRunning && _listener != null)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync();
                string id = Guid.NewGuid().ToString("N")[..8];
                _clients[id] = client;
                string remote = client.Client.RemoteEndPoint?.ToString() ?? "לא ידוע";
                AddLog($"לקוח חדש התחבר [{id}] מ-{remote}. סה\"כ: {_clients.Count}");
                _ = HandleClientAsync(id, client);
            }
            catch { break; }
        }
    }

    private async Task HandleClientAsync(string id, TcpClient client)
    {
        try
        {
            using var stream = client.GetStream();
            var buffer = new byte[4096];

            // שליחת ברכה ללקוח החדש
            var welcome = Encoding.UTF8.GetBytes($"ברוך הבא ל-OSI Simulator TCP Server! [Session: {id}]\n");
            await stream.WriteAsync(welcome);

            while (client.Connected && _isRunning)
            {
                int bytesRead = await stream.ReadAsync(buffer);
                if (bytesRead == 0) break;

                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                AddLog($"[{id}] קיבלתי: {message}");

                // Echo – שולח את ההודעה חזרה
                var echo = Encoding.UTF8.GetBytes($"[Echo] {message}\n");
                await stream.WriteAsync(echo);
            }
        }
        catch (Exception ex)
        {
            AddLog($"[{id}] שגיאה: {ex.Message}");
        }
        finally
        {
            _clients.TryRemove(id, out _);
            client.Close();
            AddLog($"לקוח [{id}] התנתק. סה\"כ: {_clients.Count}");
        }
    }

    public async Task<int> BroadcastAsync(string message)
    {
        var bytes = Encoding.UTF8.GetBytes(message + "\n");
        int sent = 0;
        foreach (var (id, client) in _clients)
        {
            try
            {
                await client.GetStream().WriteAsync(bytes);
                sent++;
            }
            catch
            {
                _clients.TryRemove(id, out _);
            }
        }
        if (sent > 0) AddLog($"[Broadcast] נשלח ל-{sent} לקוחות: {message}");
        return sent;
    }

    // BackgroundService – הפעלה אוטומטית בעת הפעלת השרת
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // ממתין עד שה-App מוכן ולוקח את HubContext
        await Task.Delay(500, stoppingToken);
        AddLog("TcpServerService מוכן (ממתין להפעלה ידנית דרך /api/tcp/start).");
        await Task.Delay(Timeout.Infinite, stoppingToken);
    }
}

#endregion

#region --- מודלים (DTOs) ---

record RegisterRequest(string Fullname, string Email, string Password);
record VerifyRequest(string Email, string Code);
record ResendCodeRequest(string Email);
record LoginRequest(string Email, string Password);
record ForgotPasswordRequest(string Email);
record VerifyResetCodeRequest(string Email, string Code);
record ResetPasswordRequest(string Email, string Code, string NewPassword);
record TcpSendRequest(string Message);

#endregion