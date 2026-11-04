using MyLoginProject.Data;
using MyLoginProject.Endpoints;
using MyLoginProject.Hubs;
using MyLoginProject.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. הגדרת CORS שמאפשרת פניות מכל מקור, כולל תמיכה ב-SignalR WebSockets ו-Credentials
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

// 2. הוספת שירותי SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.MaximumReceiveMessageSize = 102400;
});

// 3. רישום שירותי מערכת ומסד נתונים
string connString = builder.Configuration["DbConnectionString"] 
    ?? "Host=localhost; Port=5432; Database=postgres; Username=postgres; Password=12345654321;";

var dbContext = new DatabaseContext(connString);
dbContext.Initialize();

builder.Services.AddSingleton(dbContext);
builder.Services.AddSingleton<AuthService>();

var app = builder.Build();

// 4. הגדרת Middlewares
app.UseWebSockets();
app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// 5. ניתובים (Endpoints) בחלוקה מסודרת ומודולרית
app.MapAuthEndpoints();     // הרשמה, אימות, כניסה, שכחתי סיסמה
app.MapAdminEndpoints();    // פאנל מנהל: ניהול משתמשים, סטטיסטיקות, מחיקה
app.MapClientEndpoints();   // שירותי לקוח: פרופיל וסטטוס אישי
app.MapSystemEndpoints();   // סטטוס מערכתי (DB + Socket)

// 6. ניתובים מהירים לדפי ה-UI (הפרדה מלאה בקישורים נפרדים)
app.MapGet("/", () => Results.Redirect("/client/login.html"));
app.MapGet("/login", () => Results.Redirect("/client/login.html"));

// קישורי לקוח (Client Portal)
app.MapGet("/client", () => Results.Redirect("/client/dashboard.html"));
app.MapGet("/client/login", () => Results.Redirect("/client/login.html"));
app.MapGet("/dashboard", () => Results.Redirect("/client/dashboard.html"));

// קישורי מנהל (Admin Portal)
app.MapGet("/admin", () => Results.Redirect("/admin/dashboard.html"));
app.MapGet("/admin/login", () => Results.Redirect("/admin/login.html"));

// 7. נתיב ה-SignalR Hub
app.MapHub<OsiHub>("/osihub");

app.Run();