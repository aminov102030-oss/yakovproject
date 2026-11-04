using Npgsql;
using MyLoginProject.Data;

namespace MyLoginProject.Endpoints;

public static class ClientEndpoints
{
    public static void MapClientEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/client");

        // פרופיל אישי של הלקוח
        group.MapGet("/profile", async (string email, DatabaseContext db) =>
        {
            if (string.IsNullOrWhiteSpace(email))
                return Results.BadRequest(new { success = false, message = "נא לספק אימייל." });

            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Fullname, Email, IsVerified, Role FROM Users WHERE LOWER(TRIM(Email)) = LOWER(TRIM(@email));";
            command.Parameters.AddWithValue("@email", email);

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return Results.Ok(new
                {
                    id = reader.GetInt32(0),
                    fullname = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    email = reader.GetString(2),
                    isVerified = !reader.IsDBNull(3) && reader.GetBoolean(3),
                    role = reader.IsDBNull(4) ? "User" : reader.GetString(4)
                });
            }

            return Results.NotFound(new { success = false, message = "משתמש לא נמצא." });
        });
    }

    public static void MapSystemEndpoints(this WebApplication app)
    {
        // סטטוס מערכתי (Socket & DB)
        app.MapGet("/api/system/status", async (DatabaseContext db) =>
        {
            bool dbConnected = false;
            try
            {
                using var connection = db.CreateConnection();
                await connection.OpenAsync();
                dbConnected = true;
            }
            catch
            {
                dbConnected = false;
            }

            return Results.Ok(new
            {
                socketRunning = true,
                socketStatus = "פועל ומאזין",
                protocol = "WebSocket (TCP)",
                dbType = "PostgreSQL",
                dbConnected = dbConnected,
                dbStatus = dbConnected ? "מחובר ותקין" : "שגיאת חיבור למסד",
                listenPort = "5057"
            });
        });
    }
}
