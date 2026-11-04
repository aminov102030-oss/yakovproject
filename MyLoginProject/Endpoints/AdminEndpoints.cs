using Npgsql;
using MyLoginProject.Data;
using MyLoginProject.Models;

namespace MyLoginProject.Endpoints;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/admin");

        // 1. שליפת כלל המשתמשים עבור פאנל הניהול
        group.MapGet("/users", async (DatabaseContext db) =>
        {
            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Fullname, Email, Password, IsVerified, Role FROM Users ORDER BY Id;";

            using var reader = await command.ExecuteReaderAsync();
            var users = new List<UserDto>();

            while (await reader.ReadAsync())
            {
                users.Add(new UserDto(
                    reader.GetInt32(0),
                    reader.IsDBNull(1) ? "" : reader.GetString(1),
                    reader.GetString(2),
                    reader.IsDBNull(3) ? "" : reader.GetString(3),
                    !reader.IsDBNull(4) && reader.GetBoolean(4),
                    reader.IsDBNull(5) ? "User" : reader.GetString(5)
                ));
            }

            return Results.Ok(users);
        });

        // 2. מחיקת משתמש מהמערכת
        group.MapDelete("/users/{id:int}", async (int id, DatabaseContext db) =>
        {
            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM Users WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            int rowsAffected = await command.ExecuteNonQueryAsync();

            if (rowsAffected > 0)
                return Results.Ok(new { success = true, message = $"משתמש #{id} נמחק בהצלחה." });

            return Results.NotFound(new { success = false, message = "המשתמש לא נמצא." });
        });

        // 3. שינוי תפקיד משתמש (העלאה ל-Admin או הורדה ל-User)
        group.MapPut("/users/{id:int}/role", async (int id, UpdateRoleRequest req, DatabaseContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Role) || (req.Role != "Admin" && req.Role != "User"))
                return Results.BadRequest(new { success = false, message = "תפקיד לא תקין. ערכים מותרים: Admin, User" });

            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = "UPDATE Users SET Role = @role WHERE Id = @id;";
            command.Parameters.AddWithValue("@role", req.Role);
            command.Parameters.AddWithValue("@id", id);

            int rowsAffected = await command.ExecuteNonQueryAsync();

            if (rowsAffected > 0)
                return Results.Ok(new { success = true, message = $"תפקיד משתמש #{id} עודכן ל-{req.Role}." });

            return Results.NotFound(new { success = false, message = "המשתמש לא נמצא." });
        });

        // 4. סטטיסטיקות ומדדים עבור מנהל המערכת
        group.MapGet("/stats", async (DatabaseContext db) =>
        {
            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT 
                    COUNT(*) AS TotalUsers,
                    COUNT(CASE WHEN IsVerified = TRUE THEN 1 END) AS VerifiedUsers,
                    COUNT(CASE WHEN Role = 'Admin' THEN 1 END) AS AdminsCount
                FROM Users;
            ";

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return Results.Ok(new
                {
                    totalUsers = reader.GetInt64(0),
                    verifiedUsers = reader.GetInt64(1),
                    adminsCount = reader.GetInt64(2)
                });
            }

            return Results.Ok(new { totalUsers = 0, verifiedUsers = 0, adminsCount = 0 });
        });
    }
}
