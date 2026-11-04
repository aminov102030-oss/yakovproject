using Npgsql;
using MyLoginProject.Data;
using MyLoginProject.Models;
using MyLoginProject.Services;

namespace MyLoginProject.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth");

        // 1. הרשמת משתמש לקוח
        group.MapPost("/register", async (RegisterRequest req, DatabaseContext db, AuthService auth) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

            string cleanEmail = req.Email.Trim().ToLower();
            string passwordHash = auth.HashPassword(req.Password);
            string code = Random.Shared.Next(1000, 10000).ToString();

            using var connection = db.CreateConnection();
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
                INSERT INTO Users (Fullname, Email, Password, IsVerified, VerificationCode, Role) 
                VALUES (@fullname, @email, @password, FALSE, @code, 'User')
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
                auth.SendEmail(cleanEmail, code, "קוד אימות להרשמה", "הפעלת החשבון");
                return Results.Ok(new { success = true, message = "קוד אימות בן 4 ספרות נשלח למייל שלך! אנא הזן אותו להפעלת החשבון." });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { success = false, message = $"שגיאה: {ex.Message}" });
            }
        });

        // 2. אימות קוד הרשמה
        group.MapPost("/verify-registration", async (VerifyRequest req, DatabaseContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
                return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

            string cleanEmail = req.Email.Trim().ToLower();

            using var connection = db.CreateConnection();
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
        group.MapPost("/resend-code", async (ResendCodeRequest req, DatabaseContext db, AuthService auth) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email))
                return Results.BadRequest(new { success = false, message = "נא להזין כתובת אימייל." });

            string cleanEmail = req.Email.Trim().ToLower();
            string code = Random.Shared.Next(1000, 10000).ToString();

            using var connection = db.CreateConnection();
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
                auth.SendEmail(cleanEmail, code, "קוד אימות חדש להרשמה", "הפעלת החשבון");
                return Results.Ok(new { success = true, message = "קוד אימות חדש נשלח למייל שלך." });
            }

            return Results.BadRequest(new { success = false, message = "האימייל לא נמצא או שכבר אומת במערכת." });
        });

        // 4. התחברות (מחזיר Fullname וגם Role כדי לנווט ל-Client או ל-Admin)
        group.MapPost("/login", async (LoginRequest req, DatabaseContext db, AuthService auth) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText = "SELECT Fullname, IsVerified, Password, Role FROM Users WHERE LOWER(TRIM(Email)) = LOWER(TRIM(@email));";
            command.Parameters.AddWithValue("@email", req.Email);

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                string dbPasswordHash = reader.IsDBNull(2) ? "" : reader.GetString(2);
                
                if (!auth.VerifyPassword(req.Password, dbPasswordHash))
                {
                    return Results.BadRequest(new { success = false, message = "אימייל או סיסמה שגויים." });
                }

                bool isVerified = !reader.IsDBNull(1) && reader.GetBoolean(1);
                if (!isVerified)
                {
                    return Results.BadRequest(new { success = false, message = "החשבון טרם אומת במייל. אנא הזן את קוד האימות שנשלח אליך." });
                }

                string fullname = reader.IsDBNull(0) ? "" : reader.GetString(0);
                string role = reader.IsDBNull(3) ? "User" : reader.GetString(3);

                return Results.Ok(new 
                { 
                    success = true, 
                    fullname = fullname, 
                    role = role, 
                    message = $"ברוך הבא {fullname}!" 
                });
            }

            return Results.BadRequest(new { success = false, message = "אימייל או סיסמה שגויים." });
        });

        // 5. שכחתי סיסמה
        group.MapPost("/forgot-password", async (ForgotPasswordRequest req, DatabaseContext db, AuthService auth) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email))
                return Results.BadRequest(new { success = false, message = "נא להזין כתובת אימייל." });

            string cleanEmail = req.Email.Trim().ToLower();

            using var connection = db.CreateConnection();
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

            auth.SendEmail(cleanEmail, code, "קוד אימות לשחזור סיסמה", "שחזור הסיסמה");

            return Results.Ok(new { success = true, message = "קוד אימות בן 4 ספרות נשלח לכתובת האימייל שלך!" });
        });

        // 6. אימות קוד שחזור סיסמה
        group.MapPost("/verify-reset-code", async (VerifyResetCodeRequest req, DatabaseContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
                return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

            using var connection = db.CreateConnection();
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
        group.MapPost("/reset-password", async (ResetPasswordRequest req, DatabaseContext db, AuthService auth) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Code))
                return Results.BadRequest(new { success = false, message = "נא למלא את כל השדות." });

            if (string.IsNullOrWhiteSpace(req.NewPassword))
                return Results.BadRequest(new { success = false, message = "נא להזין סיסמה חדשה." });

            using var connection = db.CreateConnection();
            await connection.OpenAsync();

            string newPasswordHash = auth.HashPassword(req.NewPassword);

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
    }
}
