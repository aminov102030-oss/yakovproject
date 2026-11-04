using Npgsql;

namespace MyLoginProject.Data;

public class DatabaseContext
{
    private readonly string _connectionString;

    public DatabaseContext(string connectionString)
    {
        _connectionString = connectionString;
    }

    public string ConnectionString => _connectionString;

    public NpgsqlConnection CreateConnection()
    {
        return new NpgsqlConnection(_connectionString);
    }

    public void Initialize()
    {
        try
        {
            using var connection = CreateConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Id SERIAL PRIMARY KEY,
                    Fullname TEXT,
                    Email TEXT UNIQUE,
                    Password TEXT,
                    IsVerified BOOLEAN DEFAULT FALSE,
                    VerificationCode TEXT,
                    Role TEXT DEFAULT 'User'
                );
                ALTER TABLE Users ADD COLUMN IF NOT EXISTS IsVerified BOOLEAN DEFAULT FALSE;
                ALTER TABLE Users ADD COLUMN IF NOT EXISTS VerificationCode TEXT;
                ALTER TABLE Users ADD COLUMN IF NOT EXISTS Role TEXT DEFAULT 'User';

                -- הגדרת מנהל ראשי כברירת מחדל אם קיים המייל של המערכת
                UPDATE Users 
                SET Role = 'Admin' 
                WHERE LOWER(TRIM(Email)) = 'aminov102030@gmail.com';
            ";
            command.ExecuteNonQuery();
            Console.WriteLine("[DB SUCCESS] Database connected, schema updated with Role support.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DB ERROR]: {ex.Message}");
        }
    }
}
