using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;

namespace MyLoginProject.Services;

public class AuthService
{
    private readonly IConfiguration _config;

    public AuthService(IConfiguration config)
    {
        _config = config;
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    public bool VerifyPassword(string password, string hashedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword)) return false;

        if (hashedPassword.StartsWith("$2a$") || hashedPassword.StartsWith("$2b$") || hashedPassword.StartsWith("$2y$") || hashedPassword.StartsWith("$2x$"))
        {
            try { return BCrypt.Net.BCrypt.Verify(password, hashedPassword); }
            catch { return false; }
        }

        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        var shaHash = Convert.ToHexString(bytes).ToLower();
        return shaHash.Equals(hashedPassword, StringComparison.OrdinalIgnoreCase);
    }

    public void SendEmail(string toEmail, string code, string subjectTitle, string purposeTitle)
    {
        try
        {
            var smtpEmail = _config["BrevoEmail"];
            var smtpKey = _config["BrevoApiKey"];

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
}
