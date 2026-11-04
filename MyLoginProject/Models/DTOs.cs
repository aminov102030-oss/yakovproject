namespace MyLoginProject.Models;

public record UserDto(
    int Id,
    string Fullname,
    string Email,
    string PasswordHash,
    bool IsVerified,
    string Role
);

public record RegisterRequest(string Fullname, string Email, string Password);
public record VerifyRequest(string Email, string Code);
public record ResendCodeRequest(string Email);
public record LoginRequest(string Email, string Password);
public record ForgotPasswordRequest(string Email);
public record VerifyResetCodeRequest(string Email, string Code);
public record ResetPasswordRequest(string Email, string Code, string NewPassword);
public record UpdateRoleRequest(string Role);
