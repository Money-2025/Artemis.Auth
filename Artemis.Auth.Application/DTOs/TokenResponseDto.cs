namespace Artemis.Auth.Application.DTOs;

public class TokenResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Scope { get; set; } = string.Empty;
    public Dictionary<string, object> Claims { get; set; } = new();
}

public class RefreshTokenResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class TokenValidationResponseDto
{
    public bool IsValid { get; set; }
    public string? UserId { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public DateTime? ExpiresAt { get; set; }
    public string? TokenType { get; set; }
}

public class ResetTokenResponseDto
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class ConfirmationTokenResponseDto
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string Message { get; set; } = string.Empty;
}