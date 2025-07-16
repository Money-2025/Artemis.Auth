namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// User registration response DTO
/// </summary>
public class RegisterResponse
{
    /// <summary>
    /// User ID
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Username
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Registration success flag
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Registration message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Whether email verification is required
    /// </summary>
    public bool RequiresEmailVerification { get; set; } = true;

    /// <summary>
    /// Email verification token (if required)
    /// </summary>
    public string? EmailVerificationToken { get; set; }

    /// <summary>
    /// Whether account is immediately active
    /// </summary>
    public bool IsActive { get; set; } = false;

    /// <summary>
    /// Next steps for the user
    /// </summary>
    public List<string> NextSteps { get; set; } = new();

    /// <summary>
    /// Registration timestamp
    /// </summary>
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Default role assigned to user
    /// </summary>
    public string DefaultRole { get; set; } = "User";
}