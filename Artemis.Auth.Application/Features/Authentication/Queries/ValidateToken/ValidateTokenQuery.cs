using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Queries.ValidateToken;

/// <summary>
/// Query for validating JWT token
/// </summary>
public class ValidateTokenQuery : IRequest<Result<ValidateTokenDto>>
{
    public string Token { get; set; } = string.Empty;
    public string? TokenType { get; set; } = "access";
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Token validation response data transfer object
/// </summary>
public class ValidateTokenDto
{
    public bool IsValid { get; set; }
    public Guid? UserId { get; set; }
    public string? Username { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public DateTime? ExpiresAt { get; set; }
    public TimeSpan? RemainingLifetime { get; set; }
    public Dictionary<string, object> Claims { get; set; } = new();
}