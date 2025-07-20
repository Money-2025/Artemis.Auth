using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;

/// <summary>
/// Command for verifying email address
/// </summary>
public class VerifyEmailCommand : IRequest<Result<VerifyEmailDto>>
{
    public string Token { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Email verification response data transfer object
/// </summary>
public class VerifyEmailDto
{
    public string Email { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime VerifiedAt { get; set; }
    public bool Success { get; set; }
    public bool AccountActivated { get; set; }
}