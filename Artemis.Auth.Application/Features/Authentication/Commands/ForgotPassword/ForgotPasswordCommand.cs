using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.ForgotPassword;

/// <summary>
/// Command for initiating password reset
/// </summary>
public class ForgotPasswordCommand : IRequest<Result<ForgotPasswordDto>>
{
    public string Email { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Forgot password response data transfer object
/// </summary>
public class ForgotPasswordDto
{
    public string Email { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime RequestedAt { get; set; }
    public bool EmailSent { get; set; }
}