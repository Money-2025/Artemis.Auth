using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Authentication.Commands.ResendVerification;

/// <summary>
/// Command for resending email verification
/// </summary>
public class ResendVerificationCommand : IRequest<Result<bool>>
{
    public string Email { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? ApplicationUrl { get; set; }
}