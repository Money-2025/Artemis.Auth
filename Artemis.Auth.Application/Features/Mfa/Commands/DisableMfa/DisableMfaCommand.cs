using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Mfa.Commands.DisableMfa;

/// <summary>
/// Command for MFA disable
/// </summary>
public class DisableMfaCommand : IRequest<Result<MfaDisableDto>>
{
    public Guid UserId { get; set; }
    public string Password { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// MFA disable response data transfer object
/// </summary>
public class MfaDisableDto
{
    public bool IsDisabled { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime DisabledAt { get; set; }
}