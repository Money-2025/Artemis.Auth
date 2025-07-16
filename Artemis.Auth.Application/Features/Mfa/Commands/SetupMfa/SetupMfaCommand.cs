using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Mfa.Commands.SetupMfa;

/// <summary>
/// Command for MFA setup
/// </summary>
public class SetupMfaCommand : IRequest<Result<MfaSetupDto>>
{
    public Guid UserId { get; set; }
    public string Method { get; set; } = string.Empty;
    public string? PhoneNumber { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// MFA setup response data transfer object
/// </summary>
public class MfaSetupDto
{
    public string Method { get; set; } = string.Empty;
    public string? QrCode { get; set; }
    public string? Secret { get; set; }
    public string[]? BackupCodes { get; set; }
    public string Instructions { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
}