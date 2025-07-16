using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Mfa.Commands.VerifyMfa;

/// <summary>
/// Command for MFA verification
/// </summary>
public class VerifyMfaCommand : IRequest<Result<MfaVerifyDto>>
{
    public Guid UserId { get; set; }
    public string Method { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string? BackupCode { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// MFA verification response data transfer object
/// </summary>
public class MfaVerifyDto
{
    public bool IsVerified { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime VerifiedAt { get; set; }
    public bool IsSetupComplete { get; set; }
}