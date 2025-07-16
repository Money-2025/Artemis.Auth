using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Mfa.Commands.GenerateBackupCodes;

/// <summary>
/// Command for generating MFA backup codes
/// </summary>
public class GenerateBackupCodesCommand : IRequest<Result<MfaBackupCodesDto>>
{
    public Guid UserId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// MFA backup codes response data transfer object
/// </summary>
public class MfaBackupCodesDto
{
    public string[] BackupCodes { get; set; } = Array.Empty<string>();
    public string Message { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public int Count { get; set; }
}