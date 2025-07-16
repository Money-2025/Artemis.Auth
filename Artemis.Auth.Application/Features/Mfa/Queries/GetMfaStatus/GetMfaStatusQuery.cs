using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Mfa.Queries.GetMfaStatus;

/// <summary>
/// Query for getting MFA status
/// </summary>
public class GetMfaStatusQuery : IRequest<Result<MfaStatusDto>>
{
    public Guid UserId { get; set; }
}

/// <summary>
/// MFA status response data transfer object
/// </summary>
public class MfaStatusDto
{
    public bool IsEnabled { get; set; }
    public string[] EnabledMethods { get; set; } = Array.Empty<string>();
    public string[] AvailableMethods { get; set; } = Array.Empty<string>();
    public int BackupCodesRemaining { get; set; }
    public DateTime? LastUsed { get; set; }
    public bool IsRequired { get; set; }
}