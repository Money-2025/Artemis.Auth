using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Users.Queries.GetUserSessions;

/// <summary>
/// Query to get user sessions
/// </summary>
public class GetUserSessionsQuery : IRequest<Result<UserSessionsDto>>
{
    public Guid UserId { get; set; }
    public Guid CurrentSessionId { get; set; }
    public bool IncludeExpired { get; set; } = false;
}

/// <summary>
/// User sessions data transfer object
/// </summary>
public class UserSessionsDto
{
    public List<UserSessionDto> Sessions { get; set; } = new();
    public int TotalCount { get; set; }
    public int ActiveCount { get; set; }
}

/// <summary>
/// User session data transfer object
/// </summary>
public class UserSessionDto
{
    public Guid Id { get; set; }
    public string DeviceInfo { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime LastAccessedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsActive { get; set; }
    public bool IsCurrent { get; set; }
}