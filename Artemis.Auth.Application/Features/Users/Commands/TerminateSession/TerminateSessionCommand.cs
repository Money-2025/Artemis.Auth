using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Users.Commands.TerminateSession;

/// <summary>
/// Command to terminate a user session
/// </summary>
public class TerminateSessionCommand : IRequest<Result>
{
    public Guid UserId { get; set; }
    public Guid SessionId { get; set; }
    public Guid CurrentSessionId { get; set; }
    public bool TerminateAll { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}