using MediatR;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Auth.Commands.RefreshToken;

public class RefreshTokenCommand : IRequest<Result<RefreshTokenResponseDto>>
{
    public string RefreshToken { get; set; } = string.Empty;
    public string? ClientIpAddress { get; set; }
    public string? UserAgent { get; set; }
}