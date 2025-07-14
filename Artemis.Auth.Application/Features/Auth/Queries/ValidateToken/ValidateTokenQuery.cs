using MediatR;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Auth.Queries.ValidateToken;

public class ValidateTokenQuery : IRequest<Result<TokenValidationResponseDto>>
{
    public string Token { get; set; } = string.Empty;
    public string TokenType { get; set; } = "access_token";
}