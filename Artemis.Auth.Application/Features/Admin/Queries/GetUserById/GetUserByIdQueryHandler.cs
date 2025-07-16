using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Queries.GetUserById;

public class GetUserByIdQueryHandler : IRequestHandler<GetUserByIdQuery, Result<UserProfileDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<GetUserByIdQueryHandler> _logger;

    public GetUserByIdQueryHandler(
        IUserRepository userRepository,
        IMapper mapper,
        ILogger<GetUserByIdQueryHandler> logger)
    {
        _userRepository = userRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<Result<UserProfileDto>> Handle(GetUserByIdQuery request, CancellationToken cancellationToken)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            
            if (user == null)
            {
                return Result<UserProfileDto>.Failure("User not found");
            }

            var userDto = _mapper.Map<UserProfileDto>(user);
            return Result<UserProfileDto>.Success(userDto, "User retrieved successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user {UserId} by admin {RequestedBy}", request.UserId, request.RequestedBy);
            return Result<UserProfileDto>.Failure("Failed to retrieve user");
        }
    }
}