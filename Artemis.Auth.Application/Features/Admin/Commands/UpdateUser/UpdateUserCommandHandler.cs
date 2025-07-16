using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Commands.UpdateUser;

public class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, Result<UserProfileDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<UpdateUserCommandHandler> _logger;

    public UpdateUserCommandHandler(
        IUserRepository userRepository,
        IMapper mapper,
        ILogger<UpdateUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<Result<UserProfileDto>> Handle(UpdateUserCommand request, CancellationToken cancellationToken)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            
            if (user == null)
            {
                return Result<UserProfileDto>.Failure("User not found");
            }

            // Update user properties based on available User entity fields
            if (!string.IsNullOrEmpty(request.Email))
                user.Email = request.Email;
            
            if (!string.IsNullOrEmpty(request.PhoneNumber))
                user.PhoneNumber = request.PhoneNumber;
            
            if (request.IsEmailVerified.HasValue)
                user.EmailConfirmed = request.IsEmailVerified.Value;
            
            if (request.IsPhoneVerified.HasValue)
                user.PhoneNumberConfirmed = request.IsPhoneVerified.Value;
            
            if (request.LockoutEnd.HasValue)
                user.LockoutEnd = request.LockoutEnd.Value;
            
            if (request.ResetFailedAttempts.HasValue && request.ResetFailedAttempts.Value)
                user.ResetFailedLoginCount();
            
            if (request.TwoFactorEnabled.HasValue)
                user.TwoFactorEnabled = request.TwoFactorEnabled.Value;

            // Update audit fields
            user.ModifiedAt = DateTime.UtcNow;
            user.ModifiedBy = request.UpdatedBy;

            await _userRepository.UpdateAsync(user);

            var userDto = _mapper.Map<UserProfileDto>(user);
            return Result<UserProfileDto>.Success(userDto, "User updated successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {UserId} by admin {UpdatedBy}", request.UserId, request.UpdatedBy);
            return Result<UserProfileDto>.Failure("Failed to update user");
        }
    }
}