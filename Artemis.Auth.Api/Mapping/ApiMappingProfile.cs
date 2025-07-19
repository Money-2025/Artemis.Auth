using AutoMapper;
using Artemis.Auth.Api.DTOs.Authentication;
using Artemis.Auth.Api.DTOs.User;
using Artemis.Auth.Api.DTOs.Admin;
using Artemis.Auth.Api.DTOs.Mfa;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Features.Admin.Commands.AssignUserRoles;
using Artemis.Auth.Application.Features.Admin.Commands.UpdateUser;
using Artemis.Auth.Application.Features.Authentication.Commands.Login;
using Artemis.Auth.Application.Features.Authentication.Commands.RegisterUser;
using Artemis.Auth.Application.Features.Users.Commands.UpdateUserProfile;
using Artemis.Auth.Application.Features.Users.Commands.ChangePassword;
using Artemis.Auth.Application.Features.Users.Commands.TerminateSession;
using Artemis.Auth.Application.Features.Admin.Queries.GetUsers;
using Artemis.Auth.Application.Features.Authentication.Commands.ForgotPassword;
using Artemis.Auth.Application.Features.Authentication.Commands.RefreshToken;
using Artemis.Auth.Application.Features.Authentication.Commands.ResetPassword;
using Artemis.Auth.Application.Features.Authentication.Commands.Logout;
using Artemis.Auth.Application.Features.Authentication.Commands.VerifyEmail;
using Artemis.Auth.Application.Features.Mfa.Commands.SetupMfa;
using Artemis.Auth.Application.Features.Mfa.Commands.VerifyMfa;
using Artemis.Auth.Application.Features.Mfa.Commands.DisableMfa;

namespace Artemis.Auth.Api.Mapping;

/// <summary>
/// AutoMapper profile for API layer mappings
/// </summary>
public class ApiMappingProfile : Profile
{
    public ApiMappingProfile()
    {
        CreateAuthenticationMappings();
        CreateUserMappings();
        CreateAdminMappings();
        CreateMfaMappings();
    }

    /// <summary>
    /// Creates authentication-related mappings
    /// </summary>
    private void CreateAuthenticationMappings()
    {
        // Login mappings
        CreateMap<LoginRequest, LoginCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.RememberMe, opt => opt.MapFrom(src => src.RememberMe))
            .ForMember(dest => dest.DeviceInfo, opt => opt.MapFrom(src => src.DeviceInfo))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Register mappings
        CreateMap<RegisterRequest, RegisterUserCommand>()
            .ForMember(dest => dest.Username, opt => opt.MapFrom(src => src.Username))
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.Password, opt => opt.MapFrom(src => src.Password))
            .ForMember(dest => dest.ConfirmPassword, opt => opt.MapFrom(src => src.ConfirmPassword))
            .ForMember(dest => dest.PhoneNumber, opt => opt.MapFrom(src => src.PhoneNumber))
            .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName))
            .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName))
            .ForMember(dest => dest.AcceptTerms, opt => opt.MapFrom(src => src.AcceptTerms))
            .ForMember(dest => dest.ClientIpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Register response mappings
        CreateMap<Artemis.Auth.Application.DTOs.UserProfileDto, RegisterResponse>()
            .ForMember(dest => dest.Success, opt => opt.MapFrom(src => true))
            .ForMember(dest => dest.RequiresEmailVerification, opt => opt.MapFrom(src => !src.EmailConfirmed))
            .ForMember(dest => dest.EmailVerificationToken, opt => opt.Ignore()) // Token handled separately
            .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => src.EmailConfirmed))
            .ForMember(dest => dest.NextSteps, opt => opt.MapFrom(src => new List<string> 
            { 
                !src.EmailConfirmed ? "Check your email for verification link" : "You can now log in",
                "Complete your profile if needed"
            }))
            .ForMember(dest => dest.DefaultRole, opt => opt.MapFrom(src => "User"))
            .ForMember(dest => dest.RegisteredAt, opt => opt.MapFrom(src => src.CreatedAt));

        // Verify email mappings
        CreateMap<VerifyEmailRequest, VerifyEmailCommand>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.Token, opt => opt.MapFrom(src => src.Token))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        CreateMap<VerifyEmailDto, VerifyEmailResponse>()
            .ForMember(dest => dest.Success, opt => opt.MapFrom(src => src.Success))
            .ForMember(dest => dest.Message, opt => opt.MapFrom(src => src.Message))
            .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => src.AccountActivated))
            .ForMember(dest => dest.VerifiedAt, opt => opt.MapFrom(src => src.VerifiedAt))
            .ForMember(dest => dest.AutoLogin, opt => opt.MapFrom(src => false))
            .ForMember(dest => dest.LoginResponse, opt => opt.Ignore());

        // Forgot password mappings
        CreateMap<ForgotPasswordRequest, ForgotPasswordCommand>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Reset password mappings
        CreateMap<ResetPasswordRequest, ResetPasswordCommand>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.Token, opt => opt.MapFrom(src => src.Token))
            .ForMember(dest => dest.NewPassword, opt => opt.MapFrom(src => src.NewPassword))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Refresh token mappings
        CreateMap<RefreshTokenRequest, RefreshTokenCommand>()
            .ForMember(dest => dest.RefreshToken, opt => opt.MapFrom(src => src.RefreshToken))
            .ForMember(dest => dest.AccessToken, opt => opt.MapFrom(src => src.AccessToken))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Logout mappings
        CreateMap<LogoutRequest, LogoutCommand>()
            .ForMember(dest => dest.RefreshToken, opt => opt.MapFrom(src => src.RefreshToken))
            .ForMember(dest => dest.LogoutAllDevices, opt => opt.MapFrom(src => src.LogoutFromAllDevices))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));
    }

    /// <summary>
    /// Creates user-related mappings
    /// </summary>
    private void CreateUserMappings()
    {
        // User profile mappings
        CreateMap<UserProfileRequest, UpdateUserProfileCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore());

        // Change password mappings
        CreateMap<ChangePasswordRequest, ChangePasswordCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // Terminate session mappings
        CreateMap<TerminateSessionRequest, TerminateSessionCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.CurrentSessionId, opt => opt.Ignore())
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));
    }

    /// <summary>
    /// Creates admin-related mappings
    /// </summary>
    private void CreateAdminMappings()
    {
        // Admin user search mappings
        CreateMap<AdminUserSearchRequest, GetUsersQuery>()
            .ForMember(dest => dest.RequestedBy, opt => opt.Ignore())
            .ForMember(dest => dest.SearchTerm, opt => opt.MapFrom(src => src.Query))
            .ForMember(dest => dest.Status, opt => opt.Ignore())
            .ForMember(dest => dest.Role, opt => opt.MapFrom(src => src.RoleId.HasValue ? src.RoleId.Value.ToString() : null))
            .ForMember(dest => dest.IsLocked, opt => opt.MapFrom(src => src.IsLocked))
            .ForMember(dest => dest.IsEmailVerified, opt => opt.MapFrom(src => src.EmailConfirmed))
            .ForMember(dest => dest.SortBy, opt => opt.MapFrom(src => src.SortBy))
            .ForMember(dest => dest.SortOrder, opt => opt.MapFrom(src => src.SortDirection))
            .ForMember(dest => dest.Page, opt => opt.MapFrom(src => src.Page))
            .ForMember(dest => dest.PageSize, opt => opt.MapFrom(src => src.PageSize));

        // Admin user update mappings
        CreateMap<AdminUserRequest, UpdateUserCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.UpdatedBy, opt => opt.Ignore())
            .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
            .ForMember(dest => dest.UserAgent, opt => opt.Ignore())
            .ForMember(dest => dest.IsEmailVerified, opt => opt.MapFrom(src => src.EmailConfirmed))
            .ForMember(dest => dest.IsPhoneVerified, opt => opt.MapFrom(src => src.PhoneConfirmed));

        // Admin role assignment mappings
        CreateMap<AdminUserRoleRequest, AssignUserRolesCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.AssignedBy, opt => opt.Ignore())
            .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
            .ForMember(dest => dest.UserAgent, opt => opt.Ignore());

        // Admin response mappings - using global UserProfileDto properties
        CreateMap<Artemis.Auth.Application.DTOs.UserProfileDto, AdminUserResponse>()
            .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName ?? src.Username))
            .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName ?? string.Empty))
            .ForMember(dest => dest.PhoneConfirmed, opt => opt.MapFrom(src => src.PhoneNumberConfirmed))
            .ForMember(dest => dest.IsLocked, opt => opt.MapFrom(src => src.LockoutEnd.HasValue && src.LockoutEnd.Value > DateTime.UtcNow))
            .ForMember(dest => dest.FailedLoginAttempts, opt => opt.MapFrom(src => src.FailedLoginCount))
            .ForMember(dest => dest.UpdatedAt, opt => opt.MapFrom(src => src.ModifiedAt ?? src.CreatedAt))
            .ForMember(dest => dest.IsDeleted, opt => opt.MapFrom(src => !src.IsActive))
            .ForMember(dest => dest.DeletedAt, opt => opt.Ignore())
            .ForMember(dest => dest.ActivitySummary, opt => opt.Ignore())
            .ForMember(dest => dest.SecuritySummary, opt => opt.Ignore());

        CreateMap<AdminUsersDto, AdminUsersResponse>()
            .ForMember(dest => dest.HasNextPage, opt => opt.MapFrom(src => src.HasNext))
            .ForMember(dest => dest.HasPreviousPage, opt => opt.MapFrom(src => src.HasPrevious))
            .ForMember(dest => dest.Statistics, opt => opt.Ignore());

        CreateMap<AdminUserDto, AdminUserResponse>()
            .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName ?? string.Empty))
            .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName ?? string.Empty))
            .ForMember(dest => dest.PhoneConfirmed, opt => opt.MapFrom(src => src.PhoneNumberConfirmed))
            .ForMember(dest => dest.FailedLoginAttempts, opt => opt.MapFrom(src => src.AccessFailedCount))
            .ForMember(dest => dest.Roles, opt => opt.MapFrom(src => src.Roles.Select(r => r.Name).ToList()))
            .ForMember(dest => dest.Permissions, opt => opt.MapFrom(src => src.Roles.SelectMany(r => r.Permissions).ToList()))
            .ForMember(dest => dest.UpdatedAt, opt => opt.MapFrom(src => src.UpdatedAt ?? src.CreatedAt))
            .ForMember(dest => dest.ActivitySummary, opt => opt.Ignore())
            .ForMember(dest => dest.SecuritySummary, opt => opt.Ignore());

        CreateMap<UserRolesDto, AdminUserRoleResponse>()
            .ForMember(dest => dest.Success, opt => opt.MapFrom(src => true))
            .ForMember(dest => dest.Message, opt => opt.MapFrom(src => "Roles assigned successfully"))
            .ForMember(dest => dest.AssignedRoles, opt => opt.MapFrom(src => src.Roles.Select(r => r.Name).ToList()))
            .ForMember(dest => dest.RemovedRoles, opt => opt.MapFrom(src => new List<string>()))
            .ForMember(dest => dest.CurrentRoles, opt => opt.MapFrom(src => src.Roles.Select(r => r.Name).ToList()))
            .ForMember(dest => dest.AssignedAt, opt => opt.MapFrom(src => src.LastUpdated));

        // TODO: Add other admin mappings as commands are implemented
    }

    /// <summary>
    /// Creates MFA-related mappings
    /// </summary>
    private void CreateMfaMappings()
    {
        // MFA setup mappings
        CreateMap<MfaSetupRequest, SetupMfaCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.Method, opt => opt.MapFrom(src => src.Method))
            .ForMember(dest => dest.PhoneNumber, opt => opt.MapFrom(src => src.PhoneNumber))
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // MFA verify mappings
        CreateMap<MfaVerifyRequest, VerifyMfaCommand>()
            .ForMember(dest => dest.UserId, opt => opt.Ignore())
            .ForMember(dest => dest.Method, opt => opt.MapFrom(src => src.Method))
            .ForMember(dest => dest.Code, opt => opt.MapFrom(src => src.Code))
            .ForMember(dest => dest.BackupCode, opt => opt.Ignore()) // No BackupCode in MfaVerifyRequest
            .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
            .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));

        // MFA disable mappings - Remove since MfaDisableRequest doesn't exist
        // CreateMap<MfaDisableRequest, DisableMfaCommand>()
        //     .ForMember(dest => dest.UserId, opt => opt.Ignore())
        //     .ForMember(dest => dest.Password, opt => opt.MapFrom(src => src.Password))
        //     .ForMember(dest => dest.IpAddress, opt => opt.MapFrom(src => src.IpAddress))
        //     .ForMember(dest => dest.UserAgent, opt => opt.MapFrom(src => src.UserAgent));
    }
}

/// <summary>
/// Placeholder mapping for request DTOs that don't have direct command mappings
/// </summary>
public class TerminateSessionRequest
{
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}