using AutoMapper;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Domain.Entities;

namespace Artemis.Auth.Application.Common.Mappings;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<User, UserProfileDto>()
            .ForMember(dest => dest.Roles, opt => opt.Ignore())
            .ForMember(dest => dest.Permissions, opt => opt.Ignore())
            .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => !src.IsDeleted && (!src.LockoutEnd.HasValue || src.LockoutEnd.Value <= DateTime.UtcNow)))
            .ForMember(dest => dest.LastLogin, opt => opt.MapFrom(src => src.LastLoginAt))
            .ForMember(dest => dest.FirstName, opt => opt.Ignore())
            .ForMember(dest => dest.LastName, opt => opt.Ignore());
            
        CreateMap<User, UserSummaryDto>()
            .ForMember(dest => dest.Roles, opt => opt.Ignore())
            .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => !src.IsDeleted && (!src.LockoutEnd.HasValue || src.LockoutEnd.Value <= DateTime.UtcNow)))
            .ForMember(dest => dest.DisplayName, opt => opt.Ignore());
            
        CreateMap<UserCreateDto, User>()
            .ForMember(dest => dest.Id, opt => opt.MapFrom(src => Guid.NewGuid()))
            .ForMember(dest => dest.NormalizedUsername, opt => opt.MapFrom(src => src.Username.ToUpperInvariant()))
            .ForMember(dest => dest.NormalizedEmail, opt => opt.MapFrom(src => src.Email.ToUpperInvariant()))
            .ForMember(dest => dest.SecurityStamp, opt => opt.MapFrom(src => Guid.NewGuid().ToString()))
            .ForMember(dest => dest.CreatedAt, opt => opt.MapFrom(src => DateTime.UtcNow))
            .ForMember(dest => dest.IsDeleted, opt => opt.MapFrom(src => false))
            .ForMember(dest => dest.FailedLoginCount, opt => opt.MapFrom(src => 0))
            .ForMember(dest => dest.PasswordHash, opt => opt.Ignore())
            .ForMember(dest => dest.RowVersion, opt => opt.Ignore())
            .ForMember(dest => dest.CreatedBy, opt => opt.Ignore())
            .ForMember(dest => dest.ModifiedAt, opt => opt.Ignore())
            .ForMember(dest => dest.ModifiedBy, opt => opt.Ignore())
            .ForMember(dest => dest.DeletedAt, opt => opt.Ignore())
            .ForMember(dest => dest.DeletedBy, opt => opt.Ignore())
            .ForMember(dest => dest.LastLoginAt, opt => opt.Ignore())
            .ForMember(dest => dest.LockoutEnd, opt => opt.Ignore());
            
        CreateMap<UserUpdateDto, User>()
            .ForMember(dest => dest.NormalizedEmail, opt => opt.MapFrom(src => src.Email != null ? src.Email.ToUpperInvariant() : null))
            .ForMember(dest => dest.ModifiedAt, opt => opt.MapFrom(src => DateTime.UtcNow))
            .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null));
            
        CreateMap<Role, RoleDto>()
            .ForMember(dest => dest.Permissions, opt => opt.Ignore())
            .ForMember(dest => dest.UserCount, opt => opt.Ignore())
            .ForMember(dest => dest.IsSystemRole, opt => opt.Ignore());
            
        CreateMap<Role, RoleSummaryDto>()
            .ForMember(dest => dest.UserCount, opt => opt.Ignore())
            .ForMember(dest => dest.PermissionCount, opt => opt.Ignore())
            .ForMember(dest => dest.IsSystemRole, opt => opt.Ignore());
            
        CreateMap<RoleCreateDto, Role>()
            .ForMember(dest => dest.Id, opt => opt.MapFrom(src => Guid.NewGuid()))
            .ForMember(dest => dest.NormalizedName, opt => opt.MapFrom(src => src.Name.ToUpperInvariant()))
            .ForMember(dest => dest.CreatedAt, opt => opt.MapFrom(src => DateTime.UtcNow))
            .ForMember(dest => dest.IsDeleted, opt => opt.MapFrom(src => false))
            .ForMember(dest => dest.RowVersion, opt => opt.Ignore())
            .ForMember(dest => dest.CreatedBy, opt => opt.Ignore())
            .ForMember(dest => dest.ModifiedAt, opt => opt.Ignore())
            .ForMember(dest => dest.ModifiedBy, opt => opt.Ignore())
            .ForMember(dest => dest.DeletedAt, opt => opt.Ignore())
            .ForMember(dest => dest.DeletedBy, opt => opt.Ignore());
            
        CreateMap<RoleUpdateDto, Role>()
            .ForMember(dest => dest.NormalizedName, opt => opt.MapFrom(src => src.Name != null ? src.Name.ToUpperInvariant() : null))
            .ForMember(dest => dest.ModifiedAt, opt => opt.MapFrom(src => DateTime.UtcNow))
            .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null));
            
        CreateMap<UserSession, UserSessionDto>()
            .ForMember(dest => dest.IsCurrentSession, opt => opt.Ignore());
            
        CreateMap<TokenGrant, TokenResponseDto>()
            .ForMember(dest => dest.AccessToken, opt => opt.Ignore())
            .ForMember(dest => dest.RefreshToken, opt => opt.Ignore())
            .ForMember(dest => dest.TokenType, opt => opt.MapFrom(src => "Bearer"))
            .ForMember(dest => dest.ExpiresIn, opt => opt.MapFrom(src => (int)(src.ExpiresAt - DateTime.UtcNow).TotalSeconds))
            .ForMember(dest => dest.ExpiresAt, opt => opt.MapFrom(src => src.ExpiresAt))
            .ForMember(dest => dest.Scope, opt => opt.Ignore())
            .ForMember(dest => dest.Claims, opt => opt.Ignore());
    }
}