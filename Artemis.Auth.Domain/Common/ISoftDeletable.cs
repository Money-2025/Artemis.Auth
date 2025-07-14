namespace Artemis.Auth.Domain.Common;

/// <summary>
/// Marker interface for entities that support soft deletion
/// </summary>
public interface ISoftDeletable
{
    bool IsDeleted { get; set; }
    DateTime? DeletedAt { get; set; }
    Guid? DeletedBy { get; set; }
}