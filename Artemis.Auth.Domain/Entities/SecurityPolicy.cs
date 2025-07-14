using Artemis.Auth.Domain.Enums;

namespace Artemis.Auth.Domain.Entities;

public class SecurityPolicy : AuditableEntity
{
    public SecurityPolicyType PolicyType { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Parameters { get; set; } = string.Empty;
    public int ParametersVersion { get; set; }
    public bool IsActive { get; set; }
}