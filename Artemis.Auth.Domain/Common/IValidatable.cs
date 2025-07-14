namespace Artemis.Auth.Domain.Common;

public interface IValidatable
{
    ValidationResult Validate();
}