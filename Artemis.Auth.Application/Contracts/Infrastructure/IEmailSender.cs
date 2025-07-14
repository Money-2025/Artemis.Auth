namespace Artemis.Auth.Application.Contracts.Infrastructure;

public interface IEmailSender
{
    Task SendEmailConfirmationAsync(string email, string userName, string confirmationLink);
    Task SendPasswordResetAsync(string email, string userName, string resetLink);
    Task SendPasswordChangedNotificationAsync(string email, string userName);
    Task SendAccountLockedNotificationAsync(string email, string userName, DateTime lockoutEnd);
    Task SendSecurityAlertAsync(string email, string userName, string alertMessage, string ipAddress);
    Task SendWelcomeEmailAsync(string email, string userName);
    Task SendTwoFactorCodeAsync(string email, string userName, string code);
    Task SendAccountDeactivatedNotificationAsync(string email, string userName);
    Task SendEmailAsync(string to, string subject, string body, bool isHtml = true);
}