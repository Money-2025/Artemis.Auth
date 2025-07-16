namespace Artemis.Auth.Infrastructure.Templates;

/// <summary>
/// Email Templates: Contains HTML email templates for authentication workflows
/// Provides responsive, professional email templates for user communications
/// Templates are optimized for various email clients and devices
/// </summary>
public static class EmailTemplates
{
    /// <summary>
    /// Base HTML template with common styling and structure
    /// Provides consistent branding and responsive design
    /// Used as wrapper for all email content
    /// </summary>
    public static string GetBaseTemplate(string title, string content, string applicationUrl)
    {
        return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .container {{
            background-color: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 20px;
        }}
        .logo {{
            font-size: 28px;
            font-weight: bold;
            color: #495057;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #6c757d;
            font-size: 16px;
        }}
        .content {{
            margin-bottom: 30px;
        }}
        .button {{
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            margin: 15px 0;
            text-align: center;
        }}
        .button:hover {{
            background-color: #0056b3;
        }}
        .alert {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .alert.danger {{
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }}
        .alert.success {{
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }}
        .code {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            font-weight: bold;
            text-align: center;
            letter-spacing: 2px;
            margin: 15px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
            color: #6c757d;
            font-size: 14px;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
        .security-notice {{
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin: 20px 0;
            border-radius: 0 5px 5px 0;
        }}
        @media (max-width: 600px) {{
            body {{
                padding: 10px;
            }}
            .container {{
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <div class=""logo"">🛡️ Artemis Auth</div>
            <div class=""subtitle"">Secure Authentication Service</div>
        </div>
        <div class=""content"">
            {content}
        </div>
        <div class=""footer"">
            <p>This email was sent from Artemis Auth</p>
            <p>If you didn't request this email, please ignore it or <a href=""{applicationUrl}/support"">contact support</a></p>
            <p>&copy; {DateTime.UtcNow.Year} Artemis Auth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";
    }

    /// <summary>
    /// Email confirmation template
    /// Sent to new users to verify their email address
    /// Contains secure confirmation link with expiration
    /// </summary>
    public static string GetEmailConfirmationTemplate(string userName, string confirmationLink)
    {
        var content = $@"
            <h2>Welcome to Artemis Auth, {userName}!</h2>
            <p>Thank you for creating your account. To complete your registration and start using our services, please confirm your email address by clicking the button below:</p>
            
            <div style=""text-align: center; margin: 30px 0;"">
                <a href=""{confirmationLink}"" class=""button"">Confirm Email Address</a>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style=""word-break: break-all; color: #007bff;"">{confirmationLink}</p>
            
            <div class=""security-notice"">
                <strong>Security Notice:</strong>
                <ul>
                    <li>This confirmation link will expire in 24 hours</li>
                    <li>If you didn't create this account, please ignore this email</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>";

        return content;
    }

    /// <summary>
    /// Password reset template
    /// Sent when users request password reset
    /// Contains secure reset link with short expiration
    /// </summary>
    public static string GetPasswordResetTemplate(string userName, string resetLink)
    {
        var content = $@"
            <h2>Password Reset Request</h2>
            <p>Hello {userName},</p>
            <p>We received a request to reset your password for your Artemis Auth account. If you made this request, click the button below to reset your password:</p>
            
            <div style=""text-align: center; margin: 30px 0;"">
                <a href=""{resetLink}"" class=""button"">Reset Password</a>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style=""word-break: break-all; color: #007bff;"">{resetLink}</p>
            
            <div class=""alert danger"">
                <strong>Security Alert:</strong>
                <ul>
                    <li>This reset link will expire in 2 hours</li>
                    <li>If you didn't request this reset, please ignore this email</li>
                    <li>Your password will not be changed unless you click the link above</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>";

        return content;
    }

    /// <summary>
    /// Welcome email template
    /// Sent after successful email confirmation
    /// Provides helpful information for new users
    /// </summary>
    public static string GetWelcomeTemplate(string userName)
    {
        var content = $@"
            <h2>Welcome to Artemis Auth, {userName}! 🎉</h2>
            <p>Congratulations! Your email has been successfully confirmed and your account is now active.</p>
            
            <div class=""alert success"">
                <strong>Your account is ready to use!</strong>
                <p>You can now access all features of our secure authentication service.</p>
            </div>
            
            <h3>Getting Started</h3>
            <ul>
                <li><strong>Secure Login:</strong> Use your email and password to sign in</li>
                <li><strong>Two-Factor Authentication:</strong> Enable 2FA for enhanced security</li>
                <li><strong>Profile Management:</strong> Update your profile and security settings</li>
                <li><strong>Session Management:</strong> Monitor your active sessions</li>
            </ul>
            
            <h3>Security Best Practices</h3>
            <ul>
                <li>Use a strong, unique password</li>
                <li>Enable two-factor authentication</li>
                <li>Keep your email address up to date</li>
                <li>Log out from shared devices</li>
                <li>Report any suspicious activity</li>
            </ul>
            
            <div class=""security-notice"">
                <strong>Need Help?</strong>
                <p>If you have any questions or need assistance, our support team is here to help.</p>
            </div>";

        return content;
    }

    /// <summary>
    /// Two-factor authentication code template
    /// Sent when users request 2FA codes
    /// Contains time-sensitive verification code
    /// </summary>
    public static string GetTwoFactorCodeTemplate(string userName, string code)
    {
        var content = $@"
            <h2>Two-Factor Authentication Code</h2>
            <p>Hello {userName},</p>
            <p>You are attempting to sign in to your Artemis Auth account. Please use the verification code below to complete your login:</p>
            
            <div class=""code"">{code}</div>
            
            <p style=""text-align: center; margin: 20px 0;"">
                <strong>Enter this code in your authentication app or browser</strong>
            </p>
            
            <div class=""alert"">
                <strong>Important:</strong>
                <ul>
                    <li>This code expires in 5 minutes</li>
                    <li>Use this code only once</li>
                    <li>If you didn't request this code, please secure your account immediately</li>
                </ul>
            </div>
            
            <div class=""security-notice"">
                <strong>Security Tip:</strong>
                <p>Consider using an authenticator app for more secure two-factor authentication.</p>
            </div>";

        return content;
    }

    /// <summary>
    /// Account locked notification template
    /// Sent when user account is locked due to security
    /// Provides unlock information and security guidance
    /// </summary>
    public static string GetAccountLockedTemplate(string userName, DateTime lockoutEnd)
    {
        var lockoutEndLocal = lockoutEnd.ToString("yyyy-MM-dd HH:mm:ss UTC");
        var content = $@"
            <h2>Account Security Alert</h2>
            <p>Hello {userName},</p>
            <p>Your Artemis Auth account has been temporarily locked due to multiple failed login attempts.</p>
            
            <div class=""alert danger"">
                <strong>Account Status:</strong>
                <ul>
                    <li>Account locked until: <strong>{lockoutEndLocal}</strong></li>
                    <li>Reason: Multiple failed login attempts</li>
                    <li>This is a security measure to protect your account</li>
                </ul>
            </div>
            
            <h3>What happens next?</h3>
            <ul>
                <li>Your account will be automatically unlocked at the time shown above</li>
                <li>You can then sign in normally with your correct credentials</li>
                <li>If you forgot your password, you can reset it after the lockout period</li>
            </ul>
            
            <div class=""security-notice"">
                <strong>Security Recommendations:</strong>
                <ul>
                    <li>Ensure you're using the correct password</li>
                    <li>Check for any suspicious activity on your account</li>
                    <li>Consider enabling two-factor authentication</li>
                    <li>Use a unique, strong password</li>
                </ul>
            </div>
            
            <p>If you believe this lockout was triggered by suspicious activity, please contact our support team immediately.</p>";

        return content;
    }

    /// <summary>
    /// Security alert template
    /// Sent for various security events and suspicious activities
    /// Provides detailed information about security incidents
    /// </summary>
    public static string GetSecurityAlertTemplate(string userName, string alertMessage, string ipAddress)
    {
        var content = $@"
            <h2>Security Alert</h2>
            <p>Hello {userName},</p>
            <p>We detected unusual activity on your Artemis Auth account and wanted to notify you immediately.</p>
            
            <div class=""alert danger"">
                <strong>Security Event Details:</strong>
                <ul>
                    <li><strong>Alert:</strong> {alertMessage}</li>
                    <li><strong>IP Address:</strong> {ipAddress}</li>
                    <li><strong>Time:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}</li>
                </ul>
            </div>
            
            <h3>Immediate Actions Required</h3>
            <ol>
                <li><strong>Verify Activity:</strong> If this was you, no action is needed</li>
                <li><strong>Secure Account:</strong> If this wasn't you, change your password immediately</li>
                <li><strong>Review Sessions:</strong> Check your active sessions and log out from unknown devices</li>
                <li><strong>Enable 2FA:</strong> Add an extra layer of security to your account</li>
            </ol>
            
            <div class=""security-notice"">
                <strong>Account Protection:</strong>
                <p>We continuously monitor for suspicious activity to keep your account secure. This alert was generated automatically by our security systems.</p>
            </div>
            
            <p>If you need immediate assistance or believe your account has been compromised, please contact our security team right away.</p>";

        return content;
    }

    /// <summary>
    /// Password changed notification template
    /// Sent after successful password change
    /// Confirms the security action and provides guidance
    /// </summary>
    public static string GetPasswordChangedTemplate(string userName)
    {
        var content = $@"
            <h2>Password Changed Successfully</h2>
            <p>Hello {userName},</p>
            <p>Your password for your Artemis Auth account has been successfully changed.</p>
            
            <div class=""alert success"">
                <strong>Password Update Confirmed</strong>
                <ul>
                    <li>Changed on: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}</li>
                    <li>All existing sessions have been invalidated</li>
                    <li>You'll need to sign in again on all devices</li>
                </ul>
            </div>
            
            <h3>Security Measures Activated</h3>
            <ul>
                <li>All active sessions have been terminated</li>
                <li>New security stamp generated</li>
                <li>Authentication tokens have been revoked</li>
            </ul>
            
            <div class=""security-notice"">
                <strong>Didn't change your password?</strong>
                <p>If you didn't make this change, your account may be compromised. Please contact our security team immediately and consider the following:</p>
                <ul>
                    <li>Reset your password immediately</li>
                    <li>Enable two-factor authentication</li>
                    <li>Review your account activity</li>
                    <li>Check your email for other security alerts</li>
                </ul>
            </div>";

        return content;
    }

    /// <summary>
    /// Account deactivated notification template
    /// Sent when user account is deactivated
    /// Provides information about account status and reactivation
    /// </summary>
    public static string GetAccountDeactivatedTemplate(string userName)
    {
        var content = $@"
            <h2>Account Deactivated</h2>
            <p>Hello {userName},</p>
            <p>Your Artemis Auth account has been deactivated as requested.</p>
            
            <div class=""alert"">
                <strong>Account Status:</strong>
                <ul>
                    <li>Account deactivated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}</li>
                    <li>All sessions have been terminated</li>
                    <li>Your data is preserved for reactivation</li>
                </ul>
            </div>
            
            <h3>What this means</h3>
            <ul>
                <li>You cannot sign in to your account</li>
                <li>All active sessions have been terminated</li>
                <li>Your account data is safely stored</li>
                <li>You can reactivate your account at any time</li>
            </ul>
            
            <h3>Need to reactivate?</h3>
            <p>If you want to reactivate your account in the future, simply attempt to sign in and follow the reactivation process.</p>
            
            <div class=""security-notice"">
                <strong>Account Security:</strong>
                <p>Your account data remains secure and will be available when you choose to reactivate.</p>
            </div>";

        return content;
    }
}