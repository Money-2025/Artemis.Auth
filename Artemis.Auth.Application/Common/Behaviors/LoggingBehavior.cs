using MediatR;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Artemis.Auth.Application.Common.Behaviors;

public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;

    public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var requestName = typeof(TRequest).Name;
        var stopwatch = Stopwatch.StartNew();
        
        _logger.LogInformation("Handling {RequestName} - {Request}", requestName, request);
        
        try
        {
            var response = await next();
            
            stopwatch.Stop();
            _logger.LogInformation("Handled {RequestName} in {ElapsedMs}ms", requestName, stopwatch.ElapsedMilliseconds);
            
            return response;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Error handling {RequestName} in {ElapsedMs}ms - {Error}", 
                requestName, stopwatch.ElapsedMilliseconds, ex.Message);
            throw;
        }
    }
}