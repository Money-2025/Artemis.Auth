# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an ASP.NET Core 8.0 authentication service following Clean Architecture principles with four main layers:

- **Artemis.Auth.Api** - Web API layer with controllers and HTTP endpoints
- **Artemis.Auth.Application** - Application logic and use cases 
- **Artemis.Auth.Domain** - Core business logic and entities
- **Artemis.Auth.Infrastructure** - Data access and external service integrations

## Development Commands

### Building
```bash
# Build entire solution
dotnet build

# Build specific project
dotnet build Artemis.Auth.Api/Artemis.Auth.Api.csproj
```

### Running the API
```bash
# Run the API project (starts on https://localhost:7109)
dotnet run --project Artemis.Auth.Api

# Run with specific configuration
dotnet run --project Artemis.Auth.Api --configuration Release
```

### Testing
```bash
# Run all tests (when test projects are added)
dotnet test

# Run tests for specific project
dotnet test <TestProjectName>
```

## Architecture Notes

- Uses .NET 8.0 with nullable reference types enabled
- API includes Swagger/OpenAPI documentation available at `/swagger` in development
- Currently contains a basic weather forecast endpoint as a template
- Clean Architecture separation with distinct layers for API, Application, Domain, and Infrastructure
- No test projects currently exist in the solution

## Project Dependencies

- **Artemis.Auth.Api**: Microsoft.AspNetCore.OpenApi, Swashbuckle.AspNetCore
- Other projects currently have no additional dependencies beyond .NET 8.0 base libraries