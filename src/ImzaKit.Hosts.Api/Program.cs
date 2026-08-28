using System.Security.Cryptography;
using ImzaKit.Api.Hosting;
using ImzaKit.DependencyInjection;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace ImzaKit.Hosts.Api;

public static class KestrelSignatureApiAdapter
{
    public static KestrelMutualTlsPolicy Policy { get; } = KestrelMutualTlsPolicy.Create();

    public static void ConfigureHttps(HttpsConnectionAdapterOptions https)
    {
        ArgumentNullException.ThrowIfNull(https);
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        if (Policy.AllowUntrustedDeviceCertificates)
        {
            https.AllowAnyClientCertificate();
        }
    }

    public static async Task<ApiHttpRequest> MapAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        using StreamReader reader = new(request.Body);
        string body = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        Dictionary<string, string> headers = request.Headers.ToDictionary(
            static header => header.Key,
            static header => header.Value.ToString(),
            StringComparer.OrdinalIgnoreCase);
        return MutualTlsRequestMapper.Bind(
            request.Method,
            request.Path.HasValue ? request.Path.Value! : "/",
            headers,
            body,
            request.HttpContext.Connection.ClientCertificate);
    }
}

public sealed class HeaderApiCallerResolver : IApiCallerResolver
{
    private readonly JwtBearerApiCallerResolver? _jwt;

    public HeaderApiCallerResolver()
    {
        JwtBearerCallerOptions? jwt = JwtBearerCallerOptions.FromEnvironment();
        _jwt = jwt is not null ? new JwtBearerApiCallerResolver(jwt) : null;
    }

    public ApiCallerIdentity Resolve(ApiHttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _jwt is not null
            ? _jwt.Resolve(request)
            : new ApiCallerIdentity(false, "", "");
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        builder.Services.AddImzaKitCore();
        builder.Services.AddImzaKitApiHost(RandomNumberGenerator.GetBytes(32));
        builder.Services.AddSingleton<IApiCallerResolver, HeaderApiCallerResolver>();
        builder.WebHost.ConfigureKestrel(kestrel =>
            kestrel.ConfigureHttpsDefaults(KestrelSignatureApiAdapter.ConfigureHttps));

        WebApplication app = builder.Build();
        app.Run(async context =>
        {
            SignatureApiRequestHandler handler = context.RequestServices.GetRequiredService<SignatureApiRequestHandler>();
            ApiHttpRequest mapped = await KestrelSignatureApiAdapter.MapAsync(context.Request, context.RequestAborted)
                .ConfigureAwait(false);
            ApiHttpResponse response = handler.Handle(mapped);
            context.Response.StatusCode = response.StatusCode;
            context.Response.ContentType = response.ContentType;
            await context.Response.WriteAsync(response.Body, context.RequestAborted).ConfigureAwait(false);
        });
        app.Run();
    }
}
