using System.Reflection;

namespace ImzaKit.Api.Hosting;

public static class OpenApiContract
{
    public static string ReadYaml()
    {
        using Stream stream = typeof(OpenApiContract).Assembly.GetManifestResourceStream("ImzaKit.Api.openapi.yaml")
            ?? throw new InvalidOperationException("The OpenAPI contract resource is missing.");
        using StreamReader reader = new(stream);
        return reader.ReadToEnd();
    }
}
