using ImzaKit.Agent.Native;
using ImzaKit.DependencyInjection;
using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Hosts.Desktop.Session;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;

namespace ImzaKit.Hosts.Desktop.App;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
        ServiceCollection services = new();
        services.AddImzaKitWindowsAgent();
        ServiceProvider provider = services.BuildServiceProvider();
        Session = DesktopHostFactory.CreateSession(provider.GetRequiredService<INativePinPrompt>());
    }

    internal SignSessionViewModel Session { get; }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindow window = new(Session);
        window.Activate();
    }
}
