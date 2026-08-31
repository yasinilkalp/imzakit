using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using WinRT;

namespace ImzaKit.Hosts.Desktop.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ComWrappersSupport.InitializeComWrappers();
        Application.Start(static parameters =>
        {
            DispatcherQueueSynchronizationContext context = new(DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            _ = parameters;
            _ = new App();
        });
    }
}
