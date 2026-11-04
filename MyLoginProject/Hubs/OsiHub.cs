using Microsoft.AspNetCore.SignalR;

namespace MyLoginProject.Hubs;

/// <summary>
/// Hub ראשי לסימולטור OSI – מאפשר תקשורת דו-כיוונית בזמן אמת עבור הלקוח והמנהל.
/// </summary>
public class OsiHub : Hub
{
    public async Task SendPacket(string layerName, string data)
    {
        await Clients.All.SendAsync("ReceivePacket", layerName, data);
    }
}
