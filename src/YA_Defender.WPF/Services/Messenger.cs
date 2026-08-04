using System.IO;
namespace YA_Defender.WPF.Services;

public class Messenger
{
    private readonly Dictionary<Type, List<Delegate>> _subscribers = new();

    public void Subscribe<T>(Action<T> handler)
    {
        lock (_subscribers)
        {
            if (!_subscribers.TryGetValue(typeof(T), out var list))
            {
                list = new List<Delegate>();
                _subscribers[typeof(T)] = list;
            }
            list.Add(handler);
        }
    }

    public void Publish<T>(T message)
    {
        List<Delegate>? snapshot;
        lock (_subscribers)
        {
            if (!_subscribers.TryGetValue(typeof(T), out var list)) return;
            snapshot = list.ToList();
        }
        foreach (var handler in snapshot)
            try { ((Action<T>)handler)(message); } catch { }
    }
}
