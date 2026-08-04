using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Input;
using YA_Defender.WPF.Services;

namespace YA_Defender.WPF.ViewModels;

public class MainViewModel : ViewModelBase
{
    private ViewModelBase? _selected;
    public AppServices Services { get; }

    public ObservableCollection<NavItem> NavItems { get; } = new();

    public ViewModelBase? Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

    public string StatusText { get; set; } = "";

    public ICommand NavigateCommand { get; }

    public MainViewModel(AppServices services)
    {
        Services = services;
        NavigateCommand = new RelayCommand(p =>
        {
            if (p is NavItem item) Selected = item.Target;
        });

        NavItems.Add(new NavItem { Title = "HOME", Glyph = "\uE80F", Target = new HomeViewModel(this) });
        NavItems.Add(new NavItem { Title = "SCAN", Glyph = "\uE721", Target = new ScanViewModel(this) });
        NavItems.Add(new NavItem { Title = "QUARANTINE", Glyph = "\uE7E3", Target = new QuarantineViewModel(this) });
        NavItems.Add(new NavItem { Title = "PROFILE", Glyph = "\uE713", Target = new ProfileViewModel(this) });

        Selected = NavItems[0].Target;
    }
}

public class NavItem
{
    public string Title { get; set; } = "";
    public string Glyph { get; set; } = "";
    public ViewModelBase Target { get; set; } = null!;
}
