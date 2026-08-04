using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace YA_Defender.WPF.Views;

public partial class ProfileView : UserControl
{
    private bool _syncing;

    public ProfileView()
    {
        InitializeComponent();
        Loaded += (_, _) => SyncPasswords();
    }

    private void SyncPasswords()
    {
        if (DataContext is not ViewModels.ProfileViewModel vm) return;
        _syncing = true;
        VtPassword.Password = vm.VtKey;
        HaPassword.Password = vm.HaKey;
        _syncing = false;
    }

    private void VtPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncing || DataContext is not ViewModels.ProfileViewModel vm) return;
        vm.VtKey = VtPassword.Password;
    }

    private void HaPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncing || DataContext is not ViewModels.ProfileViewModel vm) return;
        vm.HaKey = HaPassword.Password;
    }
}
