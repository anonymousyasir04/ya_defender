using System.IO;
using System.Windows;
using YA_Defender.WPF.ViewModels;

namespace YA_Defender.WPF;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel(App.Services);
    }
}
