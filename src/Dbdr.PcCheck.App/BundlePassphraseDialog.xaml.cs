using System.Windows;
using Dbdr.PcCheck.Packaging;

namespace Dbdr.PcCheck.App;

public partial class BundlePassphraseDialog : Window
{
    public BundlePassphraseDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => PassphrasePasswordBox.Focus();
    }

    public string Passphrase { get; private set; } = string.Empty;

    private void OpenButton_OnClick(object sender, RoutedEventArgs e)
    {
        var passphrase = PassphrasePasswordBox.Password;
        if (passphrase.Length is < EvidenceBundleWriter.MinimumPassphraseCharacters
            or > EvidenceBundleWriter.MaximumPassphraseCharacters
            || string.IsNullOrWhiteSpace(passphrase))
        {
            ValidationTextBlock.Text = $"Enter {EvidenceBundleWriter.MinimumPassphraseCharacters}–{EvidenceBundleWriter.MaximumPassphraseCharacters} characters.";
            return;
        }

        Passphrase = passphrase;
        DialogResult = true;
    }
}
