using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Sentinel.ViewModels;

namespace Sentinel.Views;

public partial class MainWindow : Window
{
    private readonly AppState _state = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _state;
        _state.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(AppState.CurrentSection) or nameof(AppState.Authorized))
                ShowPage();
        };
        ShowPage();
    }

    private void NavClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button btn) return;
        _state.CurrentSection = btn.Name switch
        {
            "NavNetwork" => AppState.Section.Network,
            "NavThisPc" => AppState.Section.ThisPc,
            "NavPersistence" => AppState.Section.Persistence,
            "NavAccounts" => AppState.Section.Accounts,
            "NavSignatures" => AppState.Section.Signatures,
            "NavFindings" => AppState.Section.Findings,
            _ => AppState.Section.Overview
        };
        ShowPage();
    }

    private void ShowPage()
    {
        PageOverview.IsVisible = _state.CurrentSection == AppState.Section.Overview;
        PageNetwork.IsVisible = _state.CurrentSection == AppState.Section.Network;
        PageThisPc.IsVisible = _state.CurrentSection == AppState.Section.ThisPc;
        PagePersistence.IsVisible = _state.CurrentSection == AppState.Section.Persistence;
        PageAccounts.IsVisible = _state.CurrentSection == AppState.Section.Accounts;
        PageSignatures.IsVisible = _state.CurrentSection == AppState.Section.Signatures;
        PageFindings.IsVisible = _state.CurrentSection == AppState.Section.Findings;
    }

    private async void ScanNetwork(object? sender, RoutedEventArgs e) => await _state.ScanNetworkAsync();
    private async void ScanThisPc(object? sender, RoutedEventArgs e) => await _state.ScanThisPcAsync();
    private async void ScanFull(object? sender, RoutedEventArgs e) => await _state.FullAsync();
    private async void UpdateSigs(object? sender, RoutedEventArgs e) => await _state.UpdateSignaturesAsync();

    private void FilterChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (FilterBox.SelectedItem is ComboBoxItem item && item.Content is string s)
            _state.Filter = s;
    }

    private void ClearFindings(object? sender, RoutedEventArgs e) => _state.ClearFindings();

    private async void ExportMd(object? sender, RoutedEventArgs e) => await SaveAsync("Markdown", "md");
    private async void ExportHtml(object? sender, RoutedEventArgs e) => await SaveAsync("HTML", "html");

    private async System.Threading.Tasks.Task SaveAsync(string name, string ext)
    {
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export Sentinel report",
            SuggestedFileName = $"Sentinel-Report.{ext}",
            DefaultExtension = ext,
            FileTypeChoices = new[]
            {
                new FilePickerFileType(name) { Patterns = new[] { $"*.{ext}" } }
            }
        });
        if (file is null) return;
        var path = file.TryGetLocalPath();
        if (string.IsNullOrEmpty(path)) return;
        _state.SaveReport(path);
    }
}
