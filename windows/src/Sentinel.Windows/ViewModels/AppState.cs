using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.ViewModels;

public sealed class AppState : INotifyPropertyChanged
{
    public enum Section { Overview, Network, ThisPc, Persistence, Accounts, Signatures, Findings }

    private Section _section = Section.Overview;
    private bool _authorized;
    private bool _busy;
    private string _status = "Ready. Authorize the scan, then choose Network or This PC.";
    private double _progress;
    private string _phase = "";
    private string _filter = "All";
    private NetworkSnapshot? _snapshot;
    private SignatureDatabase _db = SignatureDatabase.Load();
    private CancellationTokenSource? _cts;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<Finding> Findings { get; } = new();
    public ObservableCollection<Finding> VisibleFindings { get; } = new();
    public ObservableCollection<DiscoveredHost> Hosts { get; } = new();
    public ObservableCollection<UpdateResult> UpdateLog { get; } = new();

    public Section CurrentSection
    {
        get => _section;
        set { _section = value; OnPropertyChanged(); OnPropertyChanged(nameof(Title)); }
    }

    public string Title => CurrentSection switch
    {
        Section.Overview => "Overview",
        Section.Network => "Network",
        Section.ThisPc => "This PC",
        Section.Persistence => "Persistence",
        Section.Accounts => "Accounts",
        Section.Signatures => "Signatures",
        Section.Findings => "Findings",
        _ => "Sentinel"
    };

    public bool Authorized
    {
        get => _authorized;
        set { _authorized = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanScan)); }
    }

    public bool IsBusy
    {
        get => _busy;
        set { _busy = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanScan)); }
    }

    public bool CanScan => Authorized && !IsBusy;

    public string Status
    {
        get => _status;
        set { _status = value; OnPropertyChanged(); }
    }

    public double Progress
    {
        get => _progress;
        set { _progress = value; OnPropertyChanged(); }
    }

    public string Phase
    {
        get => _phase;
        set { _phase = value; OnPropertyChanged(); }
    }

    public string Filter
    {
        get => _filter;
        set { _filter = value; ApplyFilter(); OnPropertyChanged(); }
    }

    public NetworkSnapshot? Snapshot
    {
        get => _snapshot;
        set { _snapshot = value; OnPropertyChanged(); OnPropertyChanged(nameof(NetworkLine)); }
    }

    public string NetworkLine => Snapshot == null
        ? "No interface snapshot yet"
        : $"{Snapshot.InterfaceName}  {Snapshot.IpAddress}/{Snapshot.Cidr}  gw {Snapshot.Gateway ?? "?"}";

    public string SignatureLine
    {
        get
        {
            var s = _db.Stats;
            var when = s.LastUpdated?.ToString("g") ?? "bundled seed only";
            return $"{s.HashCount:N0} hashes · {s.FilenameCount:N0} names · {when}";
        }
    }

    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int HighCount => Findings.Count(f => f.Severity == Severity.High);
    public int MediumCount => Findings.Count(f => f.Severity == Severity.Medium);
    public int FindingCount => Findings.Count;
    public bool IsAdmin => WinHelpers.IsAdministrator;

    public async Task ScanNetworkAsync()
    {
        if (!Authorized) { Status = "Check the authorization box first."; return; }
        if (IsBusy) return;
        IsBusy = true;
        _cts = new CancellationTokenSource();
        try
        {
            Snapshot = NetworkInfoService.Current();
            Phase = "Host discovery";
            var live = await NetworkScanner.DiscoverHostsAsync(Snapshot, Report, _cts.Token);
            Phase = "Port identification";
            var hosts = await NetworkScanner.ScanPortsAsync(live, PortCatalog.DefaultScanPorts, Snapshot.IpAddress, Report, _cts.Token);
            Hosts.Clear();
            foreach (var h in hosts) Hosts.Add(h);
            AddFindings(NetworkScanner.ToFindings(hosts, Snapshot));
            Status = $"Network scan finished. {hosts.Count} live host(s), {Findings.Count} finding(s).";
            CurrentSection = Section.Findings;
        }
        catch (OperationCanceledException)
        {
            Status = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
            Progress = 0;
            Phase = "";
        }
    }

    public async Task ScanThisPcAsync()
    {
        if (!Authorized) { Status = "Check the authorization box first."; return; }
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            await Task.Run(() =>
            {
                Report(new ScanProgress { Phase = "This PC", Completed = 0, Total = 5, StatusLine = "Hardening" });
                var batch = new List<Finding>();
                batch.AddRange(HardeningScanner.Run(Report));
                Report(new ScanProgress { Phase = "This PC", Completed = 1, Total = 5, StatusLine = "Persistence" });
                batch.AddRange(PersistenceScanner.Run(_db, Report));
                Report(new ScanProgress { Phase = "This PC", Completed = 2, Total = 5, StatusLine = "Malware / processes" });
                batch.AddRange(MalwareScanner.Run(_db, Report));
                Report(new ScanProgress { Phase = "This PC", Completed = 3, Total = 5, StatusLine = "Accounts" });
                batch.AddRange(AccountScanner.Run(Report));
                Report(new ScanProgress { Phase = "This PC", Completed = 4, Total = 5, StatusLine = "Event log" });
                batch.AddRange(EventLogScanner.Run(Report));
                Avalonia.Threading.Dispatcher.UIThread.Post(() => AddFindings(batch));
            });
            Status = $"This-PC assessment finished. {Findings.Count} finding(s).";
            CurrentSection = Section.Findings;
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
            Progress = 0;
            Phase = "";
        }
    }

    public async Task FullAsync()
    {
        await ScanNetworkAsync();
        if (Authorized) await ScanThisPcAsync();
    }

    public async Task UpdateSignaturesAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        Status = "Downloading public IOC feeds (nothing is uploaded from this PC)…";
        try
        {
            var (db, results) = await Task.Run(() => SignatureUpdater.UpdateAsync(_db));
            _db = db;
            UpdateLog.Clear();
            foreach (var r in results) UpdateLog.Add(r);
            OnPropertyChanged(nameof(SignatureLine));
            Status = $"Signatures updated. {_db.HashesSha256.Count:N0} hashes.";
        }
        catch (Exception ex)
        {
            Status = "Signature update failed: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void ClearFindings()
    {
        Findings.Clear();
        ApplyFilter();
        RefreshCounts();
    }

    public string ExportMarkdown() => ReportWriter.Markdown(Findings, Snapshot, _db.Stats);
    public string ExportHtml() => ReportWriter.Html(Findings, Snapshot, _db.Stats);

    public void SaveReport(string path)
    {
        var text = path.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ? ExportHtml() : ExportMarkdown();
        File.WriteAllText(path, text);
        Status = "Saved " + path;
    }

    private void AddFindings(IEnumerable<Finding> items)
    {
        foreach (var f in items) Findings.Add(f);
        ApplyFilter();
        RefreshCounts();
    }

    private void ApplyFilter()
    {
        VisibleFindings.Clear();
        IEnumerable<Finding> q = Findings;
        q = Filter switch
        {
            "Critical" => q.Where(f => f.Severity == Severity.Critical),
            "High" => q.Where(f => f.Severity == Severity.High),
            "Medium+" => q.Where(f => f.Severity >= Severity.Medium),
            "This PC" => q.Where(f => f.Host is "this-pc" or null),
            "Network" => q.Where(f => f.Category is FindingCategory.Network or FindingCategory.RemoteAccess),
            _ => q
        };
        foreach (var f in q.OrderByDescending(f => f.Severity).ThenBy(f => f.Title))
            VisibleFindings.Add(f);
    }

    private void RefreshCounts()
    {
        OnPropertyChanged(nameof(CriticalCount));
        OnPropertyChanged(nameof(HighCount));
        OnPropertyChanged(nameof(MediumCount));
        OnPropertyChanged(nameof(FindingCount));
    }

    private void Report(ScanProgress p)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            Phase = p.Phase;
            Progress = p.Fraction;
            Status = p.StatusLine;
        });
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
