using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Interop;
using System.Collections.Generic;
using System.Net.Http;
using Newtonsoft.Json;
using System.Linq;
using System.Windows.Threading;
using System.Text;
using System.Reflection;
using static ModernStealthLauncher.LogEntry;
using System.Windows.Documents;
using System.Globalization;

namespace ModernStealthLauncher
{
    public partial class MainWindow : Window
    {
        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string lpLibFileName);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookExW(int idHook, IntPtr lpfn, IntPtr hmod, uint dwThreadId);
        [DllImport("user32.dll")]
        private static extern bool PostThreadMessageW(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll")]
        private static extern int EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr hWnd, [Out] char[] lpString, int nMaxCount);
        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule, [Out] char[] lpBaseName, uint nSize);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        private bool isTerminalVisible = true;
        private bool lastGameWindowFound = false;
        private bool selectLatestRelease = false;
        private const int WH_GETMESSAGE = 3;
        private const uint WM_NULL = 0x0000;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private Dictionary<string, string> repoUrlMap = new Dictionary<string, string>();
        private Dictionary<string, List<ReleaseInfo>> releasesMap = new Dictionary<string, List<ReleaseInfo>>();
        private List<string> releaseTypes = new List<string> { "Stable", "Beta", "Pre-release" };
        private ReleaseInfo currentReleaseInfo;
        private const int WM_COPYDATA = 0x004A;
        private ReleaseInfo globalLatestRelease = null;

        [StructLayout(LayoutKind.Sequential)]
        public struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public int cbData;
            public IntPtr lpData;
        }

        public MainWindow()
        {
            InitializeComponent();

            InitializeLogger();

            repoUrlMap["Stable"] = "https://api.github.com/repos/D4rkks/r.e.p.o-cheat/releases";
            repoUrlMap["Beta"] = "https://api.github.com/repos/peeberpoober/beta-d.a.r.k.-cheat/releases";
            repoUrlMap["Pre-release"] = "https://api.github.com/repos/hdunl/DarkRepoInjector/releases";

            ReleaseTypeComboBox.ItemsSource = releaseTypes;
            ReleaseTypeComboBox.SelectedIndex = 0;

            NamespaceTextBox.Text = "dark_cheat";
            ClassNameTextBox.Text = "Loader";
            MethodNameTextBox.Text = "Init";

            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            this.MouseDown += Window_MouseDown;

            StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(249, 191, 68));
            StatusText.Text = "Waiting on injection...";

            Task.Run(async () =>
            {
                await FetchReleasesAsync();
                Dispatcher.Invoke(() =>
                {
                    UpdateVersionComboBox();
                });
            });

            var timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(2);
            timer.Tick += RepoStatusTimer_Tick;
            timer.Start();
        }

        private void LatestReleaseCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            selectLatestRelease = true;
            Logger.Instance.Info("Latest Release option selected (across all channels)");
            ReleaseTypeComboBox.IsEnabled = false;
            ReleaseVersionComboBox.IsEnabled = false;

            FindAndSelectGlobalLatestRelease();
        }

        private void LatestReleaseCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            selectLatestRelease = false;
            Logger.Instance.Info("Latest Release option deselected");
            ReleaseTypeComboBox.IsEnabled = true;
            ReleaseVersionComboBox.IsEnabled = true;

            if (ReleaseTypeComboBox.SelectedItem != null)
            {
                UpdateVersionComboBox();
            }
        }

        private void FindAndSelectGlobalLatestRelease()
        {
            globalLatestRelease = null;

            foreach (var type in releaseTypes)
            {
                if (releasesMap.ContainsKey(type) && releasesMap[type].Count > 0)
                {
                    var latestInChannel = releasesMap[type][0];

                    if (globalLatestRelease == null || latestInChannel.PublishedDate > globalLatestRelease.PublishedDate)
                    {
                        globalLatestRelease = latestInChannel;
                    }
                }
            }

            if (globalLatestRelease != null)
            {
                string releaseType = null;
                foreach (var type in releaseTypes)
                {
                    if (releasesMap.ContainsKey(type) &&
                        releasesMap[type].Any(r => r.TagName == globalLatestRelease.TagName && r.AssetName == globalLatestRelease.AssetName))
                    {
                        releaseType = type;
                        break;
                    }
                }

                if (releaseType != null)
                {
                    int typeIndex = releaseTypes.IndexOf(releaseType);
                    if (typeIndex >= 0)
                    {
                        ReleaseTypeComboBox.SelectedIndex = typeIndex;

                        var versions = releasesMap[releaseType].Select(r => r.TagName).ToList();
                        ReleaseVersionComboBox.ItemsSource = versions;

                        int versionIndex = versions.IndexOf(globalLatestRelease.TagName);
                        if (versionIndex >= 0)
                        {
                            ReleaseVersionComboBox.SelectedIndex = versionIndex;
                        }

                        currentReleaseInfo = globalLatestRelease;
                        DllNameText.Text = globalLatestRelease.AssetName;
                        UpdateDefaultNamespace(globalLatestRelease.AssetName);

                        Logger.Instance.Success($"Selected latest release across all channels: {globalLatestRelease.TagName} ({releaseType}) - Published: {globalLatestRelease.PublishedDate}");
                    }
                };
            }
            else
            {
                Logger.Instance.Warning("No releases found in any channel");
            }
        }

        private void AppendLogEntry(LogEntry entry)
        {
            var paragraph = new Paragraph();
            var run = new Run(entry.FormattedText)
            {
                Foreground = entry.Color
            };
            paragraph.Inlines.Add(run);

            LogRichTextBox.Document.Blocks.Add(paragraph);
            LogRichTextBox.CaretPosition = LogRichTextBox.Document.ContentEnd;

            Dispatcher.InvokeAsync(() =>
            {
                LogScrollViewer.ScrollToEnd();
            }, DispatcherPriority.Background);
        }

        private void InitializeLogger()
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(InitializeLogger);
                return;
            }

            try
            {
                Logger.Instance.OnLogAdded += (sender, entry) =>
                {
                    Dispatcher.InvokeAsync(() => AppendLogEntry(entry), DispatcherPriority.Background);
                };

                CheckAndClearLogFile();

                Logger.Instance.Info($"System initialized");
                Logger.Instance.Info($"OS: {Environment.OSVersion}");
                Logger.Instance.Info($"Machine: {Environment.MachineName}");
                Logger.Instance.Info($"Launcher Version: {Assembly.GetExecutingAssembly().GetName().Version}");
                Logger.Instance.Debug($"Repository URLs loaded: {repoUrlMap.Count}");
                Logger.Instance.Info($"Loading repositories...");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing logger: {ex.Message}");
            }
        }

        private void CopySelectedButton_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(LogRichTextBox.Selection.Text))
            {
                Clipboard.SetText(LogRichTextBox.Selection.Text);
                Logger.Instance.Info("Selected text copied to clipboard");
            }
            else
            {
                Logger.Instance.Warning("No text selected to copy");
            }
        }

        private void CopyAllButton_Click(object sender, RoutedEventArgs e)
        {
            LogRichTextBox.SelectAll();
            Clipboard.SetText(LogRichTextBox.Selection.Text);
            Logger.Instance.Info("All terminal text copied to clipboard");
        }

        private void CheckAndClearLogFile()
        {
            try
            {
                string appDataPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "ModernStealthLauncher");

                string runCountFile = Path.Combine(appDataPath, "run_count.txt");
                int runCount = 1;

                Directory.CreateDirectory(appDataPath);

                if (File.Exists(runCountFile))
                {
                    string countText = File.ReadAllText(runCountFile);
                    if (int.TryParse(countText, out int savedCount))
                    {
                        runCount = savedCount + 1;
                    }
                }

                File.WriteAllText(runCountFile, runCount.ToString());

                Logger.Instance.Debug($"Application run count: {runCount}");

                if (runCount % 3 == 0)
                {
                    string logFilePath = Path.Combine(appDataPath, "launcher.log");
                    if (File.Exists(logFilePath))
                    {
                        File.WriteAllText(logFilePath, string.Empty);
                        Logger.Instance.Info("Log file cleared (automatic maintenance)");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Error($"Error managing log file: {ex.Message}");
            }
        }

        private void OpenDebugLogsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ModernStealthLauncher");
                string launcherLogPath = Path.Combine(appDataPath, "launcher.log");

                string monoLoaderLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MonoLoader.log");

                if (File.Exists(launcherLogPath))
                {
                    Process.Start("notepad.exe", launcherLogPath);
                }
                else
                {
                    MessageBox.Show($"Launcher log file not found:\n{launcherLogPath}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                if (File.Exists(monoLoaderLogPath))
                {
                    Process.Start("notepad.exe", monoLoaderLogPath);
                }
                else
                {
                    MessageBox.Show($"MonoLoader log file not found:\n{monoLoaderLogPath}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open debug logs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);

            var windowInteropHelper = new WindowInteropHelper(this);
            IntPtr handle = windowInteropHelper.Handle;

            HwndSource source = HwndSource.FromHwnd(handle);
            source.AddHook(WndProc);

            Logger.Instance.Debug("Message handler initialized");
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_COPYDATA)
            {
                try
                {
                    COPYDATASTRUCT cds = (COPYDATASTRUCT)Marshal.PtrToStructure(lParam, typeof(COPYDATASTRUCT));

                    if (cds.dwData.ToInt32() == 0x1234 && cds.cbData > 0)
                    {
                        string receivedMessage = Marshal.PtrToStringAnsi(cds.lpData);

                        string[] parts = receivedMessage.Split(new char[] { '|' }, 2);
                        if (parts.Length == 2)
                        {
                            int level = int.Parse(parts[0]);
                            string message = parts[1];

                            switch (level)
                            {
                                case 0:
                                    Logger.Instance.Info("(DLL) " + message);
                                    break;
                                case 1:
                                    Logger.Instance.Success("(DLL) " + message);
                                    break;
                                case 2:
                                    Logger.Instance.Warning("(DLL) " + message);
                                    break;
                                case 3:
                                    Logger.Instance.Error("(DLL) " + message);
                                    break;
                                case 4:
                                    Logger.Instance.Debug("(DLL) " + message);
                                    break;
                                default:
                                    Logger.Instance.Info("(DLL) " + message);
                                    break;
                            }
                        }

                        handled = true;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error($"Error processing message from DLL: {ex.Message}");
                }
            }

            return IntPtr.Zero;
        }

        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            Logger.Instance.Clear();
            Logger.Instance.Info("Log cleared");
        }

        private void ToggleTerminalButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                isTerminalVisible = !isTerminalVisible;
                TerminalPanel.Visibility = isTerminalVisible ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error toggling terminal: {ex.Message}");
            }
        }

        private void RepoStatusTimer_Tick(object sender, EventArgs e)
        {
            try
            {
                IntPtr window = FindREPOGameWindow();
                bool currentGameWindowFound = window != IntPtr.Zero;

                if (currentGameWindowFound != lastGameWindowFound)
                {
                    Dispatcher.Invoke(() =>
                    {
                        if (currentGameWindowFound)
                        {
                            RepoStatusIndicator.Fill = Brushes.LimeGreen;
                            RepoStatusText.Text = "REPO Found";
                            Logger.Instance.Success("Game process detected");
                        }
                        else
                        {
                            RepoStatusIndicator.Fill = Brushes.Red;
                            RepoStatusText.Text = "REPO Not Found";
                            Logger.Instance.Warning("Game process not detected - waiting for game to start");
                        }
                    });

                    lastGameWindowFound = currentGameWindowFound;
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    RepoStatusIndicator.Fill = Brushes.Red;
                    RepoStatusText.Text = "Error checking REPO";
                    Logger.Instance.Error($"RepoStatusTimer_Tick error: {ex.Message}");
                });
            }
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.ButtonState == MouseButtonState.Pressed)
                if (e.GetPosition(this).Y < 40)
                    this.DragMove();
        }

        private async Task FetchReleasesAsync()
        {
            Logger.Instance.Info("Fetching releases from GitHub repositories...");

            releasesMap.Clear();

            foreach (var type in releaseTypes)
            {
                var url = repoUrlMap[type];
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("ModernStealthLauncher");
                    try
                    {
                        Logger.Instance.Debug($"Requesting {type} releases from: {url}");
                        var json = await client.GetStringAsync(url);
                        var releases = JsonConvert.DeserializeObject<List<dynamic>>(json);
                        var list = new List<ReleaseInfo>();
                        foreach (var rel in releases)
                        {
                            string tag = rel.tag_name;
                            DateTime publishedDate = DateTime.Parse((string)rel.published_at, CultureInfo.InvariantCulture);

                            foreach (var asset in rel.assets)
                            {
                                string name = asset.name;
                                if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                                    !name.Equals("SharpMonoInjector.dll", StringComparison.OrdinalIgnoreCase))
                                {
                                    string downloadUrl = asset.browser_download_url;
                                    list.Add(new ReleaseInfo
                                    {
                                        TagName = tag,
                                        AssetName = name,
                                        DownloadUrl = downloadUrl,
                                        PublishedDate = publishedDate
                                    });
                                    Logger.Instance.Debug($"Found release: {tag} - {name} - {publishedDate}");
                                    break;
                                }
                            }
                        }

                        // Sort the releases by published date, newest first
                        list = list.OrderByDescending(r => r.PublishedDate).ToList();
                        releasesMap[type] = list;
                        Logger.Instance.Success($"Found {list.Count} {type} releases");
                    }
                    catch (Exception ex)
                    {
                        Logger.Instance.Error($"Failed to fetch {type} releases: {ex.Message}");
                        releasesMap[type] = new List<ReleaseInfo>();
                    }
                }
            }

            // After fetching all releases, check if we need to select the global latest
            if (selectLatestRelease)
            {
                Dispatcher.Invoke(() => {
                    FindAndSelectGlobalLatestRelease();
                });
            }
        }

        private void UpdateVersionComboBox()
        {
            if (selectLatestRelease)
                return;

            string selectedType = ReleaseTypeComboBox.SelectedItem.ToString();
            Logger.Instance.Debug($"Updating version combobox for type: {selectedType}");

            if (releasesMap.ContainsKey(selectedType))
            {
                var releases = releasesMap[selectedType];
                var versions = releases.Select(r => r.TagName).ToList();
                ReleaseVersionComboBox.ItemsSource = versions;

                if (versions.Count > 0)
                {
                    if (selectLatestRelease)
                    {
                        ReleaseVersionComboBox.SelectedIndex = 0;
                        Logger.Instance.Info($"Selected latest version: {versions[0]}");
                    }
                    else if (ReleaseVersionComboBox.SelectedIndex < 0)
                    {
                        ReleaseVersionComboBox.SelectedIndex = 0;
                    }

                    string selectedVersion = ReleaseVersionComboBox.SelectedItem as string;
                    currentReleaseInfo = releases.FirstOrDefault(r => r.TagName == selectedVersion);

                    if (currentReleaseInfo != null)
                    {
                        DllNameText.Text = currentReleaseInfo.AssetName;
                        UpdateDefaultNamespace(currentReleaseInfo.AssetName);
                        Logger.Instance.Info($"Selected version: {currentReleaseInfo.TagName}, DLL: {currentReleaseInfo.AssetName}");
                    }
                }
                else
                {
                    ReleaseVersionComboBox.ItemsSource = null;
                    currentReleaseInfo = null;
                    DllNameText.Text = "-";
                    Logger.Instance.Warning($"No versions available for {selectedType}");
                }
            }
        }

        private void ReleaseType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ReleaseTypeComboBox.SelectedItem != null && !selectLatestRelease)
            {
                Logger.Instance.Info($"Selected release type: {ReleaseTypeComboBox.SelectedItem}");
                UpdateVersionComboBox();
            }
        }

        private void ReleaseVersion_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ReleaseTypeComboBox.SelectedItem != null && ReleaseVersionComboBox.SelectedItem != null)
            {
                string selectedType = ReleaseTypeComboBox.SelectedItem.ToString();
                string selectedVersion = ReleaseVersionComboBox.SelectedItem.ToString();
                Logger.Instance.Info($"Selected version: {selectedVersion}");

                if (releasesMap.ContainsKey(selectedType))
                {
                    var list = releasesMap[selectedType];
                    string selectedTag = ReleaseVersionComboBox.SelectedItem as string;
                    currentReleaseInfo = list.FirstOrDefault(r => r.TagName == selectedTag);
                    if (currentReleaseInfo != null)
                    {
                        DllNameText.Text = currentReleaseInfo.AssetName;
                        UpdateDefaultNamespace(currentReleaseInfo.AssetName);
                        Logger.Instance.Debug($"DLL: {currentReleaseInfo.AssetName}, URL: {currentReleaseInfo.DownloadUrl}");
                    }
                }
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Logger.Instance.Info("Application closing");
            this.Close();
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void LaunchButton_Click(object sender, RoutedEventArgs e)
        {
            string ns = NamespaceTextBox.Text;
            string cls = ClassNameTextBox.Text;
            string mth = MethodNameTextBox.Text;

            Logger.Instance.Info($"Starting injection process...");
            Logger.Instance.Debug($"Namespace: {ns}, Class: {cls}, Method: {mth}");

            if (!Logger.Instance.CheckFileAccessBeforeInjection())
            {
                MessageBox.Show("Cannot access log files. Close any other running launcher instances and try again.", "File Access Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Logger.Instance.ResetInjectionStatus();

            LaunchIndicator.Visibility = Visibility.Visible;
            LaunchIndicator.IsIndeterminate = true;
            Dispatcher.Invoke(() =>
            {
                StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(249, 191, 68));
                StatusText.Text = "Injecting...";
            });

            EventHandler<bool> fileAccessStatusHandler = null;
            fileAccessStatusHandler = (sender, canAccess) =>
            {
                if (!canAccess)
                {
                    Logger.Instance.OnFileAccessStatusChanged -= fileAccessStatusHandler;
                    Dispatcher.Invoke(() =>
                    {
                        LaunchIndicator.Visibility = Visibility.Collapsed;
                        LaunchIndicator.IsIndeterminate = false;
                        StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(232, 17, 35));
                        StatusText.Text = "Injection Failed - Log Files Locked";
                        Logger.Instance.Warning("Injection aborted - log files are locked by another process");
                        MessageBox.Show("Injection aborted because log files are locked by another process. Close any other running launcher instances and try again.", "File Access Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    });
                }
            };

            EventHandler<bool> injectionStatusHandler = null;
            injectionStatusHandler = (sender, successful) =>
            {
                Logger.Instance.OnInjectionStatusChanged -= injectionStatusHandler;
                Logger.Instance.OnFileAccessStatusChanged -= fileAccessStatusHandler;

                Dispatcher.Invoke(() =>
                {
                    LaunchIndicator.Visibility = Visibility.Collapsed;
                    LaunchIndicator.IsIndeterminate = false;

                    if (successful)
                    {
                        StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 210, 106));
                        StatusText.Text = "Injection Successful";
                        Logger.Instance.Success("Cheat injected successfully");
                        MessageBox.Show("Cheat injected successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(232, 17, 35));
                        StatusText.Text = "Injection Failed";
                        Logger.Instance.Error("Injection failed based on MonoLoader output");
                        MessageBox.Show("Injection failed. Check the logs for details.", "Launch Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                });
            };

            Logger.Instance.OnFileAccessStatusChanged += fileAccessStatusHandler;
            Logger.Instance.OnInjectionStatusChanged += injectionStatusHandler;

            Task.Run(() =>
            {
                try
                {
                    Logger.Instance.Info("Checking game process...");
                    IntPtr gameWindow = FindREPOGameWindow();
                    if (gameWindow == IntPtr.Zero)
                    {
                        throw new Exception("REPO game window not found.");
                    }
                    Logger.Instance.Success("Game window found");

                    LaunchCheat(ns, cls, mth);

                    Task.Delay(5000).Wait();

                    if (!Logger.Instance.IsInjectionSuccessful() && !Logger.Instance.IsInjectionFailed())
                    {
                        Logger.Instance.OnInjectionStatusChanged -= injectionStatusHandler;
                        Logger.Instance.OnFileAccessStatusChanged -= fileAccessStatusHandler;

                        Dispatcher.Invoke(() =>
                        {
                            LaunchIndicator.Visibility = Visibility.Collapsed;
                            LaunchIndicator.IsIndeterminate = false;
                            StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(232, 17, 35));
                            StatusText.Text = "Injection Status Unknown";
                            Logger.Instance.Warning("No injection status reported by MonoLoader");
                            MessageBox.Show("Injection status unknown. Check the logs for details.", "Launch Status", MessageBoxButton.OK, MessageBoxImage.Warning);
                        });
                    }
                }
                catch (Exception ex)
                {
                    Logger.Instance.OnInjectionStatusChanged -= injectionStatusHandler;
                    Logger.Instance.OnFileAccessStatusChanged -= fileAccessStatusHandler;

                    Dispatcher.Invoke(() =>
                    {
                        LaunchIndicator.Visibility = Visibility.Collapsed;
                        LaunchIndicator.IsIndeterminate = false;
                        StatusIndicator.Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(232, 17, 35));
                        StatusText.Text = "Injection Failed";
                        Logger.Instance.Error($"Injection failed: {ex.Message}");
                        MessageBox.Show($"Error: {ex.Message}", "Launch Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            });
        }

        private IntPtr FindREPOGameWindow()
        {
            IntPtr gameWindow = IntPtr.Zero;

            EnumWindows(new EnumWindowsProc((hWnd, lParam) =>
            {
                try
                {
                    char[] buffer = new char[256];
                    GetWindowTextW(hWnd, buffer, buffer.Length);
                    string title = new string(buffer).TrimEnd('\0');

                    if (string.Equals(title, "R.E.P.O.", StringComparison.OrdinalIgnoreCase))
                    {
                        GetWindowThreadProcessId(hWnd, out uint processId);
                        if (processId != 0)
                        {
                            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
                            if (processHandle != IntPtr.Zero)
                            {
                                char[] exeName = new char[1024];
                                if (GetModuleBaseNameW(processHandle, IntPtr.Zero, exeName, (uint)exeName.Length) > 0)
                                {
                                    string processName = new string(exeName).TrimEnd('\0');
                                    if (string.Equals(processName, "REPO.exe", StringComparison.OrdinalIgnoreCase))
                                    {
                                        gameWindow = hWnd;
                                        CloseHandle(processHandle);
                                        return false;
                                    }
                                }
                                CloseHandle(processHandle);
                            }
                        }
                    }
                }
                catch { }
                return true;
            }), IntPtr.Zero);

            return gameWindow;
        }

        private bool DownloadDLLFromGitHub(ReleaseInfo release)
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                string directory = Path.GetDirectoryName(exePath);
                string dllPath = System.IO.Path.Combine(directory, release.AssetName);

                Logger.Instance.Info($"Downloading {release.AssetName} from GitHub...");

                using (var client = new System.Net.WebClient())
                {
                    client.DownloadFile(release.DownloadUrl, dllPath);
                }

                bool exists = File.Exists(dllPath);
                if (exists)
                {
                    Logger.Instance.Success($"DLL downloaded successfully: {dllPath}");
                }
                else
                {
                    Logger.Instance.Error($"DLL download failed, file does not exist: {dllPath}");
                }

                return exists;
            }
            catch (Exception ex)
            {
                Logger.Instance.Error($"Failed to download DLL: {ex.Message}");
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"Failed to download DLL: {ex.Message}", "Download Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return false;
            }
        }

        private void LaunchCheat(string ns, string cls, string mth)
        {
            Logger.Instance.Info("Starting cheat injection process");

            IntPtr gameWindow = FindREPOGameWindow();
            if (gameWindow == IntPtr.Zero)
            {
                throw new Exception("REPO game window not found.");
            }

            uint threadId = GetWindowThreadProcessId(gameWindow, IntPtr.Zero);
            if (threadId == 0)
            {
                throw new Exception("Failed to get thread ID.");
            }

            if (currentReleaseInfo == null)
            {
                throw new Exception("No release selected.");
            }

            Logger.Instance.Info($"Downloading DLL from GitHub: {currentReleaseInfo.AssetName}");
            if (!DownloadDLLFromGitHub(currentReleaseInfo))
            {
                throw new Exception($"Could not download {currentReleaseInfo.AssetName} from GitHub");
            }

            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            string directory = Path.GetDirectoryName(exePath);
            string dllName = currentReleaseInfo.AssetName;
            string dllSourcePath = Path.Combine(directory, dllName);

            string tempDir = Path.Combine(Path.GetTempPath(), "MonoStealthLauncher");
            Directory.CreateDirectory(tempDir);

            string monoLoaderPath = Path.Combine(tempDir, "MonoLoader.dll");

            ExtractEmbeddedDll("ModernStealthLauncher.Resources.MonoLoader.dll", monoLoaderPath);

            if (!File.Exists(monoLoaderPath))
            {
                throw new Exception($"MonoLoader.dll not found: {monoLoaderPath}");
            }

            string configPath = Path.Combine(tempDir, "temp_config.bin");
            File.WriteAllText(configPath, $"{dllName}|{ns}|{cls}|{mth}");

            string targetDllPath = Path.Combine(tempDir, dllName);
            File.Copy(dllSourcePath, targetDllPath, true);

            IntPtr hLocalDll = LoadLibraryW(monoLoaderPath);
            if (hLocalDll == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception($"LoadLibrary failed with error code: {error}");
            }

            IntPtr hookProc = GetProcAddress(hLocalDll, "HookProc");
            if (hookProc == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception($"GetProcAddress failed with error code: {error}");
            }

            IntPtr hook = SetWindowsHookExW(WH_GETMESSAGE, hookProc, hLocalDll, threadId);
            if (hook == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception($"SetWindowsHookEx failed with error code: {error}");
            }

            PostThreadMessageW(threadId, WM_NULL, IntPtr.Zero, IntPtr.Zero);
            System.Threading.Thread.Sleep(1000);
            UnhookWindowsHookEx(hook);
            Logger.Instance.Success("Injection process completed");
        }

        private void ExtractEmbeddedDll(string resourceName, string outputPath)
        {
            if (File.Exists(outputPath))
                return;

            Logger.Instance.Info($"Extracting resource: {resourceName}");

            using (Stream resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
            {
                if (resourceStream == null)
                    throw new Exception($"Resource not found: {resourceName}");

                using (FileStream fileStream = new FileStream(outputPath, FileMode.Create))
                {
                    resourceStream.CopyTo(fileStream);
                }
                Logger.Instance.Success($"Resource extracted: {outputPath}");
            }
        }

        private void UpdateDefaultNamespace(string dllName)
        {
            if (string.IsNullOrEmpty(dllName))
                return;

            Logger.Instance.Debug($"Updating default namespace based on DLL: {dllName}");

            string loweredDllName = dllName.ToLowerInvariant();

            if (loweredDllName.Contains("r.e.p.o.cheat"))
            {
                NamespaceTextBox.Text = "r.e.p.o_cheat";
                Logger.Instance.Info("Set namespace to r.e.p.o_cheat based on DLL name");
            }
            else if (loweredDllName.Contains("dark_cheat"))
            {
                NamespaceTextBox.Text = "dark_cheat";
                Logger.Instance.Info("Set namespace to dark_cheat based on DLL name");
            }
        }
    }

    public class ReleaseInfo
    {
        public string TagName { get; set; }
        public string AssetName { get; set; }
        public string DownloadUrl { get; set; }
        public DateTime PublishedDate { get; set; }
    }
}
