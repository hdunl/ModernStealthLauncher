using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace ModernStealthLauncher
{
    public enum LogLevel
    {
        Info,
        Success,
        Warning,
        Error,
        Debug,
        MonoLoader
    }

    public class LogEntry
    {
        public string Prefix { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
        public Brush Color { get; set; }
        public string OriginalLogLine { get; set; }

        public string FormattedText => $"[{Timestamp:HH:mm:ss}] {Prefix}{Message}";

        public LogEntry(string message, LogLevel level = LogLevel.Info)
        {
            Prefix = "$ ";
            Message = message;
            Timestamp = DateTime.Now;
            OriginalLogLine = message;

            switch (level)
            {
                case LogLevel.Info:
                    Color = Brushes.White;
                    break;
                case LogLevel.Success:
                    Color = Brushes.LimeGreen;
                    break;
                case LogLevel.Warning:
                    Color = Brushes.Orange;
                    break;
                case LogLevel.Error:
                    Color = Brushes.Red;
                    break;
                case LogLevel.Debug:
                    Color = Brushes.SkyBlue;
                    break;
                case LogLevel.MonoLoader:
                    Color = Brushes.LightGray;
                    break;
            }
        }
    }

    public class Logger
    {
        private static Logger _instance;
        private static readonly object _lock = new object();

        public ObservableCollection<LogEntry> LogEntries { get; }

        public event EventHandler<LogEntry> OnLogAdded;
        public event EventHandler<bool> OnInjectionStatusChanged;
        public event EventHandler<bool> OnFileAccessStatusChanged;

        private string _logFilePath;
        private string _monoLoaderLogPath;
        private bool _isFileLoggingEnabled;
        private Dispatcher _uiDispatcher;
        private long _lastMonoLoaderPosition = 0;
        private FileSystemWatcher _monoLoaderWatcher;
        private HashSet<string> _processedMonoLoaderEntries = new HashSet<string>();
        private Regex _monoLoaderTimestampRegex = new Regex(@"\[([\d-]+\s[\d:]+)\]\s\[(\w+)\]");
        private bool _injectionInProgress = false;
        private bool _injectionSuccessful = false;
        private bool _injectionFailed = false;
        private DateTime _lastInjectionStartTime = DateTime.MinValue;
        private bool _monoLoaderFileError = false;
        private DateTime _lastFileErrorTime = DateTime.MinValue;
        private object _fileAccessLock = new object();
        private bool _canAccessLogs = true;
        private int _fileAccessRetryCount = 0;
        private const int MAX_FILE_ACCESS_RETRIES = 3;
        private Task _fileAccessCheckTask = null;

        private Logger()
        {
            _uiDispatcher = Application.Current?.Dispatcher;

            LogEntries = new ObservableCollection<LogEntry>();

            string appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ModernStealthLauncher");

            Directory.CreateDirectory(appDataPath);
            _logFilePath = Path.Combine(appDataPath, "launcher.log");
            _monoLoaderLogPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "MonoLoader.log");
            _isFileLoggingEnabled = true;

            InitializeMonoLoaderWatcher();
            StartFileAccessChecks();
        }

        private void StartFileAccessChecks()
        {
            _fileAccessCheckTask = Task.Run(async () =>
            {
                while (true)
                {
                    CheckLogFileAccess();
                    await Task.Delay(5000);
                }
            });
        }

        private void CheckLogFileAccess()
        {
            bool previousCanAccessLogs = _canAccessLogs;
            bool currentCanAccessLogs = true;

            try
            {
                if (File.Exists(_monoLoaderLogPath))
                {
                    try
                    {
                        using (FileStream fs = new FileStream(_monoLoaderLogPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                        {
                        }
                    }
                    catch
                    {
                        currentCanAccessLogs = false;
                    }
                }

                if (File.Exists(_logFilePath))
                {
                    try
                    {
                        using (FileStream fs = new FileStream(_logFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                        {
                        }
                    }
                    catch
                    {
                        currentCanAccessLogs = false;
                    }
                }

                if (currentCanAccessLogs != previousCanAccessLogs)
                {
                    _canAccessLogs = currentCanAccessLogs;
                    OnFileAccessStatusChanged?.Invoke(this, currentCanAccessLogs);

                    if (currentCanAccessLogs)
                    {
                        Info("Log files are now accessible");
                        _fileAccessRetryCount = 0;

                        if (_monoLoaderFileError)
                        {
                            RestartMonoLoaderWatcher();
                        }
                    }
                    else
                    {
                        Warning("Log files are locked by another process - injection blocked until files are accessible");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug($"Error checking log file access: {ex.Message}");
            }
        }

        public bool CanAccessLogFiles()
        {
            return _canAccessLogs;
        }

        private void ReleaseFileLocks()
        {
            try
            {
                if (_monoLoaderWatcher != null)
                {
                    _monoLoaderWatcher.EnableRaisingEvents = false;
                }
            }
            catch
            {
            }
        }

        private void InitializeMonoLoaderWatcher()
        {
            try
            {
                if (File.Exists(_monoLoaderLogPath))
                {
                    ImportExistingMonoLoaderLogs();
                }

                string monoLoaderDir = Path.GetDirectoryName(_monoLoaderLogPath);
                if (!Directory.Exists(monoLoaderDir))
                {
                    Directory.CreateDirectory(monoLoaderDir);
                }

                _monoLoaderWatcher = new FileSystemWatcher(monoLoaderDir)
                {
                    Filter = Path.GetFileName(_monoLoaderLogPath),
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
                };

                _monoLoaderWatcher.Changed += OnMonoLoaderLogChanged;
                _monoLoaderWatcher.Created += OnMonoLoaderLogChanged;
                _monoLoaderWatcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                Debug($"Error initializing MonoLoader watcher: {ex.Message}");
                _monoLoaderFileError = true;
            }
        }

        private void RestartMonoLoaderWatcher()
        {
            lock (_fileAccessLock)
            {
                if (_monoLoaderWatcher != null)
                {
                    _monoLoaderWatcher.EnableRaisingEvents = false;
                    _monoLoaderWatcher.Changed -= OnMonoLoaderLogChanged;
                    _monoLoaderWatcher.Created -= OnMonoLoaderLogChanged;
                    _monoLoaderWatcher.Dispose();
                    _monoLoaderWatcher = null;
                }

                try
                {
                    string monoLoaderDir = Path.GetDirectoryName(_monoLoaderLogPath);
                    if (!Directory.Exists(monoLoaderDir))
                    {
                        Directory.CreateDirectory(monoLoaderDir);
                    }

                    _monoLoaderWatcher = new FileSystemWatcher(monoLoaderDir)
                    {
                        Filter = Path.GetFileName(_monoLoaderLogPath),
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
                    };

                    _monoLoaderWatcher.Changed += OnMonoLoaderLogChanged;
                    _monoLoaderWatcher.Created += OnMonoLoaderLogChanged;
                    _monoLoaderWatcher.EnableRaisingEvents = true;
                    _monoLoaderFileError = false;
                    Debug("MonoLoader watcher restarted successfully");
                }
                catch (Exception ex)
                {
                    Debug($"Error restarting MonoLoader watcher: {ex.Message}");
                    _monoLoaderFileError = true;
                }
            }
        }

        private void ImportExistingMonoLoaderLogs()
        {
            try
            {
                lock (_fileAccessLock)
                {
                    if (!File.Exists(_monoLoaderLogPath))
                    {
                        return;
                    }

                    string[] existingLogs = File.ReadAllLines(_monoLoaderLogPath);
                    List<Tuple<DateTime, string, LogLevel>> sortedEntries = new List<Tuple<DateTime, string, LogLevel>>();

                    foreach (string line in existingLogs)
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                        {
                            var match = _monoLoaderTimestampRegex.Match(line);
                            if (match.Success)
                            {
                                string timestampStr = match.Groups[1].Value;
                                string levelStr = match.Groups[2].Value;
                                DateTime timestamp;
                                if (DateTime.TryParse(timestampStr, out timestamp))
                                {
                                    LogLevel level = DetermineMonoLoaderLogLevelFromString(levelStr);
                                    sortedEntries.Add(new Tuple<DateTime, string, LogLevel>(timestamp, line, level));
                                }
                            }
                        }
                    }

                    sortedEntries.Sort((a, b) => a.Item1.CompareTo(b.Item1));

                    foreach (var entry in sortedEntries)
                    {
                        LogMonoLoaderEntry(entry.Item2, entry.Item3, entry.Item1);
                    }

                    _lastMonoLoaderPosition = new FileInfo(_monoLoaderLogPath).Length;
                }
            }
            catch (Exception ex)
            {
                Debug($"Error importing MonoLoader logs: {ex.Message}");
                _monoLoaderFileError = true;
            }
        }

        private void OnMonoLoaderLogChanged(object sender, FileSystemEventArgs e)
        {
            lock (_fileAccessLock)
            {
                if (_monoLoaderFileError)
                {
                    if ((DateTime.Now - _lastFileErrorTime).TotalSeconds < 5)
                    {
                        return;
                    }

                    RestartMonoLoaderWatcher();
                }

                try
                {
                    Task.Delay(100).Wait();

                    if (!File.Exists(_monoLoaderLogPath))
                    {
                        return;
                    }

                    using (FileStream fs = new FileStream(_monoLoaderLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        if (fs.Length <= _lastMonoLoaderPosition)
                        {
                            _lastMonoLoaderPosition = 0;
                        }

                        if (_lastMonoLoaderPosition < fs.Length)
                        {
                            fs.Seek(_lastMonoLoaderPosition, SeekOrigin.Begin);
                            using (StreamReader reader = new StreamReader(fs))
                            {
                                string newContent = reader.ReadToEnd();
                                string[] lines = newContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                List<Tuple<DateTime, string, LogLevel>> newEntries = new List<Tuple<DateTime, string, LogLevel>>();

                                foreach (string line in lines)
                                {
                                    if (!string.IsNullOrWhiteSpace(line) && !_processedMonoLoaderEntries.Contains(line))
                                    {
                                        var match = _monoLoaderTimestampRegex.Match(line);
                                        if (match.Success)
                                        {
                                            string timestampStr = match.Groups[1].Value;
                                            string levelStr = match.Groups[2].Value;
                                            DateTime timestamp;
                                            if (DateTime.TryParse(timestampStr, out timestamp))
                                            {
                                                LogLevel level = DetermineMonoLoaderLogLevelFromString(levelStr);
                                                newEntries.Add(new Tuple<DateTime, string, LogLevel>(timestamp, line, level));
                                                CheckInjectionStatus(line, level, timestamp);
                                            }
                                        }
                                    }
                                }

                                newEntries.Sort((a, b) => a.Item1.CompareTo(b.Item1));

                                foreach (var entry in newEntries)
                                {
                                    LogMonoLoaderEntry(entry.Item2, entry.Item3, entry.Item1);
                                }
                            }
                            _lastMonoLoaderPosition = fs.Length;
                        }
                    }

                    _monoLoaderFileError = false;
                }
                catch (Exception ex)
                {
                    if (!_monoLoaderFileError || (DateTime.Now - _lastFileErrorTime).TotalSeconds > 5)
                    {
                        _fileAccessRetryCount++;

                        if (_fileAccessRetryCount <= MAX_FILE_ACCESS_RETRIES)
                        {
                            Debug($"MonoLoader file access error (attempt {_fileAccessRetryCount}): {ex.Message}");
                        }

                        _monoLoaderFileError = true;
                        _lastFileErrorTime = DateTime.Now;

                        if (_fileAccessRetryCount > MAX_FILE_ACCESS_RETRIES)
                        {
                            _canAccessLogs = false;
                            OnFileAccessStatusChanged?.Invoke(this, false);
                        }
                    }
                }
            }
        }

        private void CheckInjectionStatus(string logLine, LogLevel level, DateTime timestamp)
        {
            if ((DateTime.Now - timestamp).TotalSeconds > 30)
                return;

            if (logLine.Contains("Starting assembly injection") || logLine.Contains("Starting injection"))
            {
                _injectionInProgress = true;
                _injectionSuccessful = false;
                _injectionFailed = false;
                _lastInjectionStartTime = timestamp;
                Debug("Injection process started");
            }
            else if (_injectionInProgress)
            {
                if (logLine.Contains("Injection completed successfully"))
                {
                    _injectionInProgress = false;
                    _injectionSuccessful = true;
                    OnInjectionStatusChanged?.Invoke(this, true);
                    Debug("Injection completed successfully");
                }
                else if (logLine.Contains("ERROR") || logLine.Contains("FAILED") ||
                         logLine.Contains("Exception") || logLine.Contains("failed") ||
                         logLine.Contains("error") || level == LogLevel.Error)
                {
                    _injectionInProgress = false;
                    _injectionFailed = true;
                    OnInjectionStatusChanged?.Invoke(this, false);
                    Debug($"Injection failed: {logLine}");
                }
                else if ((timestamp - _lastInjectionStartTime).TotalSeconds > 10 &&
                         !_injectionSuccessful && !_injectionFailed)
                {
                    _injectionInProgress = false;
                    _injectionFailed = true;
                    OnInjectionStatusChanged?.Invoke(this, false);
                    Warning("Injection timed out with no success confirmation");
                }
            }
        }

        private void LogMonoLoaderEntry(string logLine, LogLevel level = LogLevel.MonoLoader, DateTime? timestamp = null)
        {
            if (_processedMonoLoaderEntries.Contains(logLine))
            {
                return;
            }

            _processedMonoLoaderEntries.Add(logLine);

            var entry = new LogEntry(ExtractMonoLoaderMessage(logLine), level);
            entry.Prefix = "[MonoLoader] ";

            if (timestamp.HasValue)
            {
                entry.Timestamp = timestamp.Value;
            }
            else
            {
                var match = _monoLoaderTimestampRegex.Match(logLine);
                if (match.Success)
                {
                    string timestampStr = match.Groups[1].Value;
                    DateTime parsedTime;
                    if (DateTime.TryParse(timestampStr, out parsedTime))
                    {
                        entry.Timestamp = parsedTime;
                    }
                }
            }

            entry.OriginalLogLine = logLine;

            if (_uiDispatcher != null && !_uiDispatcher.CheckAccess())
            {
                _uiDispatcher.Invoke(() =>
                {
                    LogEntries.Add(entry);
                    OnLogAdded?.Invoke(this, entry);
                });
            }
            else
            {
                LogEntries.Add(entry);
                OnLogAdded?.Invoke(this, entry);
            }
        }

        private string ExtractMonoLoaderMessage(string logLine)
        {
            var match = _monoLoaderTimestampRegex.Match(logLine);
            if (match.Success && match.Index > 0)
            {
                int startIndex = match.Index;
                return logLine.Substring(startIndex);
            }
            return logLine;
        }

        private LogLevel DetermineMonoLoaderLogLevel(string logLine)
        {
            var match = _monoLoaderTimestampRegex.Match(logLine);
            if (match.Success)
            {
                string levelStr = match.Groups[2].Value;
                return DetermineMonoLoaderLogLevelFromString(levelStr);
            }

            if (logLine.Contains("ERROR") || logLine.Contains("FAILED") || logLine.Contains("Exception"))
            {
                return LogLevel.Error;
            }
            else if (logLine.Contains("WARNING"))
            {
                return LogLevel.Warning;
            }
            else if (logLine.Contains("SUCCESS") || logLine.Contains("Successfully"))
            {
                return LogLevel.Success;
            }
            else if (logLine.Contains("DEBUG"))
            {
                return LogLevel.Debug;
            }

            return LogLevel.MonoLoader;
        }

        private LogLevel DetermineMonoLoaderLogLevelFromString(string levelStr)
        {
            switch (levelStr.ToUpper())
            {
                case "ERROR":
                    return LogLevel.Error;
                case "WARNING":
                    return LogLevel.Warning;
                case "SUCCESS":
                    return LogLevel.Success;
                case "DEBUG":
                    return LogLevel.Debug;
                case "INFO":
                default:
                    return LogLevel.Info;
            }
        }

        public static Logger Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= new Logger();
                    }
                }
                return _instance;
            }
        }

        public bool CheckFileAccessBeforeInjection()
        {
            try
            {
                bool canAccessFiles = true;

                if (File.Exists(_monoLoaderLogPath))
                {
                    try
                    {
                        using (FileStream fs = new FileStream(_monoLoaderLogPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                        {
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug($"Cannot access MonoLoader log: {ex.Message}");
                        canAccessFiles = false;
                    }
                }

                if (File.Exists(_logFilePath))
                {
                    try
                    {
                        using (FileStream fs = new FileStream(_logFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                        {
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug($"Cannot access launcher log: {ex.Message}");
                        canAccessFiles = false;
                    }
                }

                if (!canAccessFiles)
                {
                    Warning("Log files are locked by another process - check for other launchers or programs");
                    _canAccessLogs = false;
                    OnFileAccessStatusChanged?.Invoke(this, false);

                    var processes = Process.GetProcessesByName("ModernStealthLauncher");
                    if (processes.Length > 1)
                    {
                        Warning($"Multiple launcher instances detected ({processes.Length}). Close other launchers first.");
                    }
                }
                else
                {
                    _canAccessLogs = true;
                    OnFileAccessStatusChanged?.Invoke(this, true);
                }

                return canAccessFiles;
            }
            catch (Exception ex)
            {
                Error($"Error checking file access: {ex.Message}");
                return false;
            }
        }

        public void Log(string message, LogLevel level = LogLevel.Info)
        {
            var entry = new LogEntry(message, level);
            if (_uiDispatcher != null && !_uiDispatcher.CheckAccess())
            {
                _uiDispatcher.Invoke(() =>
                {
                    LogEntries.Add(entry);
                    OnLogAdded?.Invoke(this, entry);
                });
            }
            else
            {
                LogEntries.Add(entry);
                OnLogAdded?.Invoke(this, entry);
            }

            if (_isFileLoggingEnabled)
            {
                WriteToFile(entry);
            }
        }

        public void Info(string message) => Log(message, LogLevel.Info);
        public void Success(string message) => Log(message, LogLevel.Success);
        public void Warning(string message) => Log(message, LogLevel.Warning);
        public void Error(string message) => Log(message, LogLevel.Error);
        public void Debug(string message) => Log(message, LogLevel.Debug);

        public bool IsInjectionSuccessful()
        {
            return _injectionSuccessful;
        }

        public bool IsInjectionFailed()
        {
            return _injectionFailed;
        }

        public void ResetInjectionStatus()
        {
            _injectionInProgress = false;
            _injectionSuccessful = false;
            _injectionFailed = false;
        }

        public void Clear()
        {
            if (_uiDispatcher != null && !_uiDispatcher.CheckAccess())
            {
                _uiDispatcher.Invoke(() =>
                {
                    LogEntries.Clear();
                    _processedMonoLoaderEntries.Clear();
                });
            }
            else
            {
                LogEntries.Clear();
                _processedMonoLoaderEntries.Clear();
            }
        }

        private void WriteToFile(LogEntry entry)
        {
            try
            {
                string logLine = $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] [{GetLevelString(entry.Color)}] {entry.Message}";
                File.AppendAllText(_logFilePath, logLine + Environment.NewLine);
            }
            catch
            {
                _isFileLoggingEnabled = false;
            }
        }

        private string GetLevelString(Brush brush)
        {
            if (brush == Brushes.White) return "INFO";
            if (brush == Brushes.LimeGreen) return "SUCCESS";
            if (brush == Brushes.Orange) return "WARNING";
            if (brush == Brushes.Red) return "ERROR";
            if (brush == Brushes.SkyBlue) return "DEBUG";
            if (brush == Brushes.LightGray) return "MONOLOADER";
            return "INFO";
        }

        public void Dispose()
        {
            if (_monoLoaderWatcher != null)
            {
                _monoLoaderWatcher.EnableRaisingEvents = false;
                _monoLoaderWatcher.Changed -= OnMonoLoaderLogChanged;
                _monoLoaderWatcher.Created -= OnMonoLoaderLogChanged;
                _monoLoaderWatcher.Dispose();
                _monoLoaderWatcher = null;
            }

            if (_fileAccessCheckTask != null)
            {
                try
                {
                    _fileAccessCheckTask.Wait(1000);
                }
                catch
                {
                }
            }
        }
    }
}
