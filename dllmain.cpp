#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <TlHelp32.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

typedef void* MonoDomain;
typedef void* MonoAssembly;
typedef void* MonoImage;
typedef void* MonoClass;
typedef void* MonoMethod;
typedef void* MonoObject;
typedef int MonoImageOpenStatus;

typedef MonoDomain(*MonoGetRootDomain)();
typedef MonoDomain(*MonoThreadAttach)(MonoDomain domain);
typedef MonoImage(*MonoImageOpenFromData)(const char* data, UINT32 data_len, BOOL need_copy, MonoImageOpenStatus* status);
typedef MonoAssembly(*MonoAssemblyLoadFromFull)(MonoImage image, const char* fname, MonoImageOpenStatus* status, BOOL refonly);
typedef MonoImage(*MonoAssemblyGetImage)(MonoAssembly assembly);
typedef MonoClass(*MonoClassFromName)(MonoImage image, const char* name_space, const char* name);
typedef MonoMethod(*MonoClassGetMethodFromName)(MonoClass klass, const char* name, int param_count);
typedef MonoObject* (*MonoRuntimeInvoke)(MonoMethod method, void* obj, void** params, MonoObject** exc);
typedef void (*MonoAssemblyClose)(MonoAssembly assembly);
typedef const char* (*MonoImageStrerror)(MonoImageOpenStatus status);

struct MonoFunctions {
    MonoGetRootDomain mono_get_root_domain;
    MonoThreadAttach mono_thread_attach;
    MonoImageOpenFromData mono_image_open_from_data;
    MonoAssemblyLoadFromFull mono_assembly_load_from_full;
    MonoAssemblyGetImage mono_assembly_get_image;
    MonoClassFromName mono_class_from_name;
    MonoClassGetMethodFromName mono_class_get_method_from_name;
    MonoRuntimeInvoke mono_runtime_invoke;
    MonoAssemblyClose mono_assembly_close;
    MonoImageStrerror mono_image_strerror;
};

enum class LogLevel {
    INFO,
    SUCCESS,
    WARNING_LEVEL,
    ERROR_LEVEL,
    DEBUG_LEVEL
};

class Logger {
private:
    std::string logFilePath;
    bool fileLoggingEnabled;
    HWND launcherWindow;
    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        std::tm tm;
        localtime_s(&tm, &time);
        ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    std::string getLevelString(LogLevel level) {
        switch (level) {
        case LogLevel::DEBUG_LEVEL: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::SUCCESS: return "SUCCESS";
        case LogLevel::WARNING_LEVEL: return "WARNING";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        default: return "UNKNOWN";
        }
    }
public:
    Logger() : fileLoggingEnabled(false), launcherWindow(nullptr) {
        findLauncherWindow();
    }
    void findLauncherWindow() {
        launcherWindow = FindWindowA(NULL, "MonoStealth Launcher");
    }
    bool initialize() {
        std::string appdata = std::getenv("APPDATA");
        logFilePath = appdata + "\\MonoLoader.log";
        std::ofstream logFile(logFilePath, std::ios::out | std::ios::trunc);
        if (!logFile.is_open()) {
            return false;
        }
        fileLoggingEnabled = true;
        writeLog("MonoLoader initialized", LogLevel::INFO);
        findLauncherWindow();
        return true;
    }
    void writeLog(const std::string& message, LogLevel level = LogLevel::INFO) {
        std::string timestamp = getTimestamp();
        std::string levelStr = getLevelString(level);
        std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + message;
        if (fileLoggingEnabled) {
            std::ofstream logFile(logFilePath, std::ios::app);
            if (logFile.is_open()) {
                logFile << logMessage << std::endl;
                logFile.close();
            }
        }
        if (launcherWindow != nullptr) {
            COPYDATASTRUCT cds;
            std::string formattedMsg = std::to_string(static_cast<int>(level)) + "|" + message;
            cds.dwData = 0x1234;
            cds.cbData = static_cast<DWORD>(formattedMsg.size() + 1);
            cds.lpData = (PVOID)formattedMsg.c_str();
            SendMessage(launcherWindow, WM_COPYDATA, 0, (LPARAM)&cds);
        }
    }
    void debug(const std::string& message) {
        writeLog(message, LogLevel::DEBUG_LEVEL);
    }
    void info(const std::string& message) {
        writeLog(message, LogLevel::INFO);
    }
    void success(const std::string& message) {
        writeLog(message, LogLevel::SUCCESS);
    }
    void warning(const std::string& message) {
        writeLog(message, LogLevel::WARNING_LEVEL);
    }
    void error(const std::string& message) {
        writeLog(message, LogLevel::ERROR_LEVEL);
    }
};

static Logger logger;

std::string get_module_directory(HMODULE hModule) {
    char modulePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(hModule, modulePath, MAX_PATH) == 0) {
        logger.error("Failed to get module file name");
        return "";
    }
    std::string path(modulePath);
    size_t pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(0, pos) : "";
}

HMODULE FindMonoModule() {
    const char* monoNames[] = { "mono.dll", "mono-2.0-bdwgc.dll", "mono-2.0.dll" };
    logger.debug("Searching for Mono module...");
    for (const auto& name : monoNames) {
        HMODULE hMono = GetModuleHandleA(name);
        if (hMono != NULL) {
            logger.success(std::string("Found Mono module: ") + name);
            return hMono;
        }
    }
    logger.error("Failed to find Mono module");
    return NULL;
}

bool LoadMonoFunctions(HMODULE hMono, MonoFunctions* functions) {
    if (!hMono || !functions) {
        logger.error("Invalid parameters for LoadMonoFunctions");
        return false;
    }
    logger.debug("Loading Mono functions from module");
    functions->mono_get_root_domain = (MonoGetRootDomain)GetProcAddress(hMono, "mono_get_root_domain");
    functions->mono_thread_attach = (MonoThreadAttach)GetProcAddress(hMono, "mono_thread_attach");
    functions->mono_image_open_from_data = (MonoImageOpenFromData)GetProcAddress(hMono, "mono_image_open_from_data");
    functions->mono_assembly_load_from_full = (MonoAssemblyLoadFromFull)GetProcAddress(hMono, "mono_assembly_load_from_full");
    functions->mono_assembly_get_image = (MonoAssemblyGetImage)GetProcAddress(hMono, "mono_assembly_get_image");
    functions->mono_class_from_name = (MonoClassFromName)GetProcAddress(hMono, "mono_class_from_name");
    functions->mono_class_get_method_from_name = (MonoClassGetMethodFromName)GetProcAddress(hMono, "mono_class_get_method_from_name");
    functions->mono_runtime_invoke = (MonoRuntimeInvoke)GetProcAddress(hMono, "mono_runtime_invoke");
    functions->mono_assembly_close = (MonoAssemblyClose)GetProcAddress(hMono, "mono_assembly_close");
    functions->mono_image_strerror = (MonoImageStrerror)GetProcAddress(hMono, "mono_image_strerror");
    if (!functions->mono_get_root_domain ||
        !functions->mono_thread_attach ||
        !functions->mono_image_open_from_data ||
        !functions->mono_assembly_load_from_full ||
        !functions->mono_assembly_get_image ||
        !functions->mono_class_from_name ||
        !functions->mono_class_get_method_from_name ||
        !functions->mono_runtime_invoke ||
        !functions->mono_assembly_close ||
        !functions->mono_image_strerror) {
        logger.error("Failed to get all required Mono functions");
        if (!functions->mono_get_root_domain) logger.debug("Missing: mono_get_root_domain");
        if (!functions->mono_thread_attach) logger.debug("Missing: mono_thread_attach");
        if (!functions->mono_image_open_from_data) logger.debug("Missing: mono_image_open_from_data");
        if (!functions->mono_assembly_load_from_full) logger.debug("Missing: mono_assembly_load_from_full");
        if (!functions->mono_assembly_get_image) logger.debug("Missing: mono_assembly_get_image");
        if (!functions->mono_class_from_name) logger.debug("Missing: mono_class_from_name");
        if (!functions->mono_class_get_method_from_name) logger.debug("Missing: mono_class_get_method_from_name");
        if (!functions->mono_runtime_invoke) logger.debug("Missing: mono_runtime_invoke");
        if (!functions->mono_assembly_close) logger.debug("Missing: mono_assembly_close");
        if (!functions->mono_image_strerror) logger.debug("Missing: mono_image_strerror");
        return false;
    }
    logger.success("Successfully loaded all Mono functions");
    return true;
}

std::vector<char> ReadFileContents(const std::string& path) {
    logger.debug("Reading file: " + path);
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        logger.error("Failed to open file: " + path);
        return {};
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        logger.error("Failed to read file contents: " + path);
        return {};
    }
    logger.success("Successfully read file: " + path + " (" + std::to_string(size) + " bytes)");
    return buffer;
}

bool InjectAssembly(const std::string& dllPath, const std::string& nameSpace, const std::string& className, const std::string& methodName) {
    logger.info("Starting assembly injection process");
    logger.debug("DLL Path: " + dllPath);
    logger.debug("Namespace: " + nameSpace);
    logger.debug("Class: " + className);
    logger.debug("Method: " + methodName);
    HMODULE hMono = FindMonoModule();
    if (!hMono) {
        logger.error("Failed to find Mono module");
        return false;
    }
    MonoFunctions functions = {};
    if (!LoadMonoFunctions(hMono, &functions)) {
        logger.error("Failed to load Mono functions");
        return false;
    }
    std::vector<char> assemblyData = ReadFileContents(dllPath);
    if (assemblyData.empty()) {
        logger.error("Failed to read assembly data");
        return false;
    }
    try {
        logger.debug("Getting root domain");
        MonoDomain rootDomain = functions.mono_get_root_domain();
        if (!rootDomain) {
            logger.error("Failed to get root domain");
            return false;
        }
        logger.debug("Attaching to thread");
        functions.mono_thread_attach(rootDomain);
        logger.debug("Opening image from data");
        MonoImageOpenStatus status;
        MonoImage image = functions.mono_image_open_from_data(assemblyData.data(), static_cast<UINT32>(assemblyData.size()), TRUE, &status);
        if (!image || status != 0) {
            logger.error(std::string("Failed to open image: ") + functions.mono_image_strerror(status));
            return false;
        }
        logger.success("Image opened successfully");
        logger.debug("Loading assembly");
        MonoAssembly assembly = functions.mono_assembly_load_from_full(image, "", &status, FALSE);
        if (!assembly || status != 0) {
            logger.error(std::string("Failed to load assembly: ") + functions.mono_image_strerror(status));
            return false;
        }
        logger.success("Assembly loaded successfully");
        logger.debug("Getting assembly image");
        MonoImage assemblyImage = functions.mono_assembly_get_image(assembly);
        if (!assemblyImage) {
            logger.error("Failed to get assembly image");
            return false;
        }
        logger.debug("Finding class: " + nameSpace + "." + className);
        MonoClass klass = functions.mono_class_from_name(assemblyImage, nameSpace.c_str(), className.c_str());
        if (!klass) {
            logger.error("Failed to get class");
            return false;
        }
        logger.success("Class found");
        logger.debug("Finding method: " + methodName);
        MonoMethod method = functions.mono_class_get_method_from_name(klass, methodName.c_str(), 0);
        if (!method) {
            logger.error("Failed to get method");
            return false;
        }
        logger.success("Method found");
        logger.info("Invoking method");
        MonoObject* exception = nullptr;
        functions.mono_runtime_invoke(method, nullptr, nullptr, &exception);
        if (exception) {
            logger.error("Method threw an exception");
            return false;
        }
        logger.success("Method invoked successfully");
        return true;
    }
    catch (const std::exception& e) {
        logger.error(std::string("Exception during injection: ") + e.what());
        return false;
    }
    catch (...) {
        logger.error("Unknown exception during injection");
        return false;
    }
}

std::vector<std::string> SplitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM wParam, LPARAM lParam) {
    static bool initialized = false;
    if (code >= 0 && !initialized) {
        initialized = true;
        logger.initialize();
        logger.info("HookProc called with code: " + std::to_string(code));
        logger.info("MonoLoader injection process started");
        HMODULE hModule = NULL;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(&HookProc), &hModule)) {
            logger.error("Failed to get module handle in HookProc: " + std::to_string(GetLastError()));
            return CallNextHookEx(NULL, code, wParam, lParam);
        }
        std::string folder = get_module_directory(hModule);
        std::string configPath = folder + "\\temp_config.bin";
        logger.debug("Config path: " + configPath);
        std::string dllName = "r.e.p.o.cheat.dll";
        std::string nameSpace = "dark_cheat";
        std::string className = "Init";
        std::string methodName = "Loader";
        try {
            std::ifstream configFile(configPath);
            if (configFile.is_open()) {
                std::string configData;
                std::getline(configFile, configData);
                configFile.close();
                logger.debug("Read config data: " + configData);
                auto parts = SplitString(configData, '|');
                if (parts.size() >= 4) {
                    dllName = parts[0];
                    nameSpace = parts[1];
                    className = parts[2];
                    methodName = parts[3];
                    logger.success("Read configuration successfully");
                }
                else {
                    logger.warning("Config format unexpected, using defaults. Parts: " + std::to_string(parts.size()));
                }
                DeleteFileA(configPath.c_str());
                logger.debug("Deleted config file");
            }
            else {
                logger.warning("Could not open config file, using defaults: " + configPath);
            }
        }
        catch (const std::exception& e) {
            logger.error("Error reading configuration: " + std::string(e.what()));
        }
        std::string dllPath = folder + "\\" + dllName;
        logger.info("DLL path: " + dllPath);
        logger.info("Using injection parameters:");
        logger.info(" - DLL: " + dllName);
        logger.info(" - Namespace: " + nameSpace);
        logger.info(" - Class: " + className);
        logger.info(" - Method: " + methodName);
        bool result = InjectAssembly(dllPath, nameSpace, className, methodName);
        if (result) {
            logger.success("Injection completed successfully");
        }
        else {
            logger.error("Injection failed");
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
