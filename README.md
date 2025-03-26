# Stealth Injector for REPO

## Architecture and Components

### MonoStealthInjector.exe (main.cpp)
- **Window Enumeration**:  
  Scans for a window with the title `"R.E.P.O."` and verifies its association with `REPO.exe` by checking the executable name.
- **Thread Hooking**:  
  Retrieves the target thread ID from the game window and sets a `WH_GETMESSAGE` hook by dynamically loading the MonoLoader DLL. A message (`WM_NULL`) is posted to trigger the hook, which then executes the injection routine.
- **Dynamic DLL Loading**:  
  Loads `MonoLoader.dll` at runtime and retrieves the `HookProc` function to establish the hook.

### MonoLoader.dll (dllmain.cpp)
- **Mono Runtime Integration**:  
  Locates the Mono runtime module (searching for `mono.dll`, `mono-2.0-bdwgc.dll`, or `mono-2.0.dll`) and resolves necessary function pointers via `GetProcAddress`.  
- **Assembly Injection**:  
  - Reads the Mono assembly (`dark_cheat.dll`) from the same directory as the injector.
  - Uses Mono functions to open the assembly image from data (`mono_image_open_from_data`), load the assembly (`mono_assembly_load_from_full`), and retrieve its image.
  - Locates the target class (`Loader` in namespace `dark_cheat`) and method (`Init`) using `mono_class_from_name` and `mono_class_get_method_from_name`.
  - Invokes the `Init` method via `mono_runtime_invoke` to execute the managed code.
- **Logging**:  
  Detailed logs are written to `MonoLoader.log` in the user's APPDATA directory.

## Injection

### Windows API Hooking
- **SetWindowsHookExW with WH_GETMESSAGE**:  
  The injector sets a message hook on the target thread, ensuring the hook procedure (`HookProc`) executes in the context of the REPO process.
- **Message Triggering**:  
  A `WM_NULL` message is posted to the target thread to trigger the hook, after which the hook is removed.

### Mono Runtime Function Resolution
The following Mono functions are dynamically resolved and used:
- `mono_get_root_domain`
- `mono_thread_attach`
- `mono_image_open_from_data`
- `mono_assembly_load_from_full`
- `mono_assembly_get_image`
- `mono_class_from_name`
- `mono_class_get_method_from_name`
- `mono_runtime_invoke`
- `mono_assembly_close`
- `mono_image_strerror`


## Build Environment
- **Platform**: Windows
- **Compiler**: Compatible with Visual Studio or any C++ compiler that supports Windows API.
- **Dependencies**:  
  - Windows SDK libraries (e.g., `user32.lib`, `kernel32.lib`, `psapi.lib`)
  - Mono runtime libraries must be available in the target process or system.
