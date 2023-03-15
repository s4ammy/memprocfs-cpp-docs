# memprocfs c++ wrapper documentation

Classes:

- [c_device](#c_device)
- [c_process](#c_process)
- [c_memory](#c_memory)
- [c_registry](#c_registry)
- [structs](#structs)
- [example](#example)

## c_device
class that handles the device

fields:
```cpp
bool connected = false;

uint64_t id = 0, major_version = 0, minor_version = 0;

```

### c_device initialization
```cpp
std::vector<const char*> args = { "", "-device", "FPGA" };

c_device device = c_device(args);
```

### functions
```cpp
bool connect();

void disconnect();

int error(const char* error);

c_process process_from_name(const char* str);

c_process process_from_pid(DWORD pid);

std::vector<PVMMDLL_MAP_SERVICEENTRY> get_service_list();

std::vector<user_map_data_t> get_users();

std::vector<DWORD> get_pid_list();

std::vector<c_process> get_process_list();

machine_data_t get_machine_data();
```

## c_process
class that handles a process

fields:

```cpp
bool failed = false;
VMMDLL_PROCESS_INFORMATION information = {};
```

### functions
```cpp
DWORD get_pid();

void set_pid(DWORD in);

module_data_t module_from_name(const char* module_name);

std::vector<module_map_data_t> get_module_list();

std::vector<PVMMDLL_MAP_HANDLEENTRY> get_handle_list();

std::vector<VMMDLL_MAP_VADENTRY> get_map_list();

c_memory get_memory();
```

## c_memory
class that handles memory

fields:

```cpp
VMMDLL_SCATTER_HANDLE scatter_handle = NULL;
int scatters = 0;
```

### functions
```cpp
DWORD get_pid();

void set_pid(DWORD in);

std::vector<section_data_t> get_sections(LPSTR module_name);

bool is_in_section(uint64_t address, section_data_t section_data);

uint64_t find_signature(const char* signature, uint64_t range_start, uint64_t range_end);

uint64_t string_scan(const char* str, uint64_t start, uint64_t end);

inline t read(uint64_t address);

inline bool read_raw(uint64_t address, t buffer, uint64_t in_size = 0);

inline bool write(uint64_t address, t data);

inline bool write_raw(uint64_t address, t buffer);

inline t read_chain(uint64_t address, std::vector<uint64_t> offsets);

void initialize_scatter();

void uninitialize_scatter();

t prepare_scatter(uint64_t address, bool* ret = nullptr);

void prepare_scatter(uint64_t address, t buffer);

bool dispatch_read();

void prepare_write(uint64_t address, t buffer);

bool dispatch();

t read_scatter(uint64_t address);

void read_scatter(uint64_t address, t buffer);

```

## c_registry
class that handles the windows registry

### c_registry initialization
```cpp
c_registry reg = c_registry("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild", REG_SZ);
```

### functions
```cpp
const char* get();

int get_int();

bool get_result();
```

## structs
all structs used

```cpp
struct module_data_t
{
	uint64_t base;
	uint32_t size;

	bool failed;
};

struct module_map_data_t
{
	uint64_t base;
	uint64_t pages;
	uint64_t page;
	bool is_wow64;
	uint32_t future_use;

	const char* text;

	uint32_t reserved;
	uint32_t software;
};

struct section_data_t
{
	uint64_t start, end;
	const char* name;
	uint32_t characteristics;
};

struct user_map_data_t
{
	uint32_t future_use1[2];
	uint32_t future_use2[2];
	unsigned long long va_reg_hive;
	LPSTR usz_text, usz_sid;
	LPWSTR wsz_text, wsz_sid;
};

struct machine_data_t
{
	int current_build;
	std::string edition;
	std::string display_version;
	std::string processor_name;
	std::string motherboard_manufacturer_name;
	std::string motherboard_name;
};
```

## example
```cpp
int main()
{
    std::fstream ifs("config.json");
    if (!ifs.is_open())
    {
        printf("[-] failed to open config.json\n");
        return 0;
    }

    nlohmann::json j = nlohmann::json::parse(ifs);

    ifs.close();

    bool use_memory_map = (bool)j["use_memory_map"];
    std::string memory_map_location = (std::string)j["memory_map_location"];

    j.clear();

    std::vector<const char*> args = { "", "-device", "FPGA" };
    if (use_memory_map)
    {
        args.push_back("-memmap");
        args.push_back(memory_map_location.c_str());
    }

    c_device device = c_device(args);
    if (!device.connect())
        return device.error("[-] failed to connect to device\n");
    else
        printf("[+] connected to device, id -> %lli | version -> %lli.%lli\n\n", device.id, device.major_version, device.minor_version);

    machine_data_t machine_data = device.get_machine_data();
    printf("[+] machine data\n\tcurrent build -> %d\n\tedition -> %s\n\tdisplay version -> %s\n\tprocessor name -> %s\n\tmotherboard manufacturer -> %s\n\tmotherboard model -> %s\n\n", 
        machine_data.current_build, machine_data.edition.c_str(), machine_data.display_version.c_str(), machine_data.processor_name.c_str(),
        machine_data.motherboard_manufacturer_name.c_str(), machine_data.motherboard_name.c_str());

    std::vector<user_map_data_t> users = device.get_users();
    if (users.empty())
        printf("[-] user list was empty\n");
    else
    {
        printf("[+] user list results\n");

        for (auto& data : users)
            printf("\t%s\n", data.usz_text);
    }

    printf("\n");

    c_process process = device.process_from_name("notepad.exe");
    if (process.failed)
        return device.error("[-] failed to find notepad\n");
    else
        printf("[+] found notepad, process id -> %d\n", process.get_pid());

    module_data_t module_data = process.module_from_name("notepad.exe");
    if (module_data.failed)
        return device.error("[-] failed to find notepad module\n");
    else
        printf("[+] found notepad module, base -> 0x%llx | size -> 0x%lx\n\n", module_data.base, module_data.size);

    c_memory memory = process.get_memory();

    std::vector<section_data_t> sections = memory.get_sections(CC_TO_LPSTR("notepad.exe"));
    if (sections.empty())
        printf("[-] notepad.exe section list was empty\n");
    else
    {
        printf("[+] notepad.exe section list results\n");

        for (auto& data : sections)
            printf("\tname -> %s | start -> 0x%llx | end -> 0x%llx | characteristics -> %c%c%c\n", data.name, data.start, data.end,
                (data.characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (data.characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (data.characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-');
    }
    printf("\n");

    uint64_t scan_result = memory.find_signature("48 ? 48 ? 48", module_data.base, module_data.base + module_data.size);
    uint8_t bytes[3];
    memory.read_raw(scan_result, &bytes);
    printf("[+] signature scan result -> 0x%llx | bytes -> 0x%x 0x%x 0x%x\n\n", scan_result, bytes[0], bytes[1], bytes[2]);

    uint64_t string_scan_result = memory.string_scan("Format", module_data.base, module_data.base + module_data.size);
    printf("[+] string scan for 'Format' result -> 0x%llx\n\n", string_scan_result);

    memory.initialize_scatter();

    for (int i = 0; i < 0x12; i++)
        memory.prepare_scatter<uint8_t>(module_data.base + i);

    printf("[+] prepared %d items for scatter, dispatching\n", memory.scatters);

    if (memory.dispatch_read())
    {
        printf("[+] scatter results\n\t");
        for (int i = 0; i < 0x12; i++)
        {
            uint8_t byte = memory.read_scatter<uint8_t>(module_data.base + 0x200 + i);
            printf("0x%x ", byte);
        }
    }
    else
        printf("[-] failed to dispatch read\n");

    memory.uninitialize_scatter();

    printf("\n\n");

    device.disconnect();

    printf("[+] disconnected device\n");;

    std::cin.get();
}
```
