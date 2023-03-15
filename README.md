# memprocfs c++ wrapper documentation

Classes:

- [c_device](#c_device)
- [c_process](#c_process)
- [c_memory](#c_memory)
- [c_registry](#c_registry)

- [structs](#structs)

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
