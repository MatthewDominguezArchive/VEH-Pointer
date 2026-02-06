#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>

namespace vp {
	struct access_range {
		std::uint64_t id;
		std::uintptr_t start;
		std::uintptr_t size;
	};
	struct ptr_entry {
		std::uint64_t id;
		std::uintptr_t volatile ptr;
		std::uintptr_t xor_key;
		bool using_access_ranges;
		std::vector<access_range>access_ranges;
	};

	inline std::vector<ptr_entry>ptr_entries;
	inline std::uint64_t id_count;
	inline bool initialized{};

	inline std::int32_t exception_handler(_EXCEPTION_POINTERS* exception_info) {
		std::uint64_t* current_register{ &exception_info->ContextRecord->Rax };
		std::uint64_t* last_register{ current_register + 16 };
		bool fixed{};

		for (;current_register < last_register;current_register++)
			for (const auto& entry : ptr_entries)
				if (*current_register == entry.ptr){

					// Checking Access
					if (entry.using_access_ranges) {
						bool valid_access_range{};
						std::uintptr_t instruction_ptr = exception_info->ContextRecord->Rip;
						for (const auto& range : entry.access_ranges) {
							if (range.start < instruction_ptr && instruction_ptr < range.start + range.size) {
								valid_access_range = true;
								break;
							}
						}
						if (!valid_access_range) {
							std::stringstream message;
							message << "rip -> 0x" << std::hex << instruction_ptr;
							MessageBoxA(0, message.str().c_str(), "Invalid Memory Access\n", 0);
							exit(1);
						}
					}

					// Fixing Register
					*current_register ^= entry.xor_key;
					fixed = true;
				}

		if (!fixed)
			return EXCEPTION_CONTINUE_SEARCH;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	template <typename T>
	class ptr {
		std::uintptr_t target_ptr{};
		std::uint64_t id{};
		std::uintptr_t xor_key{};
		bool using_access_ranges{};
		bool delete_on_deconstruct{};
	public:
		ptr(T* address = nullptr, const std::uintptr_t xor_key = 0x8000000000000000, const bool using_access_ranges = false) {
			if (!address){
				address = new T;
				delete_on_deconstruct = true;
			}
			ptr_entry entry{};
			entry.id = ++id_count;
			entry.ptr = reinterpret_cast<std::uintptr_t>(address) ^ xor_key;
			entry.xor_key = xor_key;
			entry.using_access_ranges = using_access_ranges;

			ptr_entries.push_back(entry);

			if (!initialized) {
				AddVectoredExceptionHandler(true, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(&exception_handler));
				initialized = true;
			}

			this->id = entry.id;
			this->target_ptr = entry.ptr;
			this->xor_key = entry.xor_key;
			this->using_access_ranges = entry.using_access_ranges;
		}
		
		~ptr() {
			ptr_entries.erase(
				std::remove_if(
					ptr_entries.begin(),
					ptr_entries.end(),
					[&](ptr_entry const& ptr_entry_) {return ptr_entry_.id == this->id;}),
				ptr_entries.end()
			);
			if (delete_on_deconstruct)
				delete reinterpret_cast<T*>(this->target_ptr ^ this->xor_key);
		}
	
		T* get() {
			return reinterpret_cast<T*>(this->target_ptr);
		}
		
		std::uintptr_t addr() {
			return this->target_ptr;
		}

		std::uint64_t register_access_range(const std::uintptr_t start, const std::uintptr_t size) {
			if (!this->using_access_ranges)
				return 0;

			for (auto& ptr_entry_ : ptr_entries) {
				if (ptr_entry_.id == this->id) {
					id_count++;
					ptr_entry_.access_ranges.push_back({ id_count, start, size });
					return id_count;
				}
			}

			return 0;
		}

		bool remove_access_range(const std::uint64_t id) {
			if (!this->using_access_ranges)
				return false;

			for (auto& ptr_entry_ : ptr_entries) {
				if (ptr_entry_.id == this->id) {
					auto& ranges = ptr_entry_.access_ranges;
					for (auto it = ranges.begin(); it != ranges.end(); ++it) {
						if (it->id == id) {
							ranges.erase(it);
							return true;
						}
					}
				}
			}
			return false;
		}

		T* operator =(const T* new_ptr) {
			this->target_ptr = reinterpret_cast<std::uintptr_t>(new_ptr) ^ this->xor_key;
			for (auto& ptr_entry_ : ptr_entries) {
				if (ptr_entry_.id == this->id) {
					ptr_entry_.ptr = this->target_ptr;
					return reinterpret_cast<T*>(this->target_ptr);
				}
			}
			return nullptr;
		}

		T* operator =(const std::uintptr_t new_ptr) {
			this->target_ptr = new_ptr ^ this->xor_key;
			for (auto& ptr_entry_ : ptr_entries) {
				if (ptr_entry_.id == this->id) {
					ptr_entry_.ptr = this->target_ptr;
					return reinterpret_cast<T*>(this->target_ptr);
				}
			}
			return nullptr;
		}
	};
}
