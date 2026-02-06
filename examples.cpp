#include "veh-pointer.h"
#include <print>
#include <iostream>

// Checking for any accesses coming from outside the current executable module
void protection_range_ex(){
	auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(0));
	auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos_header->e_lfanew);

	// 0x8000000000000000 is just flipping the MSB in binary, so its basically 100% gonna access violate
	vp::ptr<std::uint64_t>example{nullptr, 0x8000000000000000, true};

	// setting a range on module 0, any accesses out of range will access violate
	auto range_id = example.register_access_range(base, nt_header->OptionalHeader.SizeOfImage);

	// no problem accessing bc rip is within module 0
	*example.get() = 1337;

	std::println("0x{:X} | {}",example.addr(), *example.get());

	// making user32.dll access the pointer (should access violate)
	GetWindowTextA(0, reinterpret_cast<LPSTR>(example.addr()), 16);
}

// Swapping pre existing pointer with the encrypted version
void ptr_trap() {
	// imagine that this pointer resides anywhere within the process
	int a = 10;
	int* example_ptr = &a;

	// create an instnace of vp::ptr using example_ptr as the target address
	vp::ptr<int>trap{ example_ptr };

	// flipping the pre existing pointer with the xor key
	example_ptr = reinterpret_cast<int*>(trap.addr());

	// the program can continue to use this pointer like normal, except it cant be made sense of by an external
	// program / you could even register memory ranges on it to enforce integrity of access.
	std::println("previously_existing: 0x{:X} | {}", (std::uintptr_t)example_ptr, *example_ptr);
}
