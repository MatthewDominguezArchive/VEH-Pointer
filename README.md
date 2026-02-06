# VEH-Pointer
A pointer wrapper to protect from unauthorized memory access.

### Overview
**Internal Protection Overview:**
Every time this pointer is accessed, an exception is triggered. A Vectored Exception Handler will analyze the exception, and determine if the exception was from an access violation. If it was, it's possible that it's from a protected pointer being dereferenced. It will scan all your registers and see if it finds any protected pointers, and decrypt them directly in the register. Optionally, before decrypting them, if the protected pointer has the setting "using_memory_ranges" set to true, then the handler will inspect the instruction pointer from the exception record and ensure it is within a valid memory range. If an unauthorized DLL or shellcode trys to access the pointer, the exception handler will know.

**External Protection Overview:**
Because of the fact that the pointers are only decrypted in the register itself, the decrypted pointer is not held in ram. This stops malicious software from walking a pointer path and reaching a target value, because the pointers will not be valid.

**Caveats:**
If either an internal or external threat actor knows the xor_key, they will be able to access the memory without an issue. This process can even be automated by walking the ptr_entries vector. There are other ways to trap exceptions for verification, like page guarding pages with protected data. This was not included in this library because it would be out of place. Another thing to keep in mind is that this will slow your execution, if you are protecting that aims for speed, it might be best to keep the protected pointers to a minimum, or protecting things that are infrequently called. The default xor key just flips a part of the virtual addresses's sign extension, so a threat actor who knows this can just fix the sign of all virtual addresses before dereferencing, it's like this to make testing easier, but deterred from using this default key in production.

**Pro tip:**
When making an xor key, flip the sign extension bit, and make it so that the key changes the virtual address to point to a dummy structure so that if a threat actor is fixing up the sign extension before they read, they read the dummy structure without an issue but aren't getting the real structure. But when the xor is applied they get the real structure. This protects against both internal and external threats.

### Usage
**Creating an instance**
Below is an example of creating an instance of a protected pointer. The template describes what it is that is being pointed to. So in this case, we are pointing to a 64 bit unsigned integer. The constructor asks for 3 things, first being an address. If you are creating a pointer to something that already exists, you can just pass something like &x (assuming x is an instance of a std::uint64_t). If you pass nullptr, a new instance will be dynamically allocated in the constructor and freed in the deconstructor. The next parameter is the xor key, in this example I just used a key that would flip the most significant bit so that the sign of the virtual address is corrupted (guarentees a access violation). If you use an xor key that converts the pointer to point to other valid memory regions an doesn't cause an exception, your logic will be destroyed. Lastly, is the "using_memory_regions" parameter. I set this to false for the example.
```cpp
vp::ptr<std::uint64_t>example(nullptr, 0x8000000000000000, false);
```

**Methods**
To use this pointer, call the .get() method and then treat as a normal pointer.
```cpp
// Normal pointer
*a = 10;

// Protected pointer
*example.get() = 10;
```

To get the \*encrypted\* address use the .addr() method.
```cpp
example.addr();
```

To add a whitelisted memory range use the .register_access_range(start, size) method. The method returns an id that can be used to later remove the range, if you dont plan on removing the range, ignore the return address.
```cpp
// remember to construct the pointer with using_memory_ranges enabled
auto id = example.register_access_range(exe_base, image_size);
```

Use .remove_access_range(id) to remove this whitelisted entry
```cpp
example.remove_access_range(id);
```













