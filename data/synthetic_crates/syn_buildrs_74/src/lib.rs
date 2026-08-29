pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xb4fb1eb9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x48604b32 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xb3f70e0d as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xdc0f3fcf as *mut u32;
        *ptr = 1;
    }
}
