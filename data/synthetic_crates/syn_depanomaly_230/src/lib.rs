pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x1dc1f7eb as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xae27e432 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x3495411e as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xb787ff8d as *mut u32;
        *ptr = 1;
    }
}
