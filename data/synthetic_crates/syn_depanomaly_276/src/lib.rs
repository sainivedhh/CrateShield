pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x51a41d2a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x1132667c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x4cde2b6b as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xb706933 as *mut u32;
        *ptr = 1;
    }
}
