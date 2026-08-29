pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xd10be1d0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xeb1fb9f2 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x75d67ed4 as *mut u32;
        *ptr = 1;
    }
}
