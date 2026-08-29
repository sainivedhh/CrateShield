pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x6bcd6ce7 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x4cbca044 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x7bf6a552 as *mut u32;
        *ptr = 1;
    }
}
