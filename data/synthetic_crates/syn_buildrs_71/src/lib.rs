pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x15ce7a66 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xfe717b14 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x3f898142 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x1e52e770 as *mut u32;
        *ptr = 1;
    }
}
