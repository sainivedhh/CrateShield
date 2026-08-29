pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x4c71f0fe as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xc0e3cefd as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x63d63a39 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xda7ba095 as *mut u32;
        *ptr = 1;
    }
}
