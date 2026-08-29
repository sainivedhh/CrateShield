pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x87e600fe as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x8075af1f as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xe9da584a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x45c46a3e as *mut u32;
        *ptr = 1;
    }
}
