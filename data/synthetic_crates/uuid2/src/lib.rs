pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x57b946b0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x68c0dbef as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xfcb8a6bb as *mut u32;
        *ptr = 1;
    }
}
