pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xcdd0c4d4 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x79475bfa as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x84f30d0f as *mut u32;
        *ptr = 1;
    }
}
