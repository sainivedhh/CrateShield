pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xd0b1f3eb as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x5abcb6e5 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x446f74dd as *mut u32;
        *ptr = 1;
    }
}
