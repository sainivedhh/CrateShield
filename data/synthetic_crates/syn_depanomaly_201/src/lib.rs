pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x200b3903 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xa0018720 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x4d85f9c7 as *mut u32;
        *ptr = 1;
    }
}
