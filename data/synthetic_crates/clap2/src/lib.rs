pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x462373a9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x5e4c5fd1 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xd2d15ef5 as *mut u32;
        *ptr = 1;
    }
}
