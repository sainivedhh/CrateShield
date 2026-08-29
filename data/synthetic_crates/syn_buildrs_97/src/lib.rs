pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xfcd6cdca as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x966b2964 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x4c956f6a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xa3918c99 as *mut u32;
        *ptr = 1;
    }
}
