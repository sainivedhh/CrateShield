pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xba6fab9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xf96b748a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xdf57ac6 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x8da8fee4 as *mut u32;
        *ptr = 1;
    }
}
