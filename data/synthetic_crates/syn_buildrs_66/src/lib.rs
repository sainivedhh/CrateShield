pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x6cede15d as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xff234d5f as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xbef5afe6 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x8ce6524d as *mut u32;
        *ptr = 1;
    }
}
