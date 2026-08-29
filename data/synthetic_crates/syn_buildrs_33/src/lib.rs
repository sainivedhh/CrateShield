pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xe7c431c7 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xe87d2c78 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xd89a50c0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xd01380f as *mut u32;
        *ptr = 1;
    }
}
