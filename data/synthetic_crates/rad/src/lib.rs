pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x5cabdc97 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x382577b8 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xff50cde4 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xff5eaff0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_4() {
    unsafe {
        let ptr = 0x2369c584 as *mut u32;
        *ptr = 1;
    }
}
