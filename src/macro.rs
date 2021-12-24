#[macro_export]
macro_rules! sizeof {
    ($t: ident) => {
        std::mem::size_of::<$t>()
    };
}

#[macro_export]
macro_rules! os_str {
    ($var: ident in $ptr: expr) => {{
        let mut __private_index = 0;
        loop {
            let v = $ptr.offset(__private_index).as_ref().unwrap();

            if *v == '\0' as u8 {
                break;
            }

            $var.push(*v);

            __private_index += 1;
        }
    }};
}

#[macro_export]
macro_rules! try_ptr_loop {
    (($id: ident, $offset: ident) in $ptr: expr => $block: block) => {{
        let mut __private_count = 0;
        let mut $id;
        let mut $offset;
        loop {
            let __private_ptr = $ptr.add(__private_count);

            if __private_ptr.is_null() {
                break;
            }

            $offset = __private_ptr as usize;

            $id = __private_ptr.as_mut().unwrap();

            $block

            __private_count += 1;
        }
    }};
}

#[macro_export]
macro_rules! try_ptr {
    ($type: ty, $ptr: expr, $offset: expr) => {{
        if $ptr.is_null() {
            return Err("Invalid PE".into());
        }

        let __private_ptr = <$type>::from_mut_bytes($ptr.offset($offset as isize));

        if __private_ptr.is_null() {
            return Err("Invalid PE".into());
        }

        __private_ptr
    }};
}

#[macro_export]
macro_rules! try_as {
    ($type: ty, $ptr: ident, $offset: expr) => {{
        if $ptr.is_null() {
            return Err("Invalid PE".into());
        }

        let __private_ptr = <$type>::from_mut_bytes($ptr.offset($offset as isize));

        if __private_ptr.is_null() {
            return Err("Invalid PE".into());
        }

        __private_ptr.as_mut().unwrap()
    }};
    ($type: ty, $ptr: expr) => {
        if $ptr.is_null() {
            return Err("Invalid PE".into());
        } else {
            <$type>::from_mut_bytes($ptr).as_mut().unwrap()
        }
    };
    ($ptr: expr) => {
        if $ptr.is_null() {
            return Err("Invalid PE".into());
        } else {
            $ptr.as_mut().unwrap()
        }
    };
}
