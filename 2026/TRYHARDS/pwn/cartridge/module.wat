(module
  (type (;0;) (func (param i32 i32)))
  (type (;1;) (func (param i32) (result i32)))
  (type (;2;) (func (result i32)))
  (func (;0;) (type 0) (param $offset i32) (param $value i32)
    local.get $offset
    local.get $value
    i32.store)
  (func (;1;) (type 1) (param $offset i32) (result i32)
    local.get $offset
    i32.load)
  (func (;2;) (type 2) (result i32)
    i32.const 64
    i32.load)
  (memory (;0;) 1)
  (export "memory" (memory 0))
  (export "set_cell" (func 0))
  (export "get_cell" (func 1))
  (export "is_unlocked" (func 2))
  (data (;0;) (i32.const 64) "\00\00\00\00")
  (@custom "name" "\02\1c\02\00\02\00\06offset\01\05value\01\01\00\06offset"))
