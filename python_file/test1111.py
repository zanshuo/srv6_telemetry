#!/usr/bin/python
class test:
    var1=0
def get_var():
    return test.var1
def set_var():
    while True:
        test.var1+=1
if __name__ == "__main__":
    set_var()