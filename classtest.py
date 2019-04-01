#!/usr/bin/env python3
import functools
import inspect


def func(a, b, c):
    frame = inspect.currentframe()
    args, _, _, values = inspect.getargvalues(frame)
    print('function name "%s"' % inspect.getframeinfo(frame)[2])
    for i in args:
        print("    %s = %s" % (i, values[i]))
    return [(i, values[i]) for i in args]


class Person(object):

    def __init__(self):
        self.pet = Pet()
        self.residence = Residence()
        self.name = "jared"

    def rsetattr(self, attr, val):
        pre, _, post = attr.rpartition('.')
        return setattr(self.rgetattr(pre) if pre else self, post, val)

    def rgetattr(self, attr, *args):
        def _getattr(self, attr):
            return getattr(self, attr, *args)
        return functools.reduce(_getattr, [self] + attr.split('.'))


class Pet(object):

    def __init__(self, name='Fido', species='Dog'):
        self.name = name
        self.species = species


class Residence(object):

    def __init__(self, type='House', sqft=None):
        self.type = type
        self.sqft = sqft


if __name__ == '__main__':
    p = Person()
    # 'calico'
    # rsetattr(p, 'name', 'john')
    print(p.name)
    print(p.pet.name)
    p.rsetattr('pet.name', 'Sparky')
    p.rsetattr('name', 'john')
    print(p.name)
    print(p.pet.name)
    print(p.__dict__)
    print(p.pet.__dict__)
    # rsetattr(p, 'residence.type', 'Apartment')
