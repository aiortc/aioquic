from aioquic.quic.logger import get_dataclass_attr
from dataclasses import dataclass
import unittest


class NotBuiltin:
    pass

@dataclass
class First:
    l : list
    d : dict
    x : int = 0
    y : float = 1.0
    s : str = "Hello"
    b : bool = True

@dataclass 
class Second:
    x : int = 3
    nb : NotBuiltin = NotBuiltin()

class CubicTests(unittest.TestCase):

    def test_get_dataclass_attr_simple(self):

        expected = {
            "x" : 0,
            "y" : 1.0,
            "s" : "Hello",
            "b" : True,
            "l" : [1, 2, 3],
            "d" : {1:2}
        }
        temp = First(d={1:2}, l=[1, 2, 3])
        self.assertDictEqual(expected, get_dataclass_attr(temp))

    def test_get_dataclass_attr_not_builtin(self):
        expected = {
            "x" : 3
        }
        temp = Second()
        self.assertDictEqual(expected, get_dataclass_attr(temp))


if __name__ == '__main__':
    unittest.main()
