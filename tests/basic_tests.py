import unittest
from commands import getstatusoutput

class BasicTests(unittest.TestCase):

	def test_exec(self):
		status, res = getstatusoutput('sudo python mitmf.py --help')
		self.assertEqual(0, status)

if __name__ == '__main__':
    unittest.main()