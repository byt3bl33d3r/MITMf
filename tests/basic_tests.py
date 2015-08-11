import unittest
from commands import getstatusoutput

class BasicTests(unittest.TestCase):

	def test_exec(self):
		status, res = getstatusoutput('python mitmf.py --help')
		self.assertEqual(0, status)

if __name__ == '__main__':
    unittest.main()