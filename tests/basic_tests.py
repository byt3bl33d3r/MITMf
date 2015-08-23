import unittest
import logging

class BasicTests(unittest.TestCase):

    def test_configfile(self):
        from configobj import ConfigObj
        config = ConfigObj('config/mitmf.conf')

    def test_logger(self):
        from core.logger import logger
        logger.log_level = logging.DEBUG
        formatter = logging.Formatter("%(asctime)s [unittest] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        log = logger().setup_logger("unittest", formatter)

    def test_DNSChef(self):
        from core.logger import logger
        logger.log_level = logging.DEBUG
        from core.servers.DNS import DNSChef
        DNSChef().start()

if __name__ == '__main__':
    unittest.main()