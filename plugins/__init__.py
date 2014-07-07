#Hack grabbed from http://stackoverflow.com/questions/1057431/loading-all-modules-in-a-folder-in-python
#Has to be a cleaner way to do this, but it works for now
import os
import glob
__all__ = [ os.path.basename(f)[:-3] for f in glob.glob(os.path.dirname(__file__)+"/*.py")]

