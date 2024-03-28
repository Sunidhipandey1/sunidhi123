from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
ext_modules = [
    Extension("listener",  ["listener.py"]),
    ]
setup(
    name = 'ZH Listener',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules
)
